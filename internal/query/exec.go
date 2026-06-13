package query

import (
	"sort"
	"strconv"
	"time"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/ntcf/ntcf/internal/column"
	"github.com/ntcf/ntcf/internal/format"
	"github.com/ntcf/ntcf/internal/schema"
	"github.com/ntcf/ntcf/internal/store"
	"github.com/ntcf/ntcf/internal/util"
)

// DefaultRowLimit caps row output when a projection query omits LIMIT, so a bare
// `SELECT *` cannot attempt to materialise an entire archive.
const DefaultRowLimit = 1000

// ResultKind discriminates the shape of a Result.
type ResultKind int

const (
	KindCount ResultKind = iota
	KindTop
	KindRows
)

// Result is the outcome of executing a Stmt.
type Result struct {
	Kind    ResultKind
	Count   uint64
	Columns []string
	Rows    [][]string
	// Observability: how many segments were fully pruned by zone maps / bloom
	// filters versus actually scanned (decoded).
	Pruned  int
	Scanned int
}

// Execute runs a parsed statement against a reader.
func Execute(r *store.Reader, st *Stmt) (*Result, error) {
	sch := r.Schema()
	if err := validate(sch, st); err != nil {
		return nil, err
	}
	switch {
	case st.Aggregate != nil && st.Aggregate.Func == "count":
		return execCount(r, st)
	case st.Aggregate != nil && st.Aggregate.Func == "top":
		return execTop(r, st)
	default:
		return execRows(r, st)
	}
}

func validate(sch *schema.Schema, st *Stmt) error {
	check := func(name string) error {
		if sch.Index(name) < 0 {
			return perr("unknown column %q", name)
		}
		return nil
	}
	if st.Aggregate != nil && st.Aggregate.Func == "top" {
		if err := check(st.Aggregate.Col); err != nil {
			return err
		}
	}
	for _, c := range st.Projection {
		if err := check(c); err != nil {
			return err
		}
	}
	return validateExpr(sch, st.Where)
}

func validateExpr(sch *schema.Schema, e Expr) error {
	switch t := e.(type) {
	case nil:
		return nil
	case And:
		if err := validateExpr(sch, t.L); err != nil {
			return err
		}
		return validateExpr(sch, t.R)
	case Or:
		if err := validateExpr(sch, t.L); err != nil {
			return err
		}
		return validateExpr(sch, t.R)
	case Cmp:
		if sch.Index(t.Col) < 0 {
			return perr("unknown column %q", t.Col)
		}
		return nil
	default:
		return perr("invalid expression node")
	}
}

// segCtx carries per-segment evaluation state, including a column decode cache
// so a column referenced by multiple predicates is decompressed at most once.
type segCtx struct {
	r       *store.Reader
	sch     *schema.Schema
	segIdx  int
	rows    int
	cache   map[int]*column.Data
	decoded bool
}

func (c *segCtx) col(idx int) (*column.Data, error) {
	if d, ok := c.cache[idx]; ok {
		return d, nil
	}
	d, err := c.r.Column(c.segIdx, idx)
	if err != nil {
		return nil, err
	}
	c.decoded = true
	c.cache[idx] = d
	return d, nil
}

// evalSegment evaluates the WHERE expression for one segment, returning the
// matching row bitmap. A nil expression matches all rows.
func evalSegment(ctx *segCtx, e Expr) (*roaring.Bitmap, error) {
	switch t := e.(type) {
	case nil:
		bm := roaring.New()
		bm.AddRange(0, uint64(ctx.rows))
		return bm, nil
	case And:
		l, err := evalSegment(ctx, t.L)
		if err != nil {
			return nil, err
		}
		rr, err := evalSegment(ctx, t.R)
		if err != nil {
			return nil, err
		}
		l.And(rr)
		return l, nil
	case Or:
		l, err := evalSegment(ctx, t.L)
		if err != nil {
			return nil, err
		}
		rr, err := evalSegment(ctx, t.R)
		if err != nil {
			return nil, err
		}
		l.Or(rr)
		return l, nil
	case Cmp:
		return evalCmp(ctx, t)
	default:
		return nil, perr("invalid expression node")
	}
}

func evalCmp(ctx *segCtx, c Cmp) (*roaring.Bitmap, error) {
	colIdx := ctx.sch.Index(c.Col)
	colDef := ctx.sch.Columns[colIdx]
	cd := &ctx.r.Footer().Segments[ctx.segIdx].Columns[colIdx]

	if c.Op == "in" {
		out := roaring.New()
		for _, v := range c.Vals {
			bm, err := evalEquality(ctx, colIdx, colDef, cd, v)
			if err != nil {
				return nil, err
			}
			out.Or(bm)
		}
		return out, nil
	}
	if c.Op == "=" {
		return evalEquality(ctx, colIdx, colDef, cd, c.Vals[0])
	}
	// !=, <, > require a scan of present values.
	return evalScan(ctx, colIdx, colDef, c.Op, c.Vals[0])
}

// evalEquality resolves col = value using zone maps, bloom filters, and the
// inverted index before falling back to a scan.
func evalEquality(ctx *segCtx, colIdx int, colDef schema.Column, cd *format.ColumnDir, val string) (*roaring.Bitmap, error) {
	empty := roaring.New()
	ci, err := ctx.r.Index(ctx.segIdx, colIdx)
	if err != nil {
		return nil, err
	}
	if colDef.Type.Kind() == column.KindInt {
		v, ok := normInt(colDef.Type, val)
		if !ok {
			return empty, nil
		}
		if cd.NonNull > 0 && (v < cd.MinInt || v > cd.MaxInt) {
			return empty, nil // zone-map prune
		}
		if ci.Bloom != nil && !ci.Bloom.MayContainU64(v) {
			return empty, nil
		}
		if ci.Inverted != nil {
			if bm := ci.Inverted.LookupInt(v); bm != nil {
				return bm.Clone(), nil
			}
			return empty, nil
		}
		return scanIntEq(ctx, colIdx, v)
	}
	v, ok := normBytes(colDef.Type, val)
	if !ok {
		return empty, nil
	}
	if cd.NonNull > 0 && (string(v) < string(cd.MinBytes) || string(v) > string(cd.MaxBytes)) {
		return empty, nil
	}
	if ci.Bloom != nil && !ci.Bloom.MayContain(v) {
		return empty, nil
	}
	if ci.Inverted != nil {
		if bm := ci.Inverted.LookupBytes(v); bm != nil {
			return bm.Clone(), nil
		}
		return empty, nil
	}
	return scanBytesEq(ctx, colIdx, v)
}

func scanIntEq(ctx *segCtx, colIdx int, v uint64) (*roaring.Bitmap, error) {
	d, err := ctx.col(colIdx)
	if err != nil {
		return nil, err
	}
	bm := roaring.New()
	for i := 0; i < d.Rows; i++ {
		if !d.IsNull(i) && d.Ints[i] == v {
			bm.Add(uint32(i))
		}
	}
	return bm, nil
}

func scanBytesEq(ctx *segCtx, colIdx int, v []byte) (*roaring.Bitmap, error) {
	d, err := ctx.col(colIdx)
	if err != nil {
		return nil, err
	}
	bm := roaring.New()
	for i := 0; i < d.Rows; i++ {
		if !d.IsNull(i) && string(d.Bytes[i]) == string(v) {
			bm.Add(uint32(i))
		}
	}
	return bm, nil
}

func evalScan(ctx *segCtx, colIdx int, colDef schema.Column, op, val string) (*roaring.Bitmap, error) {
	d, err := ctx.col(colIdx)
	if err != nil {
		return nil, err
	}
	bm := roaring.New()
	if colDef.Type.Kind() == column.KindInt {
		v, ok := normInt(colDef.Type, val)
		if !ok {
			return bm, nil
		}
		for i := 0; i < d.Rows; i++ {
			if d.IsNull(i) {
				continue
			}
			if cmpInt(op, d.Ints[i], v) {
				bm.Add(uint32(i))
			}
		}
		return bm, nil
	}
	v, ok := normBytes(colDef.Type, val)
	if !ok {
		return bm, nil
	}
	for i := 0; i < d.Rows; i++ {
		if d.IsNull(i) {
			continue
		}
		if cmpBytes(op, d.Bytes[i], v) {
			bm.Add(uint32(i))
		}
	}
	return bm, nil
}

func cmpInt(op string, a, b uint64) bool {
	switch op {
	case "!=":
		return a != b
	case "<":
		return a < b
	case ">":
		return a > b
	}
	return false
}

func cmpBytes(op string, a, b []byte) bool {
	switch op {
	case "!=":
		return string(a) != string(b)
	case "<":
		return string(a) < string(b)
	case ">":
		return string(a) > string(b)
	}
	return false
}

// --- value normalisation ---------------------------------------------------

func normInt(t schema.LogicalType, s string) (uint64, bool) {
	if t == schema.TypeTimestamp {
		if n, ok := parseTimestamp(s); ok {
			return uint64(n), true
		}
	}
	if t == schema.TypeBool {
		switch s {
		case "true", "1":
			return 1, true
		case "false", "0":
			return 0, true
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func normBytes(t schema.LogicalType, s string) ([]byte, bool) {
	if t == schema.TypeIP {
		return util.NormalizeIP(s)
	}
	return []byte(s), true
}

func parseTimestamp(s string) (int64, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if tm, err := time.Parse(layout, s); err == nil {
			return tm.UnixNano(), true
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	return 0, false
}

// --- formatting ------------------------------------------------------------

func formatCell(t schema.LogicalType, d *column.Data, i int) string {
	if d.IsNull(i) {
		return ""
	}
	if t.Kind() == column.KindInt {
		return formatIntVal(t, d.Ints[i])
	}
	return formatBytesVal(t, d.Bytes[i])
}

func formatIntVal(t schema.LogicalType, v uint64) string {
	switch t {
	case schema.TypeTimestamp:
		return time.Unix(0, int64(v)).UTC().Format(time.RFC3339Nano)
	case schema.TypeBool:
		if v != 0 {
			return "true"
		}
		return "false"
	default:
		return strconv.FormatUint(v, 10)
	}
}

func formatBytesVal(t schema.LogicalType, v []byte) string {
	if t == schema.TypeIP {
		return util.IPString(v)
	}
	return string(v)
}

// --- count -----------------------------------------------------------------

func execCount(r *store.Reader, st *Stmt) (*Result, error) {
	if st.Where == nil {
		return &Result{Kind: KindCount, Count: r.Footer().TotalRows}, nil
	}
	res := &Result{Kind: KindCount}
	for segIdx := range r.Footer().Segments {
		seg := &r.Footer().Segments[segIdx]
		ctx := &segCtx{r: r, sch: r.Schema(), segIdx: segIdx, rows: int(seg.Rows), cache: map[int]*column.Data{}}
		bm, err := evalSegment(ctx, st.Where)
		if err != nil {
			return nil, err
		}
		res.Count += bm.GetCardinality()
		tally(res, ctx, bm)
	}
	return res, nil
}

// --- top -------------------------------------------------------------------

func execTop(r *store.Reader, st *Stmt) (*Result, error) {
	sch := r.Schema()
	colIdx := sch.Index(st.Aggregate.Col)
	colDef := sch.Columns[colIdx]
	res := &Result{Kind: KindTop, Columns: []string{st.Aggregate.Col, "count"}}

	intHist := map[uint64]uint64{}
	bytesHist := map[string]uint64{}

	for segIdx := range r.Footer().Segments {
		seg := &r.Footer().Segments[segIdx]
		ctx := &segCtx{r: r, sch: sch, segIdx: segIdx, rows: int(seg.Rows), cache: map[int]*column.Data{}}

		// Fast path: no predicate + inverted index → merge precomputed histograms.
		if st.Where == nil {
			ci, err := r.Index(segIdx, colIdx)
			if err != nil {
				return nil, err
			}
			if colDef.Type.Kind() == column.KindInt && ci.Inverted != nil {
				for v, n := range ci.Inverted.Histogram() {
					intHist[v] += n
				}
				continue
			}
			if colDef.Type.Kind() == column.KindBytes && ci.Inverted != nil {
				for v, n := range ci.Inverted.HistogramBytes() {
					bytesHist[v] += n
				}
				continue
			}
		}

		bm, err := evalSegment(ctx, st.Where)
		if err != nil {
			return nil, err
		}
		if bm.IsEmpty() {
			tally(res, ctx, bm)
			continue
		}
		d, err := ctx.col(colIdx)
		if err != nil {
			return nil, err
		}
		it := bm.Iterator()
		for it.HasNext() {
			i := int(it.Next())
			if i >= d.Rows || d.IsNull(i) {
				continue
			}
			if colDef.Type.Kind() == column.KindInt {
				intHist[d.Ints[i]]++
			} else {
				bytesHist[string(d.Bytes[i])]++
			}
		}
		tally(res, ctx, bm)
	}

	type kv struct {
		key   string
		count uint64
	}
	var items []kv
	if colDef.Type.Kind() == column.KindInt {
		for v, n := range intHist {
			items = append(items, kv{formatIntVal(colDef.Type, v), n})
		}
	} else {
		for v, n := range bytesHist {
			items = append(items, kv{formatBytesVal(colDef.Type, []byte(v)), n})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	n := st.Aggregate.N
	if n > len(items) {
		n = len(items)
	}
	for _, it := range items[:n] {
		res.Rows = append(res.Rows, []string{it.key, strconv.FormatUint(it.count, 10)})
	}
	return res, nil
}

// --- rows / projection -----------------------------------------------------

func execRows(r *store.Reader, st *Stmt) (*Result, error) {
	sch := r.Schema()
	var outCols []int
	if st.Star {
		for i := range sch.Columns {
			outCols = append(outCols, i)
		}
	} else {
		for _, name := range st.Projection {
			outCols = append(outCols, sch.Index(name))
		}
	}
	res := &Result{Kind: KindRows}
	for _, ci := range outCols {
		res.Columns = append(res.Columns, sch.Columns[ci].Name)
	}

	limit := st.Limit
	if limit == 0 {
		limit = DefaultRowLimit
	}

	for segIdx := range r.Footer().Segments {
		if len(res.Rows) >= limit {
			break
		}
		seg := &r.Footer().Segments[segIdx]
		ctx := &segCtx{r: r, sch: sch, segIdx: segIdx, rows: int(seg.Rows), cache: map[int]*column.Data{}}
		bm, err := evalSegment(ctx, st.Where)
		if err != nil {
			return nil, err
		}
		if bm.IsEmpty() {
			tally(res, ctx, bm)
			continue
		}
		// Decode output columns for this segment.
		datas := make([]*column.Data, len(outCols))
		for k, ci := range outCols {
			d, err := ctx.col(ci)
			if err != nil {
				return nil, err
			}
			datas[k] = d
		}
		it := bm.Iterator()
		for it.HasNext() && len(res.Rows) < limit {
			i := int(it.Next())
			rowOut := make([]string, len(outCols))
			for k, ci := range outCols {
				rowOut[k] = formatCell(sch.Columns[ci].Type, datas[k], i)
			}
			res.Rows = append(res.Rows, rowOut)
		}
		tally(res, ctx, bm)
	}
	return res, nil
}

// tally records pruning observability: a segment that produced no matches
// without any column being decoded was pruned by zone maps / bloom filters.
func tally(res *Result, ctx *segCtx, bm *roaring.Bitmap) {
	if bm.IsEmpty() && !ctx.decoded {
		res.Pruned++
	} else {
		res.Scanned++
	}
}
