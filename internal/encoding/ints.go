package encoding

import (
	"encoding/binary"
	"sort"

	"github.com/ntcf/ntcf/internal/util"
)

// EncodeIntsAuto encodes vals with the integer codec that yields the smallest
// pre-entropy payload, returning the chosen ID and bytes. It always considers
// Plain/Varint as safe fallbacks, so the result is never worse than varint.
//
// The candidate set is type-directed by cheap statistics (monotonicity, value
// range, cardinality) to avoid encoding with codecs that obviously cannot win,
// then the survivors are materialised and the shortest is kept. n is bounded
// per segment, so this trial cost is acceptable for a packing tool and buys
// robust ratios without hand-tuned per-column rules.
func EncodeIntsAuto(vals []uint64) (ID, []byte) {
	if len(vals) == 0 {
		return Plain, nil
	}
	st := analyzeInts(vals)

	best := encodePlain(vals)
	bestID := Plain

	consider := func(id ID, b []byte) {
		if b != nil && len(b) < len(best) {
			best, bestID = b, id
		}
	}

	consider(Varint, encodeVarint(vals))
	if st.runs*3 < st.n { // RLE only helps when runs are meaningfully fewer than rows
		consider(RLEInt, encodeRLEInt(vals))
	}
	consider(Bitpack, encodeBitpack(vals, st))
	if st.sortedNonDesc {
		consider(Delta, encodeDelta(vals))
		consider(DeltaOfDelta, encodeDoD(vals))
	} else {
		// Even unsorted timestamps/counters often benefit; try delta cheaply.
		consider(Delta, encodeDelta(vals))
	}
	if st.distinct <= util.MaxDictEntries && st.distinct*4 < st.n*3 {
		consider(DictInt, encodeDictInt(vals, st))
	}
	return bestID, best
}

// intStats holds cheap single-pass statistics that steer codec selection.
type intStats struct {
	n             int
	min, max      uint64
	distinct      int  // exact if <= dictProbeLimit, else dictProbeLimit (capped)
	distinctExact bool // whether distinct is exact
	runs          int  // number of maximal equal-value runs
	sortedNonDesc bool // values are non-decreasing
}

const dictProbeLimit = 1 << 16 // cap distinct counting to bound selector cost

func analyzeInts(vals []uint64) intStats {
	st := intStats{n: len(vals), min: vals[0], max: vals[0], runs: 1, sortedNonDesc: true}
	seen := make(map[uint64]struct{}, min(len(vals), dictProbeLimit))
	st.distinctExact = true
	for i, v := range vals {
		if v < st.min {
			st.min = v
		}
		if v > st.max {
			st.max = v
		}
		if i > 0 {
			if v != vals[i-1] {
				st.runs++
			}
			if v < vals[i-1] {
				st.sortedNonDesc = false
			}
		}
		if st.distinctExact {
			if _, ok := seen[v]; !ok {
				if len(seen) >= dictProbeLimit {
					st.distinctExact = false
				} else {
					seen[v] = struct{}{}
				}
			}
		}
	}
	if st.distinctExact {
		st.distinct = len(seen)
	} else {
		st.distinct = dictProbeLimit
	}
	return st
}

// --- Plain -----------------------------------------------------------------

func encodePlain(vals []uint64) []byte {
	out := make([]byte, 0, len(vals)*8)
	for _, v := range vals {
		out = binary.LittleEndian.AppendUint64(out, v)
	}
	return out
}

func decodePlain(data []byte, n int) ([]uint64, error) {
	if len(data) < n*8 {
		return nil, errTruncated
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	return out, nil
}

// --- Varint ----------------------------------------------------------------

func encodeVarint(vals []uint64) []byte {
	out := make([]byte, 0, len(vals)*2)
	for _, v := range vals {
		out = binary.AppendUvarint(out, v)
	}
	return out
}

func decodeVarint(data []byte, n int) ([]uint64, error) {
	out := make([]uint64, n)
	pos := 0
	for i := 0; i < n; i++ {
		v, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		out[i] = v
		pos += m
	}
	return out, nil
}

// --- Delta -----------------------------------------------------------------

func encodeDelta(vals []uint64) []byte {
	if len(vals) == 0 {
		return nil
	}
	out := binary.AppendUvarint(make([]byte, 0, len(vals)*2), vals[0])
	for i := 1; i < len(vals); i++ {
		d := int64(vals[i]) - int64(vals[i-1])
		out = binary.AppendUvarint(out, util.ZigZag(d))
	}
	return out
}

func decodeDelta(data []byte, n int) ([]uint64, error) {
	out := make([]uint64, n)
	if n == 0 {
		return out, nil
	}
	pos := 0
	first, m := binary.Uvarint(data)
	if m <= 0 {
		return nil, errTruncated
	}
	pos += m
	out[0] = first
	for i := 1; i < n; i++ {
		z, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		out[i] = uint64(int64(out[i-1]) + util.UnZigZag(z))
	}
	return out, nil
}

// --- Delta-of-delta (timestamps) ------------------------------------------

func encodeDoD(vals []uint64) []byte {
	if len(vals) == 0 {
		return nil
	}
	out := binary.AppendUvarint(make([]byte, 0, len(vals)*2), vals[0])
	if len(vals) == 1 {
		return out
	}
	prevDelta := int64(vals[1]) - int64(vals[0])
	out = binary.AppendUvarint(out, util.ZigZag(prevDelta))
	for i := 2; i < len(vals); i++ {
		d := int64(vals[i]) - int64(vals[i-1])
		out = binary.AppendUvarint(out, util.ZigZag(d-prevDelta))
		prevDelta = d
	}
	return out
}

func decodeDoD(data []byte, n int) ([]uint64, error) {
	out := make([]uint64, n)
	if n == 0 {
		return out, nil
	}
	pos := 0
	first, m := binary.Uvarint(data)
	if m <= 0 {
		return nil, errTruncated
	}
	pos += m
	out[0] = first
	if n == 1 {
		return out, nil
	}
	z, m := binary.Uvarint(data[pos:])
	if m <= 0 {
		return nil, errTruncated
	}
	pos += m
	prevDelta := util.UnZigZag(z)
	out[1] = uint64(int64(out[0]) + prevDelta)
	for i := 2; i < n; i++ {
		z, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		prevDelta += util.UnZigZag(z)
		out[i] = uint64(int64(out[i-1]) + prevDelta)
	}
	return out, nil
}

// --- Run-length ------------------------------------------------------------

func encodeRLEInt(vals []uint64) []byte {
	out := make([]byte, 0, 16)
	i := 0
	for i < len(vals) {
		j := i + 1
		for j < len(vals) && vals[j] == vals[i] {
			j++
		}
		out = binary.AppendUvarint(out, vals[i])
		out = binary.AppendUvarint(out, uint64(j-i))
		i = j
	}
	return out
}

func decodeRLEInt(data []byte, n int) ([]uint64, error) {
	out := make([]uint64, 0, n)
	pos := 0
	for len(out) < n {
		v, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		run, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if run == 0 || len(out)+int(run) > n {
			return nil, errCorrupt
		}
		for k := uint64(0); k < run; k++ {
			out = append(out, v)
		}
	}
	if len(out) != n {
		return nil, errCorrupt
	}
	return out, nil
}

// --- Frame-of-reference bit packing ---------------------------------------

func encodeBitpack(vals []uint64, st intStats) []byte {
	width := minWidth(st.max - st.min)
	out := binary.AppendUvarint(make([]byte, 0, packedBytes(len(vals), width)+10), st.min)
	out = append(out, byte(width))
	if width == 0 {
		return out
	}
	res := make([]uint64, len(vals))
	for i, v := range vals {
		res[i] = v - st.min
	}
	return appendPacked(out, res, width)
}

func decodeBitpack(data []byte, n int) ([]uint64, error) {
	minv, m := binary.Uvarint(data)
	if m <= 0 {
		return nil, errTruncated
	}
	pos := m
	if pos >= len(data) {
		return nil, errTruncated
	}
	width := uint(data[pos])
	pos++
	if width > 64 {
		return nil, errBadWidth
	}
	out := make([]uint64, n)
	if err := unpackInto(out, data[pos:], width); err != nil {
		return nil, err
	}
	for i := range out {
		out[i] += minv
	}
	return out, nil
}

// --- Dictionary (integer) --------------------------------------------------

func encodeDictInt(vals []uint64, st intStats) []byte {
	// Build sorted distinct table.
	dict := make([]uint64, 0, st.distinct)
	seen := make(map[uint64]uint32, st.distinct)
	for _, v := range vals {
		if _, ok := seen[v]; !ok {
			seen[v] = 0
			dict = append(dict, v)
		}
	}
	sort.Slice(dict, func(i, j int) bool { return dict[i] < dict[j] })
	for i, v := range dict {
		seen[v] = uint32(i)
	}
	idx := make([]uint64, len(vals))
	for i, v := range vals {
		idx[i] = uint64(seen[v])
	}

	out := binary.AppendUvarint(make([]byte, 0, len(dict)*2+len(vals)), uint64(len(dict)))
	prev := uint64(0)
	for i, v := range dict {
		if i == 0 {
			out = binary.AppendUvarint(out, v)
		} else {
			out = binary.AppendUvarint(out, v-prev) // sorted: non-negative gaps
		}
		prev = v
	}
	width := minWidth(uint64(len(dict) - 1))
	out = append(out, byte(width))
	return appendPacked(out, idx, width)
}

func decodeDictInt(data []byte, n int) ([]uint64, error) {
	dictLen, m := binary.Uvarint(data)
	if m <= 0 {
		return nil, errTruncated
	}
	if err := util.CheckCount("dict", dictLen, util.MaxDictEntries); err != nil {
		return nil, err
	}
	pos := m
	dict := make([]uint64, dictLen)
	prev := uint64(0)
	for i := range dict {
		g, m := binary.Uvarint(data[pos:])
		if m <= 0 {
			return nil, errTruncated
		}
		pos += m
		if i == 0 {
			dict[i] = g
		} else {
			dict[i] = prev + g
		}
		prev = dict[i]
	}
	if pos >= len(data) {
		if n == 0 {
			return []uint64{}, nil
		}
		return nil, errTruncated
	}
	width := uint(data[pos])
	pos++
	if width > 64 {
		return nil, errBadWidth
	}
	idx := make([]uint64, n)
	if err := unpackInto(idx, data[pos:], width); err != nil {
		return nil, err
	}
	out := make([]uint64, n)
	for i, ix := range idx {
		if ix >= dictLen {
			return nil, errCorrupt
		}
		out[i] = dict[ix]
	}
	return out, nil
}
