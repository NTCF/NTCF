package ntcf

import (
	"bytes"
	"testing"

	"github.com/ntcf/ntcf/internal/util"
)

// buildFile writes a deterministic dataset and returns a Reader over it.
// Rows: 1000 events, country cycling RU/CN/US, dstport in {22,3389,443},
// asn in {15169,13335}, srcip 198.51.100.{0..255}.
func buildFile(t *testing.T) *Reader {
	t.Helper()
	sch := testSchema()
	var buf bytes.Buffer
	opts := DefaultWriterOptions()
	opts.SegmentRows = 128
	w, err := NewWriter(&buf, sch, opts)
	if err != nil {
		t.Fatal(err)
	}
	countries := []string{"RU", "CN", "US"}
	ports := []uint64{22, 3389, 443}
	asns := []uint64{15169, 13335}
	base := uint64(1_700_000_000_000_000_000)
	for i := 0; i < 1000; i++ {
		ipb, _ := util.NormalizeIP("198.51.100." + itoa(i%256))
		rec := Record{
			IntVal(base + uint64(i)*1_000_000),
			BytesVal(ipb),
			IntVal(ports[i%3]),
			BytesVal([]byte(countries[i%3])),
			IntVal(asns[i%2]),
			BytesVal([]byte("ssh.bruteforce")),
		}
		if err := w.Append(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestQueryCount(t *testing.T) {
	r := buildFile(t)
	res, err := r.Query("SELECT count(*) FROM events")
	if err != nil || res.Count != 1000 {
		t.Fatalf("count(*)=%d err=%v", res.Count, err)
	}
	// country='RU' is every 3rd row starting at 0 -> ceil(1000/3)=334.
	res, err = r.Query("SELECT count(*) FROM events WHERE country='RU'")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 334 {
		t.Fatalf("RU count=%d want 334", res.Count)
	}
	// RU appears in every segment, so nothing is prunable here.
	if res.Pruned != 0 {
		t.Errorf("RU present in all segments; expected 0 pruned, got %d", res.Pruned)
	}
}

func TestQueryPruning(t *testing.T) {
	r := buildFile(t)
	// srcip 198.51.100.5 only occurs in segments whose i%256 range covers .5
	// (even-numbered 128-row segments). Odd segments span .128-.255 and must be
	// pruned by the zone map without decoding the column.
	res, err := r.Query("SELECT count(*) FROM events WHERE srcip='198.51.100.5'")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count == 0 {
		t.Fatal("expected matches for srcip=198.51.100.5")
	}
	if res.Pruned == 0 {
		t.Fatalf("expected zone-map/bloom pruning, got pruned=%d scanned=%d", res.Pruned, res.Scanned)
	}
}

func TestQueryCountAndOr(t *testing.T) {
	r := buildFile(t)
	// dstport=22 AND asn=15169. port=22 at i%3==0; asn=15169 at i%2==0.
	// i%6==0 -> i in {0,6,...,996}: 167 rows.
	res, err := r.Query("SELECT count(*) FROM events WHERE dstport=22 AND asn=15169")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 167 {
		t.Fatalf("AND count=%d want 167", res.Count)
	}
	// IN list.
	res, err = r.Query("SELECT count(*) FROM events WHERE dstport IN (22, 3389)")
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 667 { // ports 22 (334) + 3389 (333)
		t.Fatalf("IN count=%d want 667", res.Count)
	}
}

func TestQueryTop(t *testing.T) {
	r := buildFile(t)
	res, err := r.Query("SELECT top(dstport) FROM events")
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != ResultTop || len(res.Rows) == 0 {
		t.Fatalf("bad top result: %+v", res)
	}
	// Most frequent port is 22 (334).
	if res.Rows[0][0] != "22" || res.Rows[0][1] != "334" {
		t.Fatalf("top port = %v, want [22 334]", res.Rows[0])
	}
}

func TestQueryProjectionAndLimit(t *testing.T) {
	r := buildFile(t)
	res, err := r.Query("SELECT srcip, dstport FROM events WHERE country='CN' LIMIT 5")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Columns) != 2 || res.Columns[0] != "srcip" {
		t.Fatalf("columns=%v", res.Columns)
	}
	if len(res.Rows) != 5 {
		t.Fatalf("rows=%d want 5", len(res.Rows))
	}
}

func TestSearch(t *testing.T) {
	r := buildFile(t)
	res, err := r.Search("country", "US", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("expected US rows")
	}
	// search ip should match the srcip column.
	res, err = r.Search("ip", "198.51.100.5", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("expected ip matches")
	}
	for _, row := range res.Rows {
		if row[1] != "198.51.100.5" { // srcip is column index 1
			t.Fatalf("unexpected srcip in result: %v", row)
		}
	}
}
