package ntcf

import (
	"bytes"
	"testing"

	"github.com/ntcf/ntcf/internal/util"
)

func testSchema() *Schema {
	return &Schema{
		ID:      1,
		Name:    "test-flow",
		Version: 1,
		Columns: []Column{
			{Name: "timestamp", Type: TypeTimestamp},
			{Name: "srcip", Type: TypeIP, Indexed: true},
			{Name: "dstport", Type: TypePort, Indexed: true},
			{Name: "country", Type: TypeEnum, Indexed: true, Nullable: true},
			{Name: "asn", Type: TypeUint, Indexed: true},
			{Name: "eventtype", Type: TypeEnum},
		},
	}
}

func mkRecord(t *testing.T, ts uint64, ip string, port uint64, country string, asn uint64, ev string) Record {
	t.Helper()
	ipb, ok := util.NormalizeIP(ip)
	if !ok {
		t.Fatalf("bad ip %q", ip)
	}
	countryVal := BytesVal([]byte(country))
	if country == "" {
		countryVal = NullVal()
	}
	return Record{
		IntVal(ts),
		BytesVal(ipb),
		IntVal(port),
		countryVal,
		IntVal(asn),
		BytesVal([]byte(ev)),
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	sch := testSchema()
	var buf bytes.Buffer
	opts := DefaultWriterOptions()
	opts.SegmentRows = 100 // force several segments
	opts.SourceType = "test"
	w, err := NewWriter(&buf, sch, opts)
	if err != nil {
		t.Fatal(err)
	}

	const n = 350
	base := uint64(1_700_000_000_000_000_000)
	for i := 0; i < n; i++ {
		country := "RU"
		if i%3 == 0 {
			country = "CN"
		}
		if i%7 == 0 {
			country = "" // null
		}
		rec := mkRecord(t, base+uint64(i)*1_000_000, "203.0.113."+itoa(i%256), uint64(20+i%5), country, uint64(15169+i%3), "ssh.bruteforce")
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
	info := r.Info()
	if info.TotalRows != n {
		t.Fatalf("TotalRows=%d want %d", info.TotalRows, n)
	}
	if len(info.Segments) != 4 { // 100,100,100,50
		t.Fatalf("segments=%d want 4", len(info.Segments))
	}
	if info.SourceType != "test" || info.SchemaName != "test-flow" {
		t.Fatalf("info meta wrong: %+v", info)
	}

	// Verify timestamps decode monotonically across the whole file.
	st := r.store()
	tsCol := sch.Index("timestamp")
	var got uint64
	row := 0
	for segIdx := range st.Footer().Segments {
		d, err := st.Column(segIdx, tsCol)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < d.Rows; i++ {
			want := base + uint64(row)*1_000_000
			if d.Ints[i] != want {
				t.Fatalf("seg %d row %d ts=%d want %d", segIdx, i, d.Ints[i], want)
			}
			got = d.Ints[i]
			row++
		}
	}
	_ = got
	if row != n {
		t.Fatalf("decoded %d rows want %d", row, n)
	}

	// Verify nullability of country was preserved.
	cCol := sch.Index("country")
	d, err := st.Column(0, cCol)
	if err != nil {
		t.Fatal(err)
	}
	if !d.IsNull(0) { // i=0 -> i%7==0 -> null
		t.Error("row 0 country should be null")
	}
	if d.IsNull(1) || string(d.Bytes[1]) != "RU" {
		t.Errorf("row 1 country=%q null=%v", d.Bytes[1], d.IsNull(1))
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
