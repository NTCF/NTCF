package format

import (
	"testing"

	"github.com/ntcf/ntcf/internal/schema"
)

func sampleFooter() (*Footer, []byte) {
	sch := &schema.Schema{
		ID:      7,
		Name:    "t",
		Version: 1,
		Columns: []schema.Column{
			{Name: "timestamp", Type: schema.TypeTimestamp},
			{Name: "srcip", Type: schema.TypeIP, Indexed: true},
			{Name: "country", Type: schema.TypeEnum, Indexed: true, Nullable: true},
		},
	}
	f := &Footer{
		Schema:     sch,
		SourceType: "unit",
		TotalRows:  3,
		MinTS:      100,
		MaxTS:      300,
		Segments: []SegmentDir{{
			Offset: 36, Length: 200, Rows: 3, MinTS: 100, MaxTS: 300,
			Columns: []ColumnDir{
				{ChunkOffset: 36, ChunkLength: 50, MinInt: 100, MaxInt: 300},
				{ChunkOffset: 86, ChunkLength: 60, IndexOffset: 146, IndexLength: 10,
					MinBytes: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x01\x02\x03\x04"),
					MaxBytes: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x05\x06\x07\x08")},
				{ChunkOffset: 146, ChunkLength: 54, HasNulls: true, NonNull: 2,
					MinBytes: []byte("CN"), MaxBytes: []byte("RU")},
			},
		}},
	}
	// A header prefix is required so ReadFooter's offset math is satisfied.
	hdr := (&Header{Version: 1}).Append(nil)
	buf := f.Append(hdr)
	return f, buf
}

func TestFooterRoundTrip(t *testing.T) {
	want, buf := sampleFooter()
	got, err := ReadFooter(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema.Name != want.Schema.Name || len(got.Schema.Columns) != 3 {
		t.Fatalf("schema mismatch: %+v", got.Schema)
	}
	if got.TotalRows != 3 || got.SourceType != "unit" || got.MinTS != 100 || got.MaxTS != 300 {
		t.Fatalf("file meta mismatch: %+v", got)
	}
	seg := got.Segments[0]
	if seg.Rows != 3 || len(seg.Columns) != 3 {
		t.Fatalf("segment mismatch: %+v", seg)
	}
	if seg.Columns[0].MinInt != 100 || seg.Columns[0].MaxInt != 300 {
		t.Errorf("int zone map wrong: %+v", seg.Columns[0])
	}
	if string(seg.Columns[2].MinBytes) != "CN" || string(seg.Columns[2].MaxBytes) != "RU" {
		t.Errorf("bytes zone map wrong: %+v", seg.Columns[2])
	}
	if !seg.Columns[2].HasNulls || seg.Columns[2].NonNull != 2 {
		t.Errorf("null stats wrong: %+v", seg.Columns[2])
	}
}

func TestHeaderRejectsCorruption(t *testing.T) {
	buf := (&Header{Version: 1}).Append(nil)
	buf[10] ^= 0xff // flip a byte under the CRC
	if _, err := ReadHeader(buf); err == nil {
		t.Fatal("expected CRC error on corrupted header")
	}
}

func FuzzReadHeader(f *testing.F) {
	f.Add((&Header{Version: 1}).Append(nil))
	f.Add([]byte("NTCF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadHeader(data) // must never panic
	})
}

func FuzzReadFooter(f *testing.F) {
	_, buf := sampleFooter()
	f.Add(buf)
	f.Add([]byte("NTCF\x00\x00\x00\x00NTCF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadFooter(data)    // must never panic
		_, _ = RecoverFooter(data) // must never panic
	})
}
