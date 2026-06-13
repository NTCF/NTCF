package index

import (
	"testing"

	"github.com/ntcf/ntcf/internal/util"
)

func TestBloomNoFalseNegatives(t *testing.T) {
	b := NewBloom(1000, 0.01)
	for i := 0; i < 1000; i++ {
		b.AddU64(uint64(i * 7))
	}
	for i := 0; i < 1000; i++ {
		if !b.MayContainU64(uint64(i * 7)) {
			t.Fatalf("false negative for %d", i*7)
		}
	}
	// Round-trip.
	raw := b.Append(nil)
	got, err := ReadBloom(util.NewCursor(raw))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if !got.MayContainU64(uint64(i * 7)) {
			t.Fatalf("post-serialize false negative for %d", i*7)
		}
	}
}

func TestInvertedIntLookup(t *testing.T) {
	vals := []uint64{22, 22, 80, 443, 22, 80}
	iv := BuildInvertedInts(vals, nil)
	bm := iv.LookupInt(22)
	if bm == nil || bm.GetCardinality() != 3 {
		t.Fatalf("expected 3 rows for 22, got %v", bm)
	}
	if !bm.Contains(0) || !bm.Contains(1) || !bm.Contains(4) {
		t.Fatal("wrong rows for value 22")
	}
	if iv.LookupInt(9999) != nil {
		t.Fatal("expected nil for absent value")
	}
	// Round-trip.
	raw := (&ColumnIndex{Inverted: iv}).Append(nil)
	ci, err := ReadColumnIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Inverted.LookupInt(443).GetCardinality() != 1 {
		t.Fatal("443 should have 1 row after round-trip")
	}
}

func TestInvertedBytesAndHistogram(t *testing.T) {
	vals := [][]byte{[]byte("RU"), []byte("CN"), []byte("RU"), []byte("US"), []byte("RU")}
	ci := BuildBytesColumn(vals, nil, true)
	if ci.Inverted.LookupBytes([]byte("RU")).GetCardinality() != 3 {
		t.Fatal("RU count")
	}
	h := ci.Inverted.HistogramBytes()
	if h["RU"] != 3 || h["CN"] != 1 {
		t.Fatalf("histogram wrong: %v", h)
	}
	if !ci.Bloom.MayContain([]byte("US")) {
		t.Fatal("bloom should contain US")
	}
}

func FuzzReadColumnIndex(f *testing.F) {
	ci := BuildIntColumn([]uint64{1, 2, 2, 3}, nil, true)
	f.Add(ci.Append(nil))
	f.Add([]byte{0x03, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadColumnIndex(data) // must never panic
	})
}
