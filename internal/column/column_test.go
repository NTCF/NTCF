package column

import (
	"bytes"
	"testing"

	"github.com/ntcf/ntcf/internal/compress"
)

func entropy(t *testing.T, id compress.ID) compress.Codec {
	t.Helper()
	c, err := compress.Get(id)
	if err != nil {
		t.Fatalf("compress.Get: %v", err)
	}
	return c
}

func TestIntColumnRoundTrip(t *testing.T) {
	for _, comp := range []compress.ID{compress.None, compress.Zstd, compress.LZ4} {
		b := NewBuilder(KindInt)
		want := []uint64{22, 22, 22, 80, 443, 0, 65535}
		nulls := map[int]bool{5: true}
		for i, v := range want {
			if nulls[i] {
				b.AppendNull()
			} else {
				b.AppendInt(v)
			}
		}
		chunk, st, err := b.Encode(entropy(t, comp))
		if err != nil {
			t.Fatal(err)
		}
		if st.Rows != len(want) || !st.HasNulls || st.NonNull != len(want)-1 {
			t.Fatalf("stats=%+v", st)
		}
		d, err := DecodeChunk(chunk)
		if err != nil {
			t.Fatalf("decode(%s): %v", comp, err)
		}
		if d.Rows != len(want) {
			t.Fatalf("rows=%d", d.Rows)
		}
		for i := range want {
			if nulls[i] {
				if !d.IsNull(i) {
					t.Errorf("row %d expected null", i)
				}
				continue
			}
			if d.IsNull(i) || d.Ints[i] != want[i] {
				t.Errorf("row %d = %d (null=%v), want %d", i, d.Ints[i], d.IsNull(i), want[i])
			}
		}
	}
}

func TestBytesColumnRoundTrip(t *testing.T) {
	b := NewBuilder(KindBytes)
	want := [][]byte{[]byte("RU"), []byte("RU"), nil, []byte("US"), []byte("")}
	b.AppendBytes(want[0])
	b.AppendBytes(want[1])
	b.AppendNull()
	b.AppendBytes(want[3])
	b.AppendBytes(want[4])

	chunk, st, err := b.Encode(entropy(t, compress.Zstd))
	if err != nil {
		t.Fatal(err)
	}
	if st.NonNull != 4 {
		t.Fatalf("nonNull=%d", st.NonNull)
	}
	d, err := DecodeChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if !d.IsNull(2) {
		t.Error("row 2 should be null")
	}
	if !bytes.Equal(d.Bytes[0], []byte("RU")) || !bytes.Equal(d.Bytes[4], []byte("")) {
		t.Errorf("byte values wrong: %q", d.Bytes)
	}
}

func TestChunkChecksumDetectsCorruption(t *testing.T) {
	b := NewBuilder(KindInt)
	for i := 0; i < 100; i++ {
		b.AppendInt(uint64(i))
	}
	chunk, _, err := b.Encode(entropy(t, compress.Zstd))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the stored payload (the last byte is part of it).
	chunk[len(chunk)-1] ^= 0xff
	if _, err := DecodeChunk(chunk); err == nil {
		t.Fatal("expected checksum/decode error on corrupted chunk")
	}
}

func FuzzDecodeChunk(f *testing.F) {
	b := NewBuilder(KindInt)
	for i := 0; i < 20; i++ {
		b.AppendInt(uint64(i))
	}
	seed, _, _ := b.Encode(mustGet(compress.Zstd))
	f.Add(seed)
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeChunk(data) // must never panic
	})
}

func mustGet(id compress.ID) compress.Codec {
	c, err := compress.Get(id)
	if err != nil {
		panic(err)
	}
	return c
}
