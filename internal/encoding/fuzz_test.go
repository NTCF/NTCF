package encoding

import (
	"encoding/binary"
	"testing"
)

// FuzzDecodeInts feeds arbitrary bytes and row counts to every integer decoder.
// The contract under test is the security invariant: decoders must return an
// error or valid result, never panic, for any input.
func FuzzDecodeInts(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0x01, 0x02, 0x03}, 4)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x7f}, 1000)
	ids := []ID{Plain, Varint, Delta, DeltaOfDelta, RLEInt, Bitpack, DictInt}
	f.Fuzz(func(t *testing.T, data []byte, n int) {
		if n < 0 || n > 1<<20 {
			return
		}
		for _, id := range ids {
			_, _ = DecodeInts(id, data, n)
		}
	})
}

// FuzzDecodeBytes does the same for the byte-domain decoders.
func FuzzDecodeBytes(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{0x02, 'h', 'i'}, 3)
	f.Fuzz(func(t *testing.T, data []byte, n int) {
		if n < 0 || n > 1<<20 {
			return
		}
		for _, id := range []ID{Raw, DictBytes, RLEBytes} {
			_, _ = DecodeBytes(id, data, n)
		}
	})
}

// FuzzRoundTripInts asserts the stronger property that auto-encoding any vector
// and decoding it reproduces the input exactly.
func FuzzRoundTripInts(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, raw []byte) {
		n := len(raw) / 8
		if n == 0 {
			return
		}
		vals := make([]uint64, n)
		for i := 0; i < n; i++ {
			vals[i] = binary.LittleEndian.Uint64(raw[i*8:])
		}
		id, enc := EncodeIntsAuto(vals)
		got, err := DecodeInts(id, enc, n)
		if err != nil {
			t.Fatalf("decode %s: %v", id, err)
		}
		if !equalU64(got, vals) {
			t.Fatalf("round-trip mismatch via %s", id)
		}
	})
}

// FuzzRoundTripBytes does the same for byte vectors, splitting the input on a
// sentinel to form variable-length values.
func FuzzRoundTripBytes(f *testing.F) {
	f.Add([]byte("a\x00bb\x00\x00ccc"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var vals [][]byte
		cur := []byte{}
		for _, b := range raw {
			if b == 0 {
				vals = append(vals, cur)
				cur = []byte{}
			} else {
				cur = append(cur, b)
			}
		}
		vals = append(vals, cur)
		id, enc := EncodeBytesAuto(vals)
		got, err := DecodeBytes(id, enc, len(vals))
		if err != nil {
			t.Fatalf("decode %s: %v", id, err)
		}
		if !equalBytes(got, vals) {
			t.Fatalf("round-trip mismatch via %s", id)
		}
	})
}
