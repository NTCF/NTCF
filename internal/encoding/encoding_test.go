package encoding

import (
	"bytes"
	"math"
	"math/rand"
	"testing"
)

// intDatasets returns representative integer columns that exercise each codec's
// strengths and edge cases (empty, single, constant, monotonic timestamps,
// low-cardinality, sequential, and full-range values including >= 2^63).
func intDatasets() map[string][]uint64 {
	r := rand.New(rand.NewSource(1))
	ds := map[string][]uint64{
		"empty":       {},
		"single":      {42},
		"constant":    rep(1000, 7),
		"twoValues":   alt(1000, 80, 443),
		"monotonicTS": monoTimestamps(2000),
		"smallRange":  randRange(2000, 0, 65535, r),
		"sequential":  seq(2000, 1_000_000),
		"sparseASN":   randChoice(2000, []uint64{13335, 15169, 16509, 32934, 8075}, r),
		"fullRange":   {0, math.MaxUint64, 1 << 63, (1 << 63) + 1, math.MaxUint64 - 1},
		"random64":    randFull(1000, r),
	}
	return ds
}

func TestIntCodecsRoundTrip(t *testing.T) {
	codecs := []ID{Plain, Varint, Delta, DeltaOfDelta, RLEInt, Bitpack, DictInt}
	for name, vals := range intDatasets() {
		st := intStats{}
		if len(vals) > 0 {
			st = analyzeInts(vals)
		}
		for _, id := range codecs {
			var enc []byte
			switch id {
			case Plain:
				enc = encodePlain(vals)
			case Varint:
				enc = encodeVarint(vals)
			case Delta:
				enc = encodeDelta(vals)
			case DeltaOfDelta:
				enc = encodeDoD(vals)
			case RLEInt:
				enc = encodeRLEInt(vals)
			case Bitpack:
				if len(vals) == 0 {
					continue
				}
				enc = encodeBitpack(vals, st)
			case DictInt:
				if len(vals) == 0 {
					continue
				}
				enc = encodeDictInt(vals, st)
			}
			got, err := DecodeInts(id, enc, len(vals))
			if err != nil {
				t.Fatalf("%s/%s decode: %v", name, id, err)
			}
			if !equalU64(got, vals) {
				t.Fatalf("%s/%s round-trip mismatch\n got=%v\nwant=%v", name, id, trunc(got), trunc(vals))
			}
		}
	}
}

func TestEncodeIntsAuto(t *testing.T) {
	for name, vals := range intDatasets() {
		id, enc := EncodeIntsAuto(vals)
		got, err := DecodeInts(id, enc, len(vals))
		if err != nil {
			t.Fatalf("%s auto(%s) decode: %v", name, id, err)
		}
		if !equalU64(got, vals) {
			t.Fatalf("%s auto(%s) mismatch", name, id)
		}
		// Auto must never be worse than plain.
		if len(vals) > 0 && len(enc) > len(encodePlain(vals)) {
			t.Errorf("%s auto(%s) %d bytes worse than plain %d", name, id, len(enc), len(encodePlain(vals)))
		}
	}
}

func bytesDatasets() map[string][][]byte {
	r := rand.New(rand.NewSource(2))
	mk := func(ss ...string) [][]byte {
		out := make([][]byte, len(ss))
		for i, s := range ss {
			out[i] = []byte(s)
		}
		return out
	}
	events := []string{"ssh.login.failed", "ssh.login.success", "rdp.scan", "http.get"}
	return map[string][][]byte{
		"empty":        {},
		"single":       mk("RU"),
		"constant":     repB(500, []byte("tcp")),
		"countries":    randChoiceB(2000, mk("RU", "CN", "US", "DE", "BR"), r),
		"eventtypes":   runsB(2000, mk(events...), r),
		"withEmpty":    mk("", "a", "", "bb", ""),
		"highCardURLs": randURLs(1000, r),
	}
}

func TestBytesCodecsRoundTrip(t *testing.T) {
	codecs := []ID{Raw, DictBytes, RLEBytes}
	for name, vals := range bytesDatasets() {
		dist := analyzeBytes(orEmptyB(vals)).distinct
		for _, id := range codecs {
			var enc []byte
			switch id {
			case Raw:
				enc = encodeRaw(vals)
			case DictBytes:
				if len(vals) == 0 {
					continue
				}
				enc = encodeDictBytes(vals, dist)
			case RLEBytes:
				if len(vals) == 0 {
					continue
				}
				enc = encodeRLEBytes(vals)
			}
			got, err := DecodeBytes(id, enc, len(vals))
			if err != nil {
				t.Fatalf("%s/%s decode: %v", name, id, err)
			}
			if !equalBytes(got, vals) {
				t.Fatalf("%s/%s round-trip mismatch", name, id)
			}
		}
		id, enc := EncodeBytesAuto(vals)
		got, err := DecodeBytes(id, enc, len(vals))
		if err != nil || !equalBytes(got, vals) {
			t.Fatalf("%s auto(%s) failed: err=%v", name, id, err)
		}
	}
}

func TestBitpackWidths(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for width := uint(0); width <= 64; width++ {
		n := 257 // not a multiple of 8 to exercise tail handling
		vals := make([]uint64, n)
		var mask uint64 = math.MaxUint64
		if width < 64 {
			mask = (uint64(1) << width) - 1
		}
		for i := range vals {
			vals[i] = r.Uint64() & mask
		}
		packed := appendPacked(nil, vals, width)
		if got := len(packed); got != packedBytes(n, width) {
			t.Fatalf("width %d: packed %d bytes, expected %d", width, got, packedBytes(n, width))
		}
		out := make([]uint64, n)
		if err := unpackInto(out, packed, width); err != nil {
			t.Fatalf("width %d unpack: %v", width, err)
		}
		if !equalU64(out, vals) {
			t.Fatalf("width %d round-trip mismatch", width)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func rep(n int, v uint64) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		s[i] = v
	}
	return s
}
func repB(n int, v []byte) [][]byte {
	s := make([][]byte, n)
	for i := range s {
		s[i] = v
	}
	return s
}
func alt(n int, a, b uint64) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		if i%2 == 0 {
			s[i] = a
		} else {
			s[i] = b
		}
	}
	return s
}
func monoTimestamps(n int) []uint64 {
	s := make([]uint64, n)
	t := uint64(1_700_000_000_000_000_000)
	for i := range s {
		t += uint64(1_000_000 + i%5)
		s[i] = t
	}
	return s
}
func seq(n int, start uint64) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		s[i] = start + uint64(i)
	}
	return s
}
func randRange(n int, lo, hi uint64, r *rand.Rand) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		s[i] = lo + uint64(r.Int63n(int64(hi-lo+1)))
	}
	return s
}
func randChoice(n int, set []uint64, r *rand.Rand) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		s[i] = set[r.Intn(len(set))]
	}
	return s
}
func randFull(n int, r *rand.Rand) []uint64 {
	s := make([]uint64, n)
	for i := range s {
		s[i] = r.Uint64()
	}
	return s
}
func randChoiceB(n int, set [][]byte, r *rand.Rand) [][]byte {
	s := make([][]byte, n)
	for i := range s {
		s[i] = set[r.Intn(len(set))]
	}
	return s
}
func runsB(n int, set [][]byte, r *rand.Rand) [][]byte {
	s := make([][]byte, 0, n)
	for len(s) < n {
		v := set[r.Intn(len(set))]
		run := 1 + r.Intn(20)
		for k := 0; k < run && len(s) < n; k++ {
			s = append(s, v)
		}
	}
	return s
}
func randURLs(n int, r *rand.Rand) [][]byte {
	s := make([][]byte, n)
	for i := range s {
		s[i] = []byte("/path/" + string(rune('a'+r.Intn(26))) + "/" + itoa(r.Intn(1_000_000)))
	}
	return s
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
func orEmptyB(v [][]byte) [][]byte {
	if len(v) == 0 {
		return [][]byte{nil}
	}
	return v
}
func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func equalBytes(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
func trunc[T any](s []T) []T {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
