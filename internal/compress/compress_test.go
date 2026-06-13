package compress

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestCodecsRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	inputs := map[string][]byte{
		"empty":          {},
		"tiny":           []byte("hello"),
		"compressible":   bytes.Repeat([]byte("telemetry "), 4096),
		"incompressible": randBytes(64<<10, r),
		"binary":         randBytes(1234, r),
	}
	for _, id := range []ID{None, Zstd, LZ4} {
		c, err := Get(id)
		if err != nil {
			t.Fatalf("Get(%s): %v", id, err)
		}
		for name, src := range inputs {
			comp := c.Compress(src)
			got, err := c.Decompress(comp, len(src))
			if err != nil {
				t.Fatalf("%s/%s decompress: %v", id, name, err)
			}
			if !bytes.Equal(got, src) {
				t.Fatalf("%s/%s round-trip mismatch (%d vs %d bytes)", id, name, len(got), len(src))
			}
		}
	}
}

func TestDecompressRejectsWrongLength(t *testing.T) {
	for _, id := range []ID{None, Zstd, LZ4} {
		c, _ := Get(id)
		comp := c.Compress([]byte("0123456789"))
		if _, err := c.Decompress(comp, 9999); err == nil {
			t.Errorf("%s: expected error on wrong outLen", id)
		}
	}
}

func TestDecompressHandlesGarbage(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, id := range []ID{None, Zstd, LZ4} {
		c, _ := Get(id)
		for i := 0; i < 200; i++ {
			junk := randBytes(r.Intn(128), r)
			// Must not panic; error is fine, accidental success is fine.
			_, _ = c.Decompress(junk, r.Intn(4096))
		}
	}
}

func FuzzDecompress(f *testing.F) {
	f.Add([]byte("hello"), 5)
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd}, 100)
	f.Fuzz(func(t *testing.T, data []byte, outLen int) {
		if outLen < 0 || outLen > 1<<20 {
			return
		}
		for _, id := range []ID{None, Zstd, LZ4} {
			c, _ := Get(id)
			_, _ = c.Decompress(data, outLen)
		}
	})
}

func randBytes(n int, r *rand.Rand) []byte {
	b := make([]byte, n)
	r.Read(b)
	return b
}
