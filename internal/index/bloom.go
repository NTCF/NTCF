// Package index implements the per-segment indexes that let NTCF answer
// equality searches and predicate filters without decompressing whole columns:
//
//   - Bloom filters: a few KB per indexed column giving "definitely absent"
//     pruning across segments, ideal for high-cardinality columns (IPs) where a
//     full posting list would be large.
//   - Inverted (Roaring bitmap) indexes: value -> exact set of matching row
//     positions, built for columns whose cardinality is below a cap. They give
//     exact answers, fast intersections for AND/OR predicates, and O(1)-ish
//     COUNT via bitmap cardinality.
//
// Zone maps (per-column min/max) live in the file footer, not here, because
// they are consulted before any segment body is touched.
package index

import (
	"encoding/binary"
	"math"

	"github.com/ntcf/ntcf/internal/util"
)

// Bloom is a classic double-hashed Bloom filter over byte keys.
type Bloom struct {
	bits []uint64
	m    uint64 // number of bits (== len(bits)*64)
	k    uint8  // number of hash probes
}

// NewBloom sizes a filter for n expected distinct keys at false-positive rate
// fp (e.g. 0.01). n and fp are clamped to sane ranges.
func NewBloom(n int, fp float64) *Bloom {
	if n < 1 {
		n = 1
	}
	if fp <= 0 || fp >= 1 {
		fp = 0.01
	}
	mBits := uint64(math.Ceil(-float64(n) * math.Log(fp) / (math.Ln2 * math.Ln2)))
	words := (mBits + 63) / 64
	if words < 1 {
		words = 1
	}
	mBits = words * 64
	k := uint8(math.Round(float64(mBits) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	if k > 32 {
		k = 32
	}
	return &Bloom{bits: make([]uint64, words), m: mBits, k: k}
}

func (b *Bloom) probes(h uint64) (uint64, uint64) {
	h1 := h
	h2 := h>>33 | h<<31 // a cheap, well-mixed second hash from the same digest
	if h2 == 0 {
		h2 = 0x9E3779B97F4A7C15
	}
	return h1, h2
}

// Add inserts a byte key.
func (b *Bloom) Add(key []byte) { b.addHash(util.XXH64(key)) }

// AddU64 inserts an integer key (encoded as 8 little-endian bytes).
func (b *Bloom) AddU64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	b.addHash(util.XXH64(buf[:]))
}

func (b *Bloom) addHash(h uint64) {
	h1, h2 := b.probes(h)
	for i := uint8(0); i < b.k; i++ {
		bit := (h1 + uint64(i)*h2) % b.m
		b.bits[bit>>6] |= 1 << (bit & 63)
	}
}

// MayContain reports whether key might be present (false = definitely absent).
func (b *Bloom) MayContain(key []byte) bool { return b.mayContainHash(util.XXH64(key)) }

// MayContainU64 is the integer-key variant of MayContain.
func (b *Bloom) MayContainU64(v uint64) bool {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return b.mayContainHash(util.XXH64(buf[:]))
}

func (b *Bloom) mayContainHash(h uint64) bool {
	h1, h2 := b.probes(h)
	for i := uint8(0); i < b.k; i++ {
		bit := (h1 + uint64(i)*h2) % b.m
		if b.bits[bit>>6]&(1<<(bit&63)) == 0 {
			return false
		}
	}
	return true
}

// Append serialises the filter: k(u8), wordCount(uvarint), words(LE u64...).
func (b *Bloom) Append(dst []byte) []byte {
	dst = append(dst, b.k)
	dst = binary.AppendUvarint(dst, uint64(len(b.bits)))
	for _, w := range b.bits {
		dst = binary.LittleEndian.AppendUint64(dst, w)
	}
	return dst
}

// ReadBloom parses a serialised filter from a bounds-checked cursor.
func ReadBloom(c *util.Cursor) (*Bloom, error) {
	k := c.U8()
	words := c.Uvarint()
	if err := util.CheckCount("bloom words", words, 1<<28); err != nil {
		return nil, err
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	bits := make([]uint64, words)
	for i := range bits {
		bits[i] = c.U64()
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	if words == 0 || k == 0 {
		return nil, util.ErrCorrupt
	}
	return &Bloom{bits: bits, m: words * 64, k: k}, nil
}
