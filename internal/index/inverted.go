package index

import (
	"encoding/binary"
	"sort"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/ntcf/ntcf/internal/util"
)

// InvertedMaxCardinality caps the number of distinct values for which an
// inverted index is built. Above this, the column relies on its Bloom filter
// plus a scan of the decoded chunk (still cheap because the segment was already
// pruned by zone maps and the Bloom filter). The cap bounds index size for
// high-cardinality columns like source IPs.
const InvertedMaxCardinality = 1 << 16

// Inverted maps each distinct value of a column to the Roaring bitmap of row
// positions (within one segment) that hold it.
type Inverted struct {
	kind   uint8 // 0 = int domain, 1 = bytes domain
	ints   map[uint64]*roaring.Bitmap
	bytesM map[string]*roaring.Bitmap
}

// BuildInvertedInts builds an inverted index over integer values, or returns
// nil if the distinct count exceeds InvertedMaxCardinality. present reports
// whether a row is non-null (nulls are not indexed).
func BuildInvertedInts(vals []uint64, present func(int) bool) *Inverted {
	iv := &Inverted{kind: 0, ints: make(map[uint64]*roaring.Bitmap)}
	for i, v := range vals {
		if present != nil && !present(i) {
			continue
		}
		bm := iv.ints[v]
		if bm == nil {
			if len(iv.ints) >= InvertedMaxCardinality {
				return nil
			}
			bm = roaring.New()
			iv.ints[v] = bm
		}
		bm.Add(uint32(i))
	}
	return iv
}

// BuildInvertedBytes is the byte-domain counterpart of BuildInvertedInts.
func BuildInvertedBytes(vals [][]byte, present func(int) bool) *Inverted {
	iv := &Inverted{kind: 1, bytesM: make(map[string]*roaring.Bitmap)}
	for i, v := range vals {
		if present != nil && !present(i) {
			continue
		}
		key := string(v)
		bm := iv.bytesM[key]
		if bm == nil {
			if len(iv.bytesM) >= InvertedMaxCardinality {
				return nil
			}
			bm = roaring.New()
			iv.bytesM[key] = bm
		}
		bm.Add(uint32(i))
	}
	return iv
}

// LookupInt returns the row bitmap for an integer value, or nil if absent.
func (iv *Inverted) LookupInt(v uint64) *roaring.Bitmap {
	if iv == nil || iv.kind != 0 {
		return nil
	}
	return iv.ints[v]
}

// LookupBytes returns the row bitmap for a byte value, or nil if absent.
func (iv *Inverted) LookupBytes(v []byte) *roaring.Bitmap {
	if iv == nil || iv.kind != 1 {
		return nil
	}
	return iv.bytesM[string(v)]
}

// Histogram returns (value, count) pairs for integer columns, used by top(col)
// aggregation. Returns nil for byte columns.
func (iv *Inverted) Histogram() map[uint64]uint64 {
	if iv == nil || iv.kind != 0 {
		return nil
	}
	h := make(map[uint64]uint64, len(iv.ints))
	for v, bm := range iv.ints {
		h[v] = bm.GetCardinality()
	}
	return h
}

// HistogramBytes returns (value, count) pairs for byte columns.
func (iv *Inverted) HistogramBytes() map[string]uint64 {
	if iv == nil || iv.kind != 1 {
		return nil
	}
	h := make(map[string]uint64, len(iv.bytesM))
	for v, bm := range iv.bytesM {
		h[v] = bm.GetCardinality()
	}
	return h
}

// Append serialises the inverted index. Entries are emitted in sorted order for
// determinism and reproducible files.
func (iv *Inverted) Append(dst []byte) []byte {
	dst = append(dst, iv.kind)
	if iv.kind == 0 {
		keys := make([]uint64, 0, len(iv.ints))
		for k := range iv.ints {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		dst = binary.AppendUvarint(dst, uint64(len(keys)))
		for _, k := range keys {
			dst = binary.AppendUvarint(dst, k)
			dst = appendBitmap(dst, iv.ints[k])
		}
	} else {
		keys := make([]string, 0, len(iv.bytesM))
		for k := range iv.bytesM {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		dst = binary.AppendUvarint(dst, uint64(len(keys)))
		for _, k := range keys {
			dst = binary.AppendUvarint(dst, uint64(len(k)))
			dst = append(dst, k...)
			dst = appendBitmap(dst, iv.bytesM[k])
		}
	}
	return dst
}

func appendBitmap(dst []byte, bm *roaring.Bitmap) []byte {
	bm.RunOptimize()
	raw, _ := bm.MarshalBinary()
	dst = binary.AppendUvarint(dst, uint64(len(raw)))
	return append(dst, raw...)
}

// ReadInverted parses a serialised inverted index from a bounds-checked cursor.
func ReadInverted(c *util.Cursor) (*Inverted, error) {
	kind := c.U8()
	count := c.Uvarint()
	if err := util.CheckCount("inverted entries", count, InvertedMaxCardinality); err != nil {
		return nil, err
	}
	if c.Err() != nil {
		return nil, c.Err()
	}
	iv := &Inverted{kind: kind}
	switch kind {
	case 0:
		iv.ints = make(map[uint64]*roaring.Bitmap, count)
	case 1:
		iv.bytesM = make(map[string]*roaring.Bitmap, count)
	default:
		return nil, util.ErrCorrupt
	}
	for i := uint64(0); i < count; i++ {
		var key uint64
		var bkey []byte
		if kind == 0 {
			key = c.Uvarint()
		} else {
			l := c.Uvarint()
			if err := util.CheckCount("inverted key", l, util.MaxBytesValue); err != nil {
				return nil, err
			}
			bkey = c.Bytes(int(l))
		}
		bmLen := c.Uvarint()
		if err := util.CheckCount("bitmap", bmLen, util.MaxChunkStored); err != nil {
			return nil, err
		}
		raw := c.Bytes(int(bmLen))
		if c.Err() != nil {
			return nil, c.Err()
		}
		bm := roaring.New()
		if err := bm.UnmarshalBinary(raw); err != nil {
			return nil, util.ErrCorrupt
		}
		if kind == 0 {
			iv.ints[key] = bm
		} else {
			iv.bytesM[string(bkey)] = bm
		}
	}
	return iv, nil
}
