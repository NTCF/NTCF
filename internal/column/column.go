// Package column models a single NTCF column: its in-memory vector, optional
// null (presence) bitmap, summary statistics for indexing, and the on-disk
// "column chunk" framing that pairs a semantic codec (internal/encoding) with
// an entropy codec (internal/compress).
//
// Two value domains exist, mirroring internal/encoding: integer columns carry
// []uint64 (the column layer maps IPs/ports/ASNs/timestamps/counters into this
// space) and byte columns carry [][]byte (strings, normalised addresses, blobs).
// Nulls are represented out-of-band by a presence bitmap, so the value stream
// holds only present values and a missing field is never confused with an
// empty string or a zero.
package column

// Kind is the value domain of a column.
type Kind uint8

const (
	KindInt   Kind = 0 // values carried as []uint64
	KindBytes Kind = 1 // values carried as [][]byte
)

func (k Kind) String() string {
	if k == KindBytes {
		return "bytes"
	}
	return "int"
}

// Bitmap is a compact presence bitmap: bit i set means row i is present
// (non-null). It is only materialised for columns that actually contain nulls.
type Bitmap struct {
	bits []byte
	n    int
}

// NewBitmap returns a bitmap for n rows with all rows marked absent.
func NewBitmap(n int) *Bitmap {
	return &Bitmap{bits: make([]byte, (n+7)/8), n: n}
}

// Set marks row i present.
func (b *Bitmap) Set(i int) { b.bits[i>>3] |= 1 << uint(i&7) }

// Get reports whether row i is present.
func (b *Bitmap) Get(i int) bool { return b.bits[i>>3]&(1<<uint(i&7)) != 0 }

// Len returns the number of rows.
func (b *Bitmap) Len() int { return b.n }

// Bytes returns the underlying bitmap bytes (length ceil(n/8)).
func (b *Bitmap) Bytes() []byte { return b.bits }

// bitmapFromBytes wraps raw bitmap bytes for n rows, validating length.
func bitmapFromBytes(raw []byte, n int) (*Bitmap, bool) {
	if len(raw) != (n+7)/8 {
		return nil, false
	}
	return &Bitmap{bits: raw, n: n}, true
}

// Data is a decoded column vector. Exactly one of Ints/Bytes is populated
// according to Kind. Present, when non-nil, gives per-row nullability; nil
// means every row is present.
type Data struct {
	Kind    Kind
	Ints    []uint64
	Bytes   [][]byte
	Present *Bitmap
	Rows    int
}

// IsNull reports whether row i is null.
func (d *Data) IsNull(i int) bool {
	return d.Present != nil && !d.Present.Get(i)
}

// Stats summarises a column chunk for index construction and zone-map pruning.
// Min/Max are over present values only and are meaningless when NonNull == 0.
type Stats struct {
	Rows     int
	NonNull  int
	HasNulls bool

	MinInt, MaxInt     uint64 // KindInt
	MinBytes, MaxBytes []byte // KindBytes
}
