package column

import (
	"github.com/ntcf/ntcf/internal/compress"
	"github.com/ntcf/ntcf/internal/encoding"
)

// Builder accumulates a single column's values for one segment, then encodes
// them into a self-describing column chunk.
//
// Null handling: the value stream always carries one entry per row (a
// placeholder for null rows), and a presence bitmap is materialised lazily the
// first time a null is appended. This keeps the encoders simple — they always
// see Rows() values — while still distinguishing null from zero/empty for query
// semantics. (Storing only the present values, Parquet-style, is a documented
// future optimisation; placeholders compress well under RLE/dictionary today.)
type Builder struct {
	kind    Kind
	ints    []uint64
	bytes   [][]byte
	present []bool // nil until the first null; thereafter len == rows
	rows    int
}

// NewBuilder returns a Builder for the given value domain.
func NewBuilder(kind Kind) *Builder { return &Builder{kind: kind} }

// Kind returns the column's value domain.
func (b *Builder) Kind() Kind { return b.kind }

// Rows returns the number of appended rows.
func (b *Builder) Rows() int { return b.rows }

// AppendInt appends a present integer value (KindInt columns only).
func (b *Builder) AppendInt(v uint64) {
	b.ints = append(b.ints, v)
	if b.present != nil {
		b.present = append(b.present, true)
	}
	b.rows++
}

// AppendBytes appends a present byte value. The slice is copied, so callers may
// reuse their buffer.
func (b *Builder) AppendBytes(v []byte) {
	cp := make([]byte, len(v))
	copy(cp, v)
	b.bytes = append(b.bytes, cp)
	if b.present != nil {
		b.present = append(b.present, true)
	}
	b.rows++
}

// AppendNull appends a null row, allocating the presence bitmap on first use.
func (b *Builder) AppendNull() {
	if b.present == nil {
		b.present = make([]bool, b.rows)
		for i := range b.present {
			b.present[i] = true
		}
	}
	if b.kind == KindInt {
		b.ints = append(b.ints, 0)
	} else {
		b.bytes = append(b.bytes, nil)
	}
	b.present = append(b.present, false)
	b.rows++
}

// Reset clears the builder for reuse across segments without reallocating.
func (b *Builder) Reset() {
	b.ints = b.ints[:0]
	b.bytes = b.bytes[:0]
	b.present = nil
	b.rows = 0
}

// Ints exposes the accumulated integer values (read-only) for index building.
func (b *Builder) Ints() []uint64 { return b.ints }

// BytesVals exposes the accumulated byte values (read-only) for index building.
func (b *Builder) BytesVals() [][]byte { return b.bytes }

// Present reports whether row i holds a present (non-null) value.
func (b *Builder) Present(i int) bool { return b.present == nil || b.present[i] }

// HasNulls reports whether any null has been appended.
func (b *Builder) HasNulls() bool { return b.present != nil }

// Stats computes summary statistics over the present values.
func (b *Builder) Stats() Stats {
	st := Stats{Rows: b.rows, HasNulls: b.present != nil}
	first := true
	for i := 0; i < b.rows; i++ {
		if !b.Present(i) {
			continue
		}
		st.NonNull++
		if b.kind == KindInt {
			v := b.ints[i]
			if first {
				st.MinInt, st.MaxInt = v, v
			} else {
				if v < st.MinInt {
					st.MinInt = v
				}
				if v > st.MaxInt {
					st.MaxInt = v
				}
			}
		} else {
			v := b.bytes[i]
			if first {
				st.MinBytes = cloneBytes(v)
				st.MaxBytes = cloneBytes(v)
			} else {
				if string(v) < string(st.MinBytes) {
					st.MinBytes = cloneBytes(v)
				}
				if string(v) > string(st.MaxBytes) {
					st.MaxBytes = cloneBytes(v)
				}
			}
		}
		first = false
	}
	return st
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// Encode serialises the column into a chunk, applying the chosen semantic codec
// and then the entropy codec — but only keeping entropy compression when it
// actually shrinks the payload (otherwise the chunk stores the semantic bytes
// verbatim with compression=None). It returns the chunk bytes and the column
// Stats for the segment directory / zone maps.
func (b *Builder) Encode(entropy compress.Codec) ([]byte, Stats, error) {
	st := b.Stats()

	var encID encoding.ID
	var encoded []byte
	if b.kind == KindInt {
		encID, encoded = encoding.EncodeIntsAuto(b.ints)
	} else {
		encID, encoded = encoding.EncodeBytesAuto(b.bytes)
	}

	compID := compress.None
	stored := encoded
	if entropy != nil && entropy.ID() != compress.None {
		cand := entropy.Compress(encoded)
		if len(cand) < len(encoded) {
			stored, compID = cand, entropy.ID()
		}
	}

	chunk := encodeChunkBytes(b.kind, encID, compID, b, len(encoded), stored)
	return chunk, st, nil
}
