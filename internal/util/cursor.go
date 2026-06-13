package util

import "encoding/binary"

// Cursor is a bounds-checked, little-endian reader over an in-memory byte
// slice. Every read validates remaining length before advancing, so decoders
// built on Cursor cannot index out of range regardless of file contents. Once
// an error occurs the cursor latches it (err sticks) so callers may issue a
// batch of reads and check err once at the end without risking a panic on
// intermediate bad data.
//
// Cursor never copies the underlying buffer; Bytes returns a sub-slice that
// aliases it. Callers that retain returned slices beyond the lifetime of the
// backing buffer must copy.
type Cursor struct {
	buf []byte
	pos int
	err error
}

// NewCursor returns a Cursor reading from buf starting at offset 0.
func NewCursor(buf []byte) *Cursor { return &Cursor{buf: buf} }

// Err returns the first error encountered, or nil.
func (c *Cursor) Err() error { return c.err }

// Pos returns the current read offset.
func (c *Cursor) Pos() int { return c.pos }

// Remaining returns the number of unread bytes.
func (c *Cursor) Remaining() int { return len(c.buf) - c.pos }

// fail latches err if not already set and returns false.
func (c *Cursor) fail(e error) bool {
	if c.err == nil {
		c.err = e
	}
	return false
}

// have reports whether n more bytes are available, latching ErrTruncated if
// not.
func (c *Cursor) have(n int) bool {
	if n < 0 || c.pos+n > len(c.buf) {
		return c.fail(ErrTruncated)
	}
	return true
}

// U8 reads a single byte.
func (c *Cursor) U8() byte {
	if c.err != nil || !c.have(1) {
		return 0
	}
	v := c.buf[c.pos]
	c.pos++
	return v
}

// U16 reads a little-endian uint16.
func (c *Cursor) U16() uint16 {
	if c.err != nil || !c.have(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(c.buf[c.pos:])
	c.pos += 2
	return v
}

// U32 reads a little-endian uint32.
func (c *Cursor) U32() uint32 {
	if c.err != nil || !c.have(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.buf[c.pos:])
	c.pos += 4
	return v
}

// U64 reads a little-endian uint64.
func (c *Cursor) U64() uint64 {
	if c.err != nil || !c.have(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(c.buf[c.pos:])
	c.pos += 8
	return v
}

// Uvarint reads an unsigned LEB128 varint.
func (c *Cursor) Uvarint() uint64 {
	if c.err != nil {
		return 0
	}
	v, n := binary.Uvarint(c.buf[c.pos:])
	if n <= 0 {
		c.fail(ErrTruncated)
		return 0
	}
	c.pos += n
	return v
}

// Varint reads a zigzag+LEB128 signed varint.
func (c *Cursor) Varint() int64 {
	return UnZigZag(c.Uvarint())
}

// Bytes returns a sub-slice of n bytes (aliasing the buffer) and advances.
// It returns nil on error.
func (c *Cursor) Bytes(n int) []byte {
	if c.err != nil || !c.have(n) {
		return nil
	}
	b := c.buf[c.pos : c.pos+n]
	c.pos += n
	return b
}

// Skip advances n bytes without returning them.
func (c *Cursor) Skip(n int) {
	if c.err != nil || !c.have(n) {
		return
	}
	c.pos += n
}

// Magic reads len(want) bytes and verifies they equal want, latching
// ErrBadMagic on mismatch.
func (c *Cursor) Magic(want []byte) {
	got := c.Bytes(len(want))
	if c.err != nil {
		return
	}
	if string(got) != string(want) {
		c.fail(ErrBadMagic)
	}
}
