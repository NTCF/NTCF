package column

import (
	"encoding/binary"
	"fmt"

	"github.com/ntcf/ntcf/internal/compress"
	"github.com/ntcf/ntcf/internal/encoding"
	"github.com/ntcf/ntcf/internal/util"
)

// Chunk header flag bits.
const (
	flagHasNulls = 1 << 0
)

// On-disk column-chunk layout (all multi-byte ints little-endian; lengths are
// LEB128 uvarints):
//
//	kind            u8
//	encodingID      u8        (internal/encoding ID)
//	compressionID   u8        (internal/compress ID)
//	flags           u8        (bit0: presence bitmap follows)
//	rows            uvarint
//	uncompressedLen uvarint   (semantic-encoded length, pre-entropy)
//	storedLen       uvarint   (post-entropy length)
//	[if hasNulls] bitmapLen uvarint, bitmap[ceil(rows/8)]
//	checksum        u64       (xxHash64 over stored payload)
//	stored          [storedLen]byte
//
// The chunk is fully self-describing: given only its bytes it validates its own
// checksum, enforces decompression limits, and reconstructs values + nulls.

func encodeChunkBytes(kind Kind, encID encoding.ID, compID compress.ID, b *Builder, uncompressedLen int, stored []byte) []byte {
	var flags byte
	if b.HasNulls() {
		flags |= flagHasNulls
	}
	out := make([]byte, 0, 32+len(stored))
	out = append(out, byte(kind), byte(encID), byte(compID), flags)
	out = binary.AppendUvarint(out, uint64(b.rows))
	out = binary.AppendUvarint(out, uint64(uncompressedLen))
	out = binary.AppendUvarint(out, uint64(len(stored)))
	if b.HasNulls() {
		bm := NewBitmap(b.rows)
		for i := 0; i < b.rows; i++ {
			if b.present[i] {
				bm.Set(i)
			}
		}
		out = binary.AppendUvarint(out, uint64(len(bm.Bytes())))
		out = append(out, bm.Bytes()...)
	}
	out = binary.LittleEndian.AppendUint64(out, util.XXH64(stored))
	out = append(out, stored...)
	return out
}

// DecodeChunk parses and decodes a column chunk, validating its checksum and
// enforcing resource/decompression limits. The returned Data never aliases raw.
func DecodeChunk(raw []byte) (*Data, error) {
	c := util.NewCursor(raw)
	kind := Kind(c.U8())
	encID := encoding.ID(c.U8())
	compID := compress.ID(c.U8())
	flags := c.U8()
	rows64 := c.Uvarint()
	uncompressedLen := c.Uvarint()
	storedLen := c.Uvarint()
	if c.Err() != nil {
		return nil, c.Err()
	}
	if err := util.CheckCount("rows", rows64, util.MaxSegmentRows); err != nil {
		return nil, err
	}
	rows := int(rows64)

	var present *Bitmap
	if flags&flagHasNulls != 0 {
		bmLen := c.Uvarint()
		if bmLen != uint64((rows+7)/8) {
			return nil, fmt.Errorf("%w: bitmap length %d for %d rows", util.ErrCorrupt, bmLen, rows)
		}
		bmBytes := c.Bytes(int(bmLen))
		if c.Err() != nil {
			return nil, c.Err()
		}
		cp := make([]byte, len(bmBytes))
		copy(cp, bmBytes)
		bm, ok := bitmapFromBytes(cp, rows)
		if !ok {
			return nil, util.ErrCorrupt
		}
		present = bm
	}

	checksum := c.U64()
	if err := util.CheckCount("storedLen", storedLen, util.MaxChunkStored); err != nil {
		return nil, err
	}
	stored := c.Bytes(int(storedLen))
	if c.Err() != nil {
		return nil, c.Err()
	}
	if util.XXH64(stored) != checksum {
		return nil, util.ErrChecksum
	}
	if err := util.CheckDecompress(storedLen, uncompressedLen); err != nil {
		return nil, err
	}

	codec, err := compress.Get(compID)
	if err != nil {
		return nil, err
	}
	encoded, err := codec.Decompress(stored, int(uncompressedLen))
	if err != nil {
		return nil, err
	}

	d := &Data{Kind: kind, Present: present, Rows: rows}
	switch kind {
	case KindInt:
		vals, err := encoding.DecodeInts(encID, encoded, rows)
		if err != nil {
			return nil, err
		}
		d.Ints = vals
	case KindBytes:
		vals, err := encoding.DecodeBytes(encID, encoded, rows)
		if err != nil {
			return nil, err
		}
		d.Bytes = vals
	default:
		return nil, fmt.Errorf("%w: column kind %d", util.ErrCorrupt, kind)
	}
	return d, nil
}
