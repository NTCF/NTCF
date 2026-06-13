// Package encoding implements NTCF's semantic column codecs: the "compress
// meaning" layer that runs before the generic entropy layer (zstd/lz4).
//
// Two value domains are supported:
//
//   - Integer columns, carried as []uint64. Logical signed/IP/port/asn/counter
//     columns are normalised to uint64 by the column layer; all integer
//     arithmetic here is exact modulo 2^64, so every codec round-trips the full
//     uint64 range regardless of how the bits are interpreted upstream.
//   - Byte columns, carried as [][]byte (variable-length strings/blobs/IPs).
//
// Each codec has a stable on-disk identifier (ID). The encoder picks the codec
// that produces the smallest pre-entropy payload (EncodeIntsAuto /
// EncodeBytesAuto); the decoder dispatches purely on the stored ID, so adding a
// codec never changes how existing files decode.
package encoding

import (
	"fmt"

	"github.com/ntcf/ntcf/internal/util"
)

// ID identifies a column codec on disk. Values are stable across releases.
type ID uint8

const (
	// Integer codecs.
	Plain        ID = 0 // 8-byte little-endian per value
	Varint       ID = 1 // LEB128 unsigned varint per value
	Delta        ID = 2 // first value + zigzag-varint successive deltas
	DeltaOfDelta ID = 3 // first value + first delta + zigzag-varint dod (timestamps)
	RLEInt       ID = 4 // (value-uvarint, run-length-uvarint) pairs
	Bitpack      ID = 5 // frame-of-reference: min + fixed-width bit packing
	DictInt      ID = 6 // sorted distinct values + bit-packed ordinals

	// Byte codecs.
	Raw       ID = 64 // (uvarint len, bytes) per value
	DictBytes ID = 65 // value table + bit-packed ordinals
	RLEBytes  ID = 66 // (value, run-length-uvarint) pairs
)

// String returns the human-readable codec name (for ntcf info / debugging).
func (id ID) String() string {
	switch id {
	case Plain:
		return "plain"
	case Varint:
		return "varint"
	case Delta:
		return "delta"
	case DeltaOfDelta:
		return "delta-of-delta"
	case RLEInt:
		return "rle"
	case Bitpack:
		return "bitpack-for"
	case DictInt:
		return "dict-int"
	case Raw:
		return "raw"
	case DictBytes:
		return "dict-bytes"
	case RLEBytes:
		return "rle-bytes"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(id))
	}
}

// IsInteger reports whether id is an integer-domain codec.
func (id ID) IsInteger() bool { return id < 64 }

// Package-local error wrappers map to the shared sentinels so callers can use
// errors.Is(err, util.ErrTruncated) etc.
var (
	errTruncated  = util.ErrTruncated
	errCorrupt    = util.ErrCorrupt
	errBadWidth   = fmt.Errorf("%w: bit width out of range", util.ErrCorrupt)
	errLimit      = util.ErrLimitExceeded
	errUnknownEnc = util.ErrUnknownEncoding
)

// DecodeInts decodes n integer values previously produced by an integer codec.
// id must be an integer-domain codec; n is the row count from the chunk header.
func DecodeInts(id ID, data []byte, n int) ([]uint64, error) {
	if n < 0 {
		return nil, errCorrupt
	}
	if err := util.CheckCount("rows", uint64(n), util.MaxSegmentRows); err != nil {
		return nil, err
	}
	switch id {
	case Plain:
		return decodePlain(data, n)
	case Varint:
		return decodeVarint(data, n)
	case Delta:
		return decodeDelta(data, n)
	case DeltaOfDelta:
		return decodeDoD(data, n)
	case RLEInt:
		return decodeRLEInt(data, n)
	case Bitpack:
		return decodeBitpack(data, n)
	case DictInt:
		return decodeDictInt(data, n)
	default:
		return nil, fmt.Errorf("%w: int id %d", errUnknownEnc, uint8(id))
	}
}

// DecodeBytes decodes n byte-slice values previously produced by a byte codec.
// The returned slices alias an internal copy of data, not data itself.
func DecodeBytes(id ID, data []byte, n int) ([][]byte, error) {
	if n < 0 {
		return nil, errCorrupt
	}
	if err := util.CheckCount("rows", uint64(n), util.MaxSegmentRows); err != nil {
		return nil, err
	}
	switch id {
	case Raw:
		return decodeRaw(data, n)
	case DictBytes:
		return decodeDictBytes(data, n)
	case RLEBytes:
		return decodeRLEBytes(data, n)
	default:
		return nil, fmt.Errorf("%w: bytes id %d", errUnknownEnc, uint8(id))
	}
}
