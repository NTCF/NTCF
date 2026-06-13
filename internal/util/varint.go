package util

import "encoding/binary"

// ZigZag maps signed integers to unsigned so small-magnitude negatives encode
// compactly as varints: 0->0, -1->1, 1->2, -2->3, ... This is the standard
// transform used before delta/varint encoding of signed deltas.
func ZigZag(v int64) uint64 {
	return uint64((v << 1) ^ (v >> 63))
}

// UnZigZag inverts ZigZag.
func UnZigZag(v uint64) int64 {
	return int64(v>>1) ^ -int64(v&1)
}

// AppendUvarint appends the LEB128 unsigned varint encoding of v to dst.
func AppendUvarint(dst []byte, v uint64) []byte {
	return binary.AppendUvarint(dst, v)
}

// AppendVarint appends the zigzag+LEB128 encoding of a signed v to dst.
func AppendVarint(dst []byte, v int64) []byte {
	return binary.AppendUvarint(dst, ZigZag(v))
}

// UvarintLen returns the number of bytes AppendUvarint would emit for v.
func UvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
