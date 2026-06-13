package encoding

import "encoding/binary"

// Bit packing stores a sequence of fixed-width unsigned integers using exactly
// `width` bits each, LSB-first, with no per-value byte alignment. It is the
// substrate for frame-of-reference integer encoding and for dictionary index
// streams: after subtracting a per-chunk minimum (FOR) or mapping to small
// dictionary ordinals, the residuals need only ceil(log2(max+1)) bits.
//
// The pack and unpack routines are deliberately word-oriented and handle the
// full width range [0,64]; width 0 means "all values equal the implied base"
// and stores zero bytes.

// minWidth returns the number of bits needed to represent values in [0, max].
func minWidth(max uint64) uint {
	w := uint(0)
	for max > 0 {
		w++
		max >>= 1
	}
	return w
}

// packedBytes returns the number of bytes appendPacked emits for n values of
// the given width.
func packedBytes(n int, width uint) int {
	if width == 0 {
		return 0
	}
	bits := uint64(n) * uint64(width)
	return int((bits + 7) / 8)
}

// appendPacked appends n values bit-packed at `width` bits each to dst.
// Values wider than width are masked. width must be in [0,64].
func appendPacked(dst []byte, vals []uint64, width uint) []byte {
	if width == 0 {
		return dst
	}
	var mask uint64 = ^uint64(0)
	if width < 64 {
		mask = (uint64(1) << width) - 1
	}
	var acc uint64
	var nbits uint
	for _, v := range vals {
		v &= mask
		free := 64 - nbits
		if width <= free {
			acc |= v << nbits
			nbits += width
		} else {
			// Low `free` bits complete the current word; flush it, then the
			// remaining high bits seed the next word.
			acc |= (v & ((uint64(1) << free) - 1)) << nbits
			dst = binary.LittleEndian.AppendUint64(dst, acc)
			acc = v >> free
			nbits = width - free
		}
		if nbits == 64 {
			dst = binary.LittleEndian.AppendUint64(dst, acc)
			acc = 0
			nbits = 0
		}
	}
	for nbits > 0 {
		dst = append(dst, byte(acc))
		acc >>= 8
		if nbits >= 8 {
			nbits -= 8
		} else {
			nbits = 0
		}
	}
	return dst
}

// readLE64 reads up to 8 little-endian bytes from src at pos, zero-padding when
// fewer than 8 remain. The padding is safe because callers mask the result to
// the meaningful width and never rely on bits beyond the validated extent.
func readLE64(src []byte, pos uint64) uint64 {
	var v uint64
	for i := uint64(0); i < 8; i++ {
		p := pos + i
		if p >= uint64(len(src)) {
			break
		}
		v |= uint64(src[p]) << (8 * i)
	}
	return v
}

// getBits extracts the width-bit value at bit offset off from a packed stream.
func getBits(src []byte, off uint64, width uint) uint64 {
	if width == 0 {
		return 0
	}
	bytePos := off >> 3
	bitPos := uint(off & 7)
	lo := readLE64(src, bytePos)
	v := lo >> bitPos
	if have := 64 - bitPos; have < width {
		hi := readLE64(src, bytePos+8)
		v |= hi << have
	}
	if width < 64 {
		v &= (uint64(1) << width) - 1
	}
	return v
}

// unpackInto fills out with len(out) values unpacked from src at the given
// width. It validates that src is large enough before reading.
func unpackInto(out []uint64, src []byte, width uint) error {
	if width == 0 {
		for i := range out {
			out[i] = 0
		}
		return nil
	}
	if width > 64 {
		return errBadWidth
	}
	need := packedBytes(len(out), width)
	if len(src) < need {
		return errTruncated
	}
	off := uint64(0)
	for i := range out {
		out[i] = getBits(src, off, width)
		off += uint64(width)
	}
	return nil
}
