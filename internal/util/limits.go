package util

import "fmt"

// Hard safety limits. These bound the resources a single file or chunk may
// cause a reader to allocate, independent of any value declared inside the
// file. They are deliberately generous for legitimate telemetry workloads but
// finite, so a malformed or hostile file cannot drive unbounded allocation.
//
// Rationale (see docs/Security.md): an attacker controls every length field on
// disk. Without ceilings, a 200-byte file could claim a 1 EiB column and OOM
// the reader before any checksum is consulted. Every allocation derived from a
// file-supplied count is gated by one of these constants.
const (
	// MaxColumns caps the number of columns in a schema. Telemetry schemas are
	// wide but not unbounded.
	MaxColumns = 4096

	// MaxSegmentRows caps rows per segment. The writer flushes well below this;
	// the ceiling exists so a corrupt row-count cannot drive a huge alloc.
	MaxSegmentRows = 16 << 20 // 16,777,216

	// MaxSegments caps segments per file. At the default flush size this allows
	// multi-billion-row files while bounding the segment directory.
	MaxSegments = 1 << 20

	// MaxDictEntries caps distinct values in a single dictionary-encoded chunk.
	MaxDictEntries = 1 << 24

	// MaxChunkStored caps the on-disk (post-compression) size of one column
	// chunk's payload that a reader will load into memory.
	MaxChunkStored = 1 << 30 // 1 GiB

	// MaxChunkUncompressed caps the size a single chunk may expand to after the
	// entropy layer is undone. This is the primary decompression-bomb ceiling.
	MaxChunkUncompressed = 4 << 30 // 4 GiB

	// MaxDecompressRatio caps stored:uncompressed expansion per chunk. Even
	// within MaxChunkUncompressed, a ratio above this is rejected as a likely
	// bomb. Real telemetry rarely exceeds ~50x; 256x leaves wide headroom.
	MaxDecompressRatio = 256

	// MaxFooterSize caps the trailing metadata block.
	MaxFooterSize = 256 << 20 // 256 MiB

	// MaxBytesValue caps the length of a single variable-length (Bytes) value,
	// e.g. one URL or user-agent string.
	MaxBytesValue = 16 << 20 // 16 MiB

	// MaxStringTableBytes caps the total bytes of a dictionary's value table.
	MaxStringTableBytes = 1 << 30 // 1 GiB
)

// CheckCount validates that a file-declared element count is within [0, max].
// It returns ErrLimitExceeded (wrapped with context) otherwise. Use this
// before allocating any slice whose length comes from the file.
func CheckCount(what string, n uint64, max uint64) error {
	if n > max {
		return fmt.Errorf("%w: %s count %d exceeds limit %d", ErrLimitExceeded, what, n, max)
	}
	return nil
}

// CheckAlloc validates that count*elemSize will not exceed max bytes and does
// not overflow. It is the canonical guard before make([]T, count).
func CheckAlloc(what string, count, elemSize, max uint64) error {
	if elemSize != 0 && count > max/elemSize {
		return fmt.Errorf("%w: %s alloc %d*%d overflows/exceeds %d", ErrLimitExceeded, what, count, elemSize, max)
	}
	if count*elemSize > max {
		return fmt.Errorf("%w: %s alloc %d bytes exceeds limit %d", ErrLimitExceeded, what, count*elemSize, max)
	}
	return nil
}

// CheckDecompress validates a declared uncompressed size against both the
// absolute ceiling and the expansion ratio relative to the stored size.
func CheckDecompress(storedLen, uncompressedLen uint64) error {
	if uncompressedLen > MaxChunkUncompressed {
		return fmt.Errorf("%w: uncompressed %d exceeds %d", ErrLimitExceeded, uncompressedLen, MaxChunkUncompressed)
	}
	if storedLen > 0 && uncompressedLen/storedLen > MaxDecompressRatio {
		return fmt.Errorf("%w: ratio %d:1 exceeds %d:1", ErrLimitExceeded, uncompressedLen/storedLen, MaxDecompressRatio)
	}
	return nil
}
