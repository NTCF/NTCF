// Package util holds low-level primitives shared across NTCF internals:
// bounds-checked binary reading, varint/zigzag helpers, hashing, and the
// hard resource limits that protect readers from malformed or hostile files.
//
// Everything in this package is allocation-conscious and must never panic on
// attacker-controlled input — that invariant is enforced by the fuzz targets
// in the format and encoding packages.
package util

import "errors"

// Sentinel errors. Callers compare with errors.Is. Keeping them as package
// vars (rather than fmt.Errorf at call sites) lets the reader and CLI map
// failures to stable exit codes and recovery behaviour.
var (
	// ErrTruncated indicates a read ran past the end of the available buffer.
	// It almost always means the file is truncated or an embedded length is
	// larger than the data that follows it.
	ErrTruncated = errors.New("ntcf: truncated input")

	// ErrBadMagic indicates the leading or trailing magic bytes are wrong, so
	// the input is not an NTCF file (or is corrupt at its boundaries).
	ErrBadMagic = errors.New("ntcf: bad magic")

	// ErrUnsupportedVersion indicates the on-disk format version is outside the
	// range this build understands.
	ErrUnsupportedVersion = errors.New("ntcf: unsupported format version")

	// ErrChecksum indicates a stored checksum did not match the data it covers.
	ErrChecksum = errors.New("ntcf: checksum mismatch")

	// ErrCorrupt is a catch-all for internally inconsistent structures that
	// survived bounds and checksum checks but still cannot be interpreted.
	ErrCorrupt = errors.New("ntcf: corrupt structure")

	// ErrLimitExceeded indicates a declared size exceeded a hard safety limit
	// (see limits.go). This is the primary defence against decompression bombs
	// and allocation-amplification attacks.
	ErrLimitExceeded = errors.New("ntcf: resource limit exceeded")

	// ErrUnknownEncoding indicates a column chunk declared an encoding id this
	// build does not implement.
	ErrUnknownEncoding = errors.New("ntcf: unknown encoding id")

	// ErrUnknownCompression indicates a chunk declared a compression id this
	// build does not implement.
	ErrUnknownCompression = errors.New("ntcf: unknown compression id")

	// ErrSchema indicates a schema definition or schema/data mismatch.
	ErrSchema = errors.New("ntcf: schema error")
)
