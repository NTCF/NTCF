package util

import (
	"hash/crc32"

	"github.com/cespare/xxhash/v2"
)

// crc32cTable uses the Castagnoli polynomial, which has hardware acceleration
// (SSE4.2 CRC32 / ARM CRC) on all platforms we target. It guards small, hot
// metadata structures (header, footer, segment headers) where we want a fast
// integrity check rather than cryptographic strength.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// CRC32C returns the Castagnoli CRC of b. Used for header/footer integrity.
func CRC32C(b []byte) uint32 {
	return crc32.Checksum(b, crc32cTable)
}

// XXH64 returns the 64-bit xxHash of b. Used for column-chunk payloads where
// the larger digest reduces collision probability across very many chunks, and
// for bloom-filter and dictionary hashing. xxHash is non-cryptographic; NTCF
// checksums detect accidental corruption, not tampering (see docs/Security.md
// for the authenticated-container roadmap item).
func XXH64(b []byte) uint64 {
	return xxhash.Sum64(b)
}
