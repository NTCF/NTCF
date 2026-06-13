# NTCF Security Model

NTCF files arrive from untrusted places: a partner's threat feed, a tenant's
honeypot, an attacker probing your collector. **Every byte on disk is treated as
attacker-controlled.** This document states the threat model, the defenses, and
the non-goals.

## Threat model

A reader may be handed a file that is truncated, corrupted, or maliciously
crafted to make the reader allocate gigabytes, loop forever, read out of bounds,
or panic. The defensive contract is:

> For **any** input bytes, a decoder returns a value or an error — never a panic,
> never unbounded allocation, never an out-of-bounds access.

This contract is enforced by fuzz targets, not just asserted.

## Defenses

### Bounds-checked reading
All structured parsing goes through `util.Cursor`, which validates remaining
length before every read and latches the first error. A decoder built on it
cannot index out of range regardless of the lengths embedded in the file.

### Hard resource limits (`internal/util/limits.go`)
Every allocation whose size derives from a file-supplied count is gated by a
ceiling *before* the allocation happens:

| Limit | Value | Guards |
|-------|-------|--------|
| `MaxColumns` | 4096 | schema width |
| `MaxSegmentRows` | 16,777,216 | per-segment row count |
| `MaxSegments` | 1,048,576 | segment directory |
| `MaxDictEntries` | 16,777,216 | dictionary tables |
| `MaxChunkStored` | 1 GiB | on-disk chunk payload |
| `MaxChunkUncompressed` | 4 GiB | decompressed chunk |
| `MaxDecompressRatio` | 256:1 | expansion ratio |
| `MaxFooterSize` | 256 MiB | footer body |
| `MaxBytesValue` | 16 MiB | one variable-length value |
| `MaxStringTableBytes` | 1 GiB | dictionary value table |

### Decompression bombs
A chunk header declares its uncompressed length. Before decompressing, the reader
enforces both the absolute ceiling (`MaxChunkUncompressed`) and the
expansion-ratio cap (`MaxDecompressRatio`) via `util.CheckDecompress`. The zstd
decoder is additionally constructed with a bounded `WithDecoderMaxMemory`, and
the decompressed length is checked to equal the declared length, so a lying
header becomes an error rather than a silent truncation.

### Integer overflow
Offset/length/`count×width` arithmetic uses explicit checked helpers
(`CheckCount`, `CheckAlloc`) with `uint64` and overflow tests, so a crafted
length cannot wrap to a small allocation that is then overrun.

### Corruption detection
- **xxHash64** over every column-chunk payload; mismatch → `ErrChecksum`.
- **CRC32C** over the fixed header and the footer body; mismatch → `ErrChecksum`.
Corruption is detected before the data is interpreted.

### Crash recovery, safely
A truncated file (writer crash) is opened via a backward scan for the last valid
**checkpoint footer**, each of which is itself length- and CRC-validated. Only
fully-committed records are recovered; partial trailing data is discarded. See
[RFC-0001](RFC-0001-format.md) §4.

### Fuzzing
Fuzz targets enforce the no-panic contract across the attack surface:

- `internal/encoding`: `FuzzDecodeInts`, `FuzzDecodeBytes`, plus round-trip fuzz.
- `internal/compress`: `FuzzDecompress` (incl. garbage and wrong lengths).
- `internal/column`: `FuzzDecodeChunk`.
- `internal/index`: `FuzzReadColumnIndex`.
- `internal/query`: `FuzzParse`.
- `internal/adapter`: `FuzzAdaptersDecode`.

Run locally with e.g. `go test ./internal/encoding/ -run=^$ -fuzz=FuzzDecodeInts
-fuzztime=30s`; CI runs a short smoke pass on each.

## Non-goals (v1)

- **Authentication / tampering resistance.** NTCF checksums detect *accidental*
  corruption, not malicious modification — they are not MACs. An attacker who can
  rewrite a file can produce a valid-looking one. Authenticated containers
  (e.g. signed footers / AEAD) are a roadmap item. Do not rely on NTCF integrity
  checks as a security boundary against an active adversary with write access.
- **Encryption at rest.** Out of scope; layer it underneath (encrypted volume) or
  await the roadmap feature.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) for private disclosure instructions. Please do
not open public issues for security reports.
