# NTCF On-Disk File Format (v1)

All multi-byte integers are **little-endian**. `uvarint` is unsigned LEB128;
`varint` is zigzag + LEB128. This document is normative for format version 1 and
matches `internal/format`, `internal/column`, `internal/schema`, and
`internal/index`.

```
┌────────────────────────────────────────────────────────────────────┐
│ Header (fixed 36 bytes)                                              │
├────────────────────────────────────────────────────────────────────┤
│ Segment 0 │ Segment 1 │ … │ Segment N-1                             │
│   each segment = column chunk 0 │ [index blob 0] │ chunk 1 │ …       │
├────────────────────────────────────────────────────────────────────┤
│ [intermediate checkpoint footers, if any — skipped on normal read]  │
├────────────────────────────────────────────────────────────────────┤
│ Footer body │ footerLen u32 │ CRC32C u32 │ trailer magic "NTCF"      │
└────────────────────────────────────────────────────────────────────┘
```

Segment and column locations are recorded by absolute offset in the footer, so
segments themselves are an opaque concatenation; intermediate checkpoint footers
written during streaming are simply skipped (the final footer's offsets account
for their bytes).

## 1. Header (36 bytes)

| Field      | Type      | Notes |
|------------|-----------|-------|
| magic      | `[4]byte` | `"NTCF"` (0x4E 0x54 0x43 0x46) |
| version    | `u16`     | format version (1) |
| flags      | `u16`     | reserved (0) |
| created    | `u64`     | creation time, unix nanoseconds |
| writerID   | `[16]byte`| opaque producer id |
| crc32c     | `u32`     | CRC32C (Castagnoli) over the preceding 32 bytes |

A reader validates magic, that `version` is supported, and the CRC before
trusting any other byte.

## 2. Column chunk

A chunk is self-describing: it validates its own checksum and enforces
decompression limits before producing values.

| Field           | Type      | Notes |
|-----------------|-----------|-------|
| kind            | `u8`      | 0 = integer domain, 1 = byte domain |
| encodingID      | `u8`      | semantic codec (§5) |
| compressionID   | `u8`      | entropy codec (§6) |
| flags           | `u8`      | bit0 = presence bitmap present (nullable) |
| rows            | `uvarint` | number of rows in this chunk (== segment rows) |
| uncompressedLen | `uvarint` | length of semantic-encoded bytes (pre-entropy) |
| storedLen       | `uvarint` | length of stored (post-entropy) payload |
| bitmapLen       | `uvarint` | present only if flags bit0 set; equals ⌈rows/8⌉ |
| bitmap          | bytes     | present-bit per row (1 = non-null), only if nullable |
| checksum        | `u64`     | xxHash64 over the stored payload |
| stored          | bytes     | `storedLen` bytes of entropy-compressed semantic data |

Decoding order: verify `checksum` over `stored`; enforce `uncompressedLen` ≤
absolute cap and `uncompressedLen/storedLen` ≤ ratio cap; entropy-decode to
exactly `uncompressedLen` bytes; semantic-decode `rows` values; reapply the
presence bitmap.

## 3. Footer

### 3.1 Schema descriptor

| Field    | Type      | Notes |
|----------|-----------|-------|
| schemaID | `u32`     | |
| nameLen  | `uvarint` | |
| name     | bytes     | |
| version  | `u16`     | schema version |
| colCount | `uvarint` | ≤ 4096 |
| columns  | …         | repeated: `nameLen uvarint`, `name`, `type u8`, `flags u8` (bit0 indexed, bit1 nullable) |

### 3.2 Footer body

| Field      | Type      | Notes |
|------------|-----------|-------|
| schema     | descriptor| §3.1 |
| sourceLen  | `uvarint` | |
| sourceType | bytes     | e.g. "honeypot" |
| totalRows  | `u64`     | |
| minTS      | `u64`     | file min timestamp (nanos), 0 if none |
| maxTS      | `u64`     | file max timestamp |
| segCount   | `uvarint` | |
| segments   | …         | repeated SegmentDir |

**SegmentDir:** `offset u64`, `length u64`, `rows uvarint`, `minTS u64`,
`maxTS u64`, `colCount uvarint`, then one **ColumnDir** per column:

| Field        | Type      | Notes |
|--------------|-----------|-------|
| chunkOffset  | `u64`     | absolute file offset of the chunk |
| chunkLength  | `u64`     | |
| indexOffset  | `u64`     | 0 if no index blob |
| indexLength  | `u64`     | |
| flags        | `u8`      | bit0 = hasNulls |
| nonNull      | `uvarint` | count of non-null values |
| zone-map min/max | …     | **integer columns:** `minInt u64`, `maxInt u64`. **byte columns:** `minLen uvarint`, `min bytes`, `maxLen uvarint`, `max bytes`. (The domain is known from the schema column type.) |

### 3.3 Footer trailer

`footerLen u32` (length of the footer body) · `CRC32C u32` (over the body) ·
`"NTCF"`. To open a file the reader seeks to the last 12 bytes, validates the
trailer magic, reads `footerLen` and CRC, slices and verifies the body.

## 4. Index blob

Written for `Indexed` columns immediately after their chunk; located by
`indexOffset`/`indexLength`.

| Field | Type | Notes |
|-------|------|-------|
| flags | `u8` | bit0 = Bloom present, bit1 = inverted present |
| bloom | …    | if present (§4.1) |
| inverted | … | if present (§4.2) |

### 4.1 Bloom filter
`k u8` (probe count) · `wordCount uvarint` · `wordCount × u64` bit words.
Sized to the column's **distinct** cardinality at a 1% target false-positive
rate. Hashing is xxHash64 with double hashing.

### 4.2 Inverted index (Roaring)
`kind u8` (0 int / 1 bytes) · `count uvarint` · entries in sorted order. Each
entry is the key (`uvarint` for int, `uvarint len`+bytes for byte) followed by
`bitmapLen uvarint` and the Roaring `MarshalBinary` bytes of the row positions.

## 5. Semantic encoding IDs (`internal/encoding`)

| ID | Name | Domain | Summary |
|----|------|--------|---------|
| 0 | plain | int | 8-byte LE per value |
| 1 | varint | int | uvarint per value |
| 2 | delta | int | first value + zigzag-varint deltas |
| 3 | delta-of-delta | int | timestamps; second-order deltas |
| 4 | rle | int | (value, run-length) pairs |
| 5 | bitpack-for | int | frame-of-reference + fixed-width bit packing |
| 6 | dict-int | int | sorted distinct values + bit-packed ordinals |
| 64 | raw | bytes | (len, bytes) per value |
| 65 | dict-bytes | bytes | value table + bit-packed ordinals |
| 66 | rle-bytes | bytes | (value, run-length) pairs |

All integer codecs round-trip the full `uint64` range exactly (arithmetic is
modulo 2⁶⁴). The encoder picks the smallest-producing codec per chunk.

## 6. Compression IDs (`internal/compress`)

| ID | Name | Notes |
|----|------|-------|
| 0 | none | stored verbatim |
| 1 | zstd | klauspost/compress, pure Go (default) |
| 2 | lz4 | pierrec/lz4 block, pure Go; 1-byte raw/compressed self-describing header |

## 7. Versioning & compatibility

The header `version` gates breaking layout changes. A reader refuses versions
outside `[FormatMin, FormatMax]`. Unknown encoding/compression IDs are rejected
cleanly (no panic). Additive changes (new codecs, new logical types) increment
the version only when they alter the byte layout of existing structures.
