---
title: "The NTCF Network & Telemetry Compression Format"
abbrev: "NTCF"
docname: draft-ntcf-format-00
category: info
ipr: trust200902
area: Operations and Management
workgroup: Independent Submission
keyword: telemetry, compression, columnar, netflow, security, logging
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - name: The NTCF Authors
    organization: NTCF Project
    email: spec@ntcf.dev
---

# Abstract

This document specifies NTCF (Network & Telemetry Compression Format), a
self-describing, columnar, append-friendly binary container for cybersecurity
and network telemetry such as flow records, honeypot events, and web/access
logs. Unlike general-purpose byte compressors, NTCF models the *semantics* of
telemetry — IP addresses, autonomous system numbers, ports, country codes,
event types, and timestamps — as typed columns and applies semantic encodings
(dictionary, delta, delta-of-delta, run-length, frame-of-reference bit-packing,
and variable-length integers) before a conventional entropy stage. The format
embeds zone-map statistics and Bloom filters so that point lookups and
analytical predicates can be evaluated by reading only the columns and segments
that can possibly match, without decompressing the entire file. This document
defines the on-disk byte layout (format version 1), the encoding catalogue, the
reading and crash-recovery algorithms, a resource-limit model, security
considerations, and an IANA media-type registration.

# Status of This Memo

This is a draft specification published for review and implementation. It is
NOT an IETF standard and has not been reviewed or approved by the IESG. It is
intended to be submittable as an Independent Submission Internet-Draft. The
key words for normativity are used as defined in BCP 14 (RFC 2119, RFC 8174).

Distribution of this memo is unlimited. The reference implementation is
available under the Apache-2.0 license.

# Copyright Notice

Copyright (c) 2026 The NTCF Authors. This document is provided under the terms
of the Apache License, Version 2.0.

---

# 1. Introduction

## 1.1 Problem

Security and network telemetry is high-volume, highly repetitive, and almost
always interrogated along a small number of dimensions (source/destination IP,
ASN, country, port, event type, and time). Operators retain large archives and
incur two costs: storage of the data at rest, and time spent decompressing whole
archives to answer a single question during an incident.

General-purpose compressors (gzip, zstd, lz4, xz) reduce the storage cost but
produce an opaque blob: answering "which records involved 203.0.113.5?" requires
full decompression, and the format provides no analytics. General-purpose
columnar analytics formats make data queryable but are not specialised for
telemetry semantics (e.g. IP/ASN/CIDR types and IP-range pruning) nor for
crash-safe streaming append from an edge sensor.

## 1.2 Goals

NTCF aims to be, simultaneously:

1. **Compact** — competitive with or better than the best general-purpose
   compressors on representative telemetry, by encoding meaning rather than
   bytes.
2. **Searchable in place** — equality search and a useful subset of analytical
   queries answerable without decompressing the whole file, using embedded
   zone maps, Bloom filters, and optional inverted indexes.
3. **Streaming- and crash-safe** — appendable from a long-running sensor such
   that a process crash leaves a readable file containing all committed records.
4. **Self-describing and versioned** — a file carries its own schema and a
   format version that gates compatibility.

## 1.3 Non-Goals (this version)

Cryptographic authentication and encryption of files, distributed query, joins
across files, and a network storage service are out of scope for format
version 1. See Section 15.

# 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 (RFC 2119) (RFC 8174) when, and only when,
they appear in all capitals.

Data types and conventions used throughout:

- All multi-octet integers are **little-endian** unless stated otherwise.
- `u8`, `u16`, `u32`, `u64` denote unsigned integers of that width.
- `uvarint` denotes an unsigned LEB128 variable-length integer (as in
  Protocol Buffers / Go `encoding/binary.Uvarint`): 7 bits per octet,
  most-significant-bit set on all but the final octet.
- `varint` denotes a signed integer encoded as ZigZag(value) then `uvarint`,
  where `ZigZag(v) = (v << 1) XOR (v >> 63)` over a two's-complement 64-bit `v`.
- `bytes[n]` denotes `n` raw octets.
- `⌈x⌉` denotes the ceiling of `x`.

Terminology:

- **Column**: a named, typed sequence of one value per row.
- **Column chunk**: the encoded, optionally compressed, self-validating
  serialization of one column within one segment.
- **Segment**: a row group; a contiguous run of rows whose columns are stored
  as adjacent column chunks. A segment is located by absolute offset from the
  footer; it is **not** independently framed (see Section 6.1).
- **Footer**: the trailing metadata block: schema descriptor, segment/column
  directory, zone-map statistics, and file-level totals.
- **Zone map**: per-column-per-segment minimum and maximum of present values,
  used to prune segments.
- **Checkpoint footer**: a footer written mid-stream by an appending writer to
  bound data loss on crash (Section 11).

# 3. Design Overview

NTCF compresses in two cooperating layers.

1. **Semantic layer.** Operating on typed columns, it removes *structural*
   redundancy that a byte compressor cannot perceive: near-monotonic timestamps
   (delta-of-delta), low-cardinality enumerations (dictionary), repeated values
   (run-length), small-range integers (frame-of-reference bit-packing), and
   general integers (variable-length + ZigZag). An encoder SHOULD trial
   candidate encodings per column chunk and keep the smallest, and MUST always
   include a baseline (Plain or Raw) so the chosen encoding is never larger than
   the baseline.

2. **Entropy layer.** A conventional byte compressor — zstd, lz4, or none —
   applied per column chunk to the semantically-encoded octets.

The two are complementary: the semantic layer maps a repeated IP column to small
dictionary ordinals; the entropy layer removes residual byte-level redundancy.

A file is a fixed header, a sequence of segments (each an opaque concatenation
of column chunks and optional index blobs), and a footer. The footer is read
first for fast open and for predicate pruning. Crash recovery relies on
checkpoint footers and a backward scan (Section 11), NOT on per-segment framing.

# 4. File Structure

```
+----------------------------------------------------------+
| Header (fixed 36 octets, Section 5)                      |
+----------------------------------------------------------+
| Segment 0 | Segment 1 | ... | Segment N-1  (Section 6)   |
|   each segment = chunk | [index] | chunk | [index] | ... |
+----------------------------------------------------------+
| [zero or more intermediate checkpoint footers]           |  (Section 11)
+----------------------------------------------------------+
| Footer body (Section 10)                                 |
| footerLen u32 | CRC32C u32 | trailer magic "NTCF"        |
+----------------------------------------------------------+
```

Column and segment byte locations are recorded as absolute file offsets in the
footer. Intermediate checkpoint footers, if present, are dead bytes that a
conforming reader skips: the authoritative footer is the final one, whose
offsets account for any preceding checkpoint footers.

# 5. Header

The header is exactly 36 octets:

| Field    | Type      | Description |
|----------|-----------|-------------|
| magic    | `bytes[4]`| `0x4E 0x54 0x43 0x46` ("NTCF") |
| version  | `u16`     | format version; this document specifies 1 |
| flags    | `u16`     | reserved; senders MUST set 0, readers MUST ignore unknown bits |
| created  | `u64`     | file creation time, Unix nanoseconds |
| writerID | `bytes[16]`| opaque producer identifier; MAY be zero |
| crc32c   | `u32`     | CRC-32C (Castagnoli) over the preceding 32 octets |

A reader MUST validate `magic`, MUST reject a `version` it does not support
(Section 17), and MUST verify `crc32c` before relying on any other octet.

# 6. Segments and Column Chunks

## 6.1 Segments

A segment is the concatenation of one column chunk per schema column, in schema
column order, with each `Indexed` column's chunk OPTIONALLY followed by its
index blob (Section 9). A segment has no magic or self-contained header; its
extent and the location of every chunk and index within it are given by the
footer's segment directory (Section 10). All chunks in a segment encode the same
number of rows.

## 6.2 Column Chunk

A column chunk is self-validating: it carries its own checksum and the lengths
needed to bound decompression.

| Field           | Type      | Description |
|-----------------|-----------|-------------|
| kind            | `u8`      | 0 = integer domain, 1 = byte domain |
| encodingID      | `u8`      | semantic encoding (Section 7) |
| compressionID   | `u8`      | entropy codec (Section 8) |
| flags           | `u8`      | bit 0 = a presence bitmap follows; other bits reserved (0) |
| rows            | `uvarint` | number of rows |
| uncompressedLen | `uvarint` | length in octets of the semantically-encoded data (pre-entropy) |
| storedLen       | `uvarint` | length in octets of the stored (post-entropy) payload |
| bitmapLen       | `uvarint` | present only if flags bit 0; MUST equal `⌈rows/8⌉` |
| bitmap          | `bytes[bitmapLen]` | present only if flags bit 0 (Section 6.3) |
| checksum        | `u64`     | xxHash64 (64-bit XXH64) over `stored` |
| stored          | `bytes[storedLen]` | entropy-compressed semantic octets |

To decode a chunk a reader MUST: (1) verify `checksum` over `stored`;
(2) enforce the decompression limits of Section 14 against `uncompressedLen` and
the ratio `uncompressedLen/storedLen`; (3) entropy-decode `stored` to exactly
`uncompressedLen` octets; (4) semantic-decode `rows` values; (5) if a presence
bitmap is present, apply it to mark null rows.

## 6.3 Presence Bitmap (Nullability)

When a column contains null (absent) values, the chunk stores a presence bitmap
of `⌈rows/8⌉` octets. Bit `i` (least-significant-bit first within each octet,
i.e. octet `i div 8`, bit `i mod 8`) is set when row `i` is present (non-null).
The encoded value stream contains one value per row; the value at a null row is
a placeholder (zero for integers, empty for bytes) and MUST be ignored by
readers when the presence bit is clear.

> Note: storing a placeholder per null row (rather than only present values) is
> a deliberate simplification of format version 1; placeholders compress well
> under run-length and dictionary encodings. A future version MAY define a
> present-values-only encoding.

# 7. Semantic Encodings

Columns are mapped to one of two physical domains. The integer domain carries
values as `u64`; the byte domain carries variable-length octet strings. The
mapping from logical type to domain is given in Section 13. All integer
encodings are exact over the full `u64` range because their arithmetic is
performed modulo 2^64 identically on encode and decode.

`encodingID` values are stable and assigned as follows:

| ID | Name | Domain | Description |
|----|------|--------|-------------|
| 0  | Plain | int | `u64` little-endian per value (baseline) |
| 1  | Varint | int | `uvarint` per value |
| 2  | Delta | int | `uvarint` first value, then `varint` of each successive difference |
| 3  | DeltaOfDelta | int | `uvarint` first value; `varint` first delta; then `varint` of each change in delta |
| 4  | RLE | int | repeated (`uvarint` value, `uvarint` run-length) pairs |
| 5  | Bitpack | int | `uvarint` min; `u8` width; residuals (value − min) bit-packed at `width` bits (Section 7.1) |
| 6  | DictInt | int | dictionary (Section 7.2), integer keys |
| 64 | Raw | bytes | repeated (`uvarint` length, `bytes`) per value |
| 65 | DictBytes | bytes | dictionary (Section 7.2), octet-string keys |
| 66 | RLEBytes | bytes | repeated (`uvarint` length, `bytes`, `uvarint` run-length) pairs |

A reader MUST reject a chunk whose `encodingID` is unknown for its `kind`.
The number of values produced MUST equal `rows`.

## 7.1 Bit Packing

Bit packing serialises a sequence of unsigned integers using exactly `width`
bits each, least-significant-bit first, with no per-value octet alignment.
`width` is in the range 0..64. A `width` of 0 encodes a sequence of zeros and
occupies no octets. The total size is `⌈(count × width)/8⌉` octets. The
Bitpack (FOR) encoding subtracts a per-chunk minimum before packing; the
dictionary encodings pack ordinal indices at `width = bits(dictLen − 1)`.

## 7.2 Dictionary Encoding

A dictionary chunk has the layout:

- `dictLen` (`uvarint`): number of distinct values.
- value table, in ascending sorted order:
  - DictInt: the first value as `uvarint`, then each subsequent value as the
    `uvarint` non-negative gap from its predecessor.
  - DictBytes: per entry, a `uvarint` length followed by that many octets.
- `width` (`u8`): bits per ordinal = `bits(dictLen − 1)`.
- the per-row ordinals, bit-packed at `width` bits (Section 7.1).

Each ordinal MUST be strictly less than `dictLen`.

# 8. Entropy Compression

The entropy layer is applied to the semantically-encoded octets of a chunk. A
writer SHOULD select `none` when entropy compression would not reduce size.
`compressionID` values:

| ID | Name | Description |
|----|------|-------------|
| 0  | none | stored octets are the semantic octets verbatim |
| 1  | zstd | a single zstd frame (RFC 8478) covering the semantic octets |
| 2  | lz4  | a one-octet selector (0 = raw, 1 = LZ4 block) followed by the payload |

For `compressionID = 2`, selector 0 means the remaining octets are the
uncompressed semantic octets (used when the data is incompressible); selector 1
means the remaining octets form an LZ4 *block* (not an LZ4 frame) that
decompresses to exactly `uncompressedLen` octets. For all codecs, a reader MUST
verify that decompression yields exactly `uncompressedLen` octets and MUST treat
any deviation as corruption.

# 9. Indexes

For each column marked `Indexed`, a writer MAY emit an index blob immediately
after that column's chunk within the segment; its location is recorded in the
footer (`indexOffset`, `indexLength`). An `indexLength` of 0 means no index.

Index blob layout:

| Field | Type | Description |
|-------|------|-------------|
| flags | `u8` | bit 0 = Bloom filter present; bit 1 = inverted index present |
| bloom | …    | present if bit 0 (Section 9.1) |
| inverted | … | present if bit 1 (Section 9.2) |

## 9.1 Bloom Filter

| Field | Type | Description |
|-------|------|-------------|
| k     | `u8` | number of hash probes |
| wordCount | `uvarint` | number of 64-bit words |
| words | `u64 × wordCount` | bit array; bit `b` is word `b div 64`, bit `b mod 64` |

The bit count `m` equals `wordCount × 64`. A value's membership uses double
hashing of its XXH64 digest `h` (integers are hashed as their 8-octet
little-endian form): with `h1 = h` and `h2 = (h >> 33) | (h << 31)` (and
`h2 = 0x9E3779B97F4A7C15` if that value is 0), probe `i` (0 ≤ i < k) addresses
bit `(h1 + i × h2) mod m`. A writer SHOULD size the filter to the column's
distinct cardinality at a target false-positive rate (the reference uses 1%).
A clear probe is a definitive non-membership; a set result is probabilistic.

## 9.2 Inverted Index

| Field | Type | Description |
|-------|------|-------------|
| kind  | `u8` | 0 = integer keys, 1 = byte keys |
| count | `uvarint` | number of distinct keys |
| entries | … | `count` entries, in ascending sorted key order |

Each entry is a key followed by a posting list:

- key: integer keys as `uvarint`; byte keys as `uvarint` length + octets.
- `bitmapLen` (`uvarint`) then `bitmapLen` octets: a Roaring Bitmap
  (per the Roaring Bitmap serialization specification) of the 0-based row
  positions within the segment holding that key.

Inverted indexes are OPTIONAL and, when absent, equality is resolved by zone-map
and Bloom pruning followed by a scan of the decoded column.

# 10. Footer

## 10.1 Schema Descriptor

| Field | Type | Description |
|-------|------|-------------|
| schemaID | `u32` | schema identifier |
| nameLen  | `uvarint` | |
| name     | `bytes[nameLen]` | schema name (UTF-8) |
| version  | `u16` | schema version |
| colCount | `uvarint` | number of columns (≤ 4096) |
| columns  | … | `colCount` column descriptors |

Each column descriptor: `nameLen` (`uvarint`), `name` (octets), `type` (`u8`,
Section 13), `flags` (`u8`: bit 0 = indexed, bit 1 = nullable).

## 10.2 Footer Body

| Field | Type | Description |
|-------|------|-------------|
| schema | descriptor | Section 10.1 |
| sourceLen | `uvarint` | |
| sourceType | `bytes[sourceLen]` | originating source identifier (e.g. "honeypot") |
| totalRows | `u64` | total rows in the file |
| minTS | `u64` | minimum timestamp (Unix ns) over the file; 0 if none |
| maxTS | `u64` | maximum timestamp |
| segCount | `uvarint` | number of segments (≤ 1 048 576) |
| segments | … | `segCount` segment directory entries |

Each **segment directory entry**:

`offset` (`u64`), `length` (`u64`), `rows` (`uvarint`), `minTS` (`u64`),
`maxTS` (`u64`), `colCount` (`uvarint`, MUST equal the schema column count),
then one **column directory entry** per column:

| Field | Type | Description |
|-------|------|-------------|
| chunkOffset | `u64` | absolute file offset of the column chunk |
| chunkLength | `u64` | |
| indexOffset | `u64` | absolute offset of the index blob, or 0 |
| indexLength | `u64` | 0 if no index |
| flags | `u8` | bit 0 = column has nulls in this segment |
| nonNull | `uvarint` | count of non-null values |
| zone-map | … | integer columns: `minInt` (`u64`), `maxInt` (`u64`). byte columns: `minLen` (`uvarint`) + min octets, `maxLen` (`uvarint`) + max octets. The domain is determined from the schema column type. |

## 10.3 Footer Trailer

The footer body is immediately followed by:

`footerLen` (`u32`, the octet length of the footer body), `crc32c` (`u32`,
CRC-32C over the footer body), and the trailer `magic` (`bytes[4]` = "NTCF").

To open a file, a reader reads the final 4 octets and verifies the trailer
magic, reads `footerLen` and `crc32c` from the 8 octets preceding it, slices the
footer body of `footerLen` octets immediately before, verifies the CRC, and
parses the body. A reader MUST enforce `footerLen ≤ 256 MiB` (Section 14) and
MUST verify that the body lies wholly between the header and the trailer.

# 11. Durability and Crash Recovery

A writer that appends records over time (streaming ingestion) SHOULD write a
**checkpoint footer** at intervals. A checkpoint footer is a complete footer
(Section 10) written at the current end of file; it is **appended**, never
overwritten. Because earlier footers are never modified, the most recently
completed footer is always intact even if the process terminates while writing a
subsequent segment.

On read, if the trailing footer is missing or fails validation, a reader MAY
recover by scanning backward from the end of file for an occurrence of the
trailer magic and attempting to parse a footer ending there; the first (latest)
candidate whose `footerLen` and CRC validate is the recovered footer. Records
written after the last checkpoint but before termination are not recoverable;
this is the correct durability boundary. Dead intermediate footers MAY be
reclaimed by an out-of-band compaction step.

# 12. Reading Algorithm (Informative)

1. Validate the header (Section 5).
2. Locate and validate the footer (Section 10.3); on failure, optionally recover
   (Section 11).
3. Parse the schema and the segment/column directory.
4. For a predicate `col OP value`:
   a. Normalise `value` into the column domain (Section 13).
   b. For each segment, consult the column's zone map; if `value` cannot lie in
      `[min, max]` for an equality or the relevant bound for a range, skip the
      segment without reading its body.
   c. For equality on an indexed column, consult the Bloom filter; a clear
      result skips the segment.
   d. If an inverted index is present, take its posting list; otherwise decode
      the single column chunk and scan it.
5. Combine per-segment row sets across predicates (intersection for AND, union
   for OR), then aggregate or project.

`count(*)` with no predicate is answered from `totalRows` with no body read.

# 13. Logical Type System

| ID | Type | Domain | Normalisation |
|----|------|--------|---------------|
| 0 | timestamp | int | Unix nanoseconds since the epoch |
| 1 | ip | bytes | canonical 16-octet form; IPv4 stored as IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so a single column holds both families and lexicographic order is total |
| 2 | uint | int | unsigned 64-bit |
| 3 | port | int | transport port 0..65535 |
| 4 | enum | bytes | low-cardinality octet string (e.g. country code, protocol name, HTTP method) |
| 5 | string | bytes | arbitrary octet string |
| 6 | bool | int | 0 or 1 |

The 16-octet IP normalisation gives correct zone-map ordering within each
address family. Implementations storing both families in one column SHOULD note
that min/max bounds spanning families are looser; this does not affect
correctness, only pruning effectiveness.

# 14. Resource Limits

Because every length and offset in a file is attacker-controlled, a reader MUST
gate every allocation derived from a file-supplied count by a finite ceiling
before allocating, and MUST bound decompression. The reference implementation
enforces (and this document RECOMMENDS) at least:

| Quantity | Ceiling |
|----------|---------|
| columns per schema | 4096 |
| rows per segment | 16 777 216 |
| segments per file | 1 048 576 |
| dictionary entries per chunk | 16 777 216 |
| stored (post-entropy) octets per chunk | 1 GiB |
| uncompressed octets per chunk | 4 GiB |
| decompression expansion ratio | 256:1 |
| footer body | 256 MiB |
| a single byte-domain value | 16 MiB |

A reader MUST reject `count × width` computations that would overflow, and MUST
reject any offset/length pair that falls outside the file.

# 15. Security Considerations

NTCF files frequently originate from untrusted parties (partner feeds, tenant
sensors, attacker probes). Conforming readers MUST treat all input as hostile:

- **No panics / unbounded work.** For any input octets, a decoder MUST return a
  value or an error; it MUST NOT crash, allocate without bound, read out of
  bounds, or loop indefinitely. The reference implementation enforces this with
  fuzz testing across the header/footer parser, every encoding decoder, the
  entropy layer, the index parser, and the query parser.
- **Decompression bombs.** A reader MUST enforce both an absolute uncompressed
  ceiling and an expansion-ratio cap (Section 14) before and during entropy
  decoding, and MUST verify the decompressed length equals the declared length.
- **Integrity, not authenticity.** The CRC-32C (header/footer) and XXH64 (chunk)
  checksums detect accidental corruption only; they are NOT message
  authentication codes. An adversary with write access can forge a
  valid-looking file. Format version 1 provides **no** confidentiality and
  **no** authenticity. Consumers requiring those properties MUST layer an
  authenticated/encrypted transport or storage mechanism beneath NTCF. An
  authenticated container is a candidate for a future version.
- **Resource exhaustion.** The limits of Section 14 bound memory and CPU per
  file; operators ingesting many files SHOULD additionally bound concurrency.

# 16. IANA Considerations

This document requests registration of the following media type and file
extension.

Media type registration (per RFC 6838):

- Type name: application
- Subtype name: vnd.ntcf
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary
- Magic number(s): the four octets `0x4E 0x54 0x43 0x46` ("NTCF") at offset 0,
  and the same four octets as the final four octets of a complete file.
- File extension(s): .ntcf
- Security considerations: see Section 15 of this document.
- Interoperability considerations: the format is versioned (Section 17).
- Published specification: this document.
- Intended usage: COMMON
- Change controller: The NTCF Authors.

If a registry of NTCF `encodingID`, `compressionID`, or logical `type` values is
desired, this document suggests an "NTCF Encodings" registry with the initial
assignments in Sections 7, 8, and 13, using a "Specification Required" policy.

# 17. Versioning and Interoperability

The header `version` field gates on-disk compatibility. A reader MUST refuse a
file whose `version` it does not implement. Within a supported version, a reader
MUST reject unknown `encodingID`, `compressionID`, and logical `type` values
rather than guess. Additive changes that do not alter the byte layout of
existing structures (for example, a new encoding identifier) MAY be made within
a version only if existing readers can still reject the new identifier safely;
otherwise the version MUST be incremented.

# 18. References

## 18.1 Normative References

- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key
  Words", BCP 14, RFC 8174.
- [RFC8478] Collet, Y. and M. Kucherawy, "Zstandard Compression and the
  application/zstd Media Type", RFC 8478.
- [RFC6838] Freed, N., Klensin, J., and T. Hansen, "Media Type Specifications
  and Registration Procedures", BCP 13, RFC 6838.

## 18.2 Informative References

- [ROARING] Chambi, S., Lemire, D., Kaser, O., Godin, R., "Better bitmap
  performance with Roaring bitmaps", Software: Practice and Experience.
- [LZ4] Collet, Y., "LZ4 Block Format Description".
- [PARQUET] Apache Parquet file format.

---

# Appendix A. Worked Example (Informative)

A minimal file containing one segment of three rows over the columns
`timestamp` (timestamp), `srcip` (ip, indexed), `country` (enum, indexed,
nullable) is laid out as:

```
[Header: "NTCF", version=1, flags=0, created, writerID, crc32c]   (36 octets)
[Segment 0]
  [chunk: timestamp]   kind=0 enc=DeltaOfDelta comp=zstd ... checksum, stored
  [chunk: srcip]       kind=1 enc=DictBytes    comp=zstd ... checksum, stored
  [index: srcip]       flags=0b01 (bloom only): k, wordCount, words
  [chunk: country]     kind=1 enc=DictBytes    comp=none flags=0b1 (nulls)
                       bitmap=[present bits], checksum, stored
  [index: country]     flags=0b01: bloom
[Footer body]
  schema{id, "demo", v1, 3 columns...}
  sourceType="demo", totalRows=3, minTS, maxTS, segCount=1
  segment0{offset=36, length, rows=3, minTS, maxTS, colCount=3,
           col0{chunkOffset,chunkLength,0,0, flags=0,nonNull=3, minInt,maxInt}
           col1{chunkOffset,chunkLength,indexOffset,indexLength, ... min/max bytes}
           col2{chunkOffset,chunkLength,indexOffset,indexLength, flags=1,nonNull=2, min/max bytes}}
[footerLen u32][crc32c u32]["NTCF"]
```

# Appendix B. Reference Implementation and Test Vectors (Informative)

A complete, Apache-2.0-licensed reference implementation in Go accompanies this
specification. It includes round-trip and fuzz tests for every encoding, the
chunk/footer framing, the index blobs, and the query parser, and a benchmark
harness. Measured compression ratios on synthetic but realistically-skewed
telemetry (flow, honeypot, and web-access) exceed those of gzip, zstd, lz4, and
xz on the same inputs while preserving in-place search; these results are
reproducible from the implementation and are illustrative rather than a
conformance requirement. Production deployments SHOULD validate ratios on their
own representative data.
