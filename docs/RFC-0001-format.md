# RFC-0001: The NTCF Container Format and Compression Model

- **Status:** Accepted (v0.1)
- **Format version:** 1
- **Authors:** NTCF maintainers

This RFC records the design of NTCF, the assumptions it challenges, the
alternatives considered, and the trade-offs accepted. It is the document a
reviewer should read first.

## 1. Problem statement

Security and network telemetry is high-volume, highly repetitive, and almost
always queried by a handful of dimensions (IP, ASN, country, port, event type,
time). Operators store petabytes of it and pay twice: once for storage, and
again in time whenever they must decompress whole archives to answer a single
question during an incident.

General compressors (gzip/zstd/lz4/xz) reduce the storage bill but leave the
data inert. Columnar analytics formats (Parquet/ORC) make it queryable but are
not tuned for telemetry semantics (IP/ASN/CIDR), telemetry-grade pruning, or
crash-safe streaming append from a sensor.

**Goal:** a format that is simultaneously (a) smaller than xz on real telemetry,
(b) searchable and analyzable without full decompression, and (c) safe to append
to continuously from a crashing-prone edge sensor.

## 2. Design thesis: compress *meaning*, in two layers

NTCF separates compression into two cooperating layers:

1. **Semantic layer** (`internal/encoding`). Operating on typed columns, it
   removes *structural* redundancy a byte compressor cannot perceive: monotonic
   timestamps (delta-of-delta), low-cardinality enums (dictionary), repeated
   values (RLE), small-range integers (frame-of-reference bit-packing), and
   general integers (varint+zigzag). The encoder trials candidate codecs per
   column chunk and keeps the smallest output, so it is never worse than varint.

2. **Entropy layer** (`internal/compress`). A conventional byte compressor —
   zstd (default), lz4, or none — mops up residual entropy in the
   semantically-encoded bytes.

The two are complementary: the semantic layer turns "203.0.113.5,203.0.113.5,…"
into tiny dictionary ordinals; the entropy layer then crushes whatever pattern
remains. Measured ratios exceed standalone xz (see benchmarks).

### 2.1 Why not hand-roll an entropy coder?

We evaluated implementing Huffman / arithmetic / range coding on the hot path
(see [Compression.md](Compression.md)). Decision: **rely on zstd/lz4** for the
entropy layer in v1. zstd already contains a tuned FSE/Huffman entropy stage;
re-implementing one would add a large correctness and fuzzing burden for a
marginal, workload-dependent gain. The semantic layer is where telemetry-specific
value lives, so that is what we own. Custom entropy coding remains documented
research, not production code.

## 3. Assumptions challenged & alternatives weighed

### 3.1 Reuse Parquet/ORC instead of a new format?
**Rejected for v1.** Parquet's type system has no first-class IP/ASN notion, its
ecosystem assumes batch analytics rather than crash-safe sensor append, and its
pruning is not tuned for IP-range zone maps. We keep interop on the roadmap
(Arrow/Parquet export) but own the on-disk layout. *Trade-off:* we forgo
Parquet's tooling ecosystem to gain telemetry-native indexing and streaming.

### 3.2 Footer-at-end (Parquet) vs. self-describing segments
**Chosen: both.** Each segment carries enough metadata to be decoded on its own,
and the footer is a roll-up directory for fast open and pruning. Crash recovery
(§4) exploits the self-describing segments + checkpoint footers. *Trade-off:*
modest metadata duplication for durability — correct for streaming ingest.

### 3.3 Per-segment vs. global dictionaries
**Per-segment by default.** Bounds writer memory, enables independent/parallel
segment encoding, and keeps each segment self-contained. *Trade-off:* we forgo
cross-segment dictionary sharing (a roadmap optimization for ultra-low-cardinality
columns).

### 3.4 IP representation: integer vs. fixed 16-byte bytes
**Chosen: normalize every address to a 16-byte form** (IPv4 as v4-in-v6). One
column holds both families; lexicographic order is correct for zone maps; heavy
IP repetition collapses under dictionary encoding. *Trade-off:* delta-coding of
sequential IPv4 scans is not exploited in v1 (roadmap); dictionary + entropy
already handle real-world repetition well.

### 3.5 Inverted index always vs. opt-in
**Opt-in.** For dictionary-encoded columns the posting lists are reconstructable
from the column itself, so storing a separate Roaring inverted index largely
duplicates data. By default NTCF writes only Bloom filters + zone maps (sized to
*distinct* cardinality, not row count) and resolves equality by pruning then
scanning a single decoded column. Inverted indexes are available via a flag for
point-lookup-heavy workloads. *Trade-off:* a scan of one column in surviving
segments vs. larger files — the default favors size.

### 3.6 Bitmap library
**Depend on `RoaringBitmap/roaring`** rather than hand-rolling compressed
bitmaps. Battle-tested correctness beats reinvention; it is the only
non-trivial data-structure dependency.

## 4. Durability & crash recovery

The streaming writer appends an **intermediate footer** at a configurable
interval (`Checkpoint`). Footers are *appended*, never overwritten, so the most
recent fully-flushed footer is always intact even if the process dies
mid-segment. On read, a missing/corrupt trailing footer triggers a backward scan
(`RecoverFooter`) for the last valid checkpoint footer. Records written after
the last checkpoint but before the crash are not recovered — the correct
durability boundary. Dead intermediate footers are reclaimed by a future
compaction pass (roadmap).

## 5. Safety

Every length and offset on disk is attacker-controlled, so every allocation
derived from one is gated by a hard limit, every read is bounds-checked through a
single cursor type, and decompression is bounded by both an absolute ceiling and
an expansion-ratio cap. Checksums (xxHash64 for chunk payloads, CRC32C for
header/footer) detect corruption. Decoders must never panic on hostile input —
enforced by fuzz targets across the format, every codec, and the query parser.
See [Security.md](Security.md).

## 6. Identified weaknesses (tracked)

- High-cardinality free text (URLs, user-agents) compresses only as well as the
  entropy layer allows; tokenization/FSST is roadmap.
- No cross-file catalog/manifest yet; a query spans one file. A
  VictoriaMetrics-style catalog is roadmap.
- The query engine is a deliberate SQL *subset*; joins, GROUP BY, and arbitrary
  expressions are roadmap.
- Whole-file in-memory reader; memory-mapped / partial-IO reading is roadmap for
  very large files.

## 7. Non-goals (v1)

Cryptographic authentication of files (only integrity checksums today),
distributed query, and a storage daemon are out of scope for v1.
