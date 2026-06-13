# NTCF Compression

NTCF compresses in two layers: a **semantic** layer that exploits the structure
of typed telemetry columns, and an **entropy** layer that mops up residual
byte-level redundancy. This document explains each codec, how the encoder
chooses among them, and why we use zstd/lz4 rather than a bespoke entropy coder.

## 1. Why two layers

A byte compressor sees `"203.0.113.5","203.0.113.5","203.0.113.6"…` as text and
models it statistically. NTCF first maps that column to dictionary ordinals
`0,0,1,…` (often 1–2 bits each after bit-packing), *then* lets zstd compress the
residual. The semantic layer removes redundancy the byte compressor structurally
cannot (e.g. that timestamps increase by ~constant deltas, or that a port column
is drawn from a tiny set). The result beats single-layer xz on real telemetry.

## 2. Semantic codecs (`internal/encoding`)

Columns are normalized to one of two domains: **integer** (`[]uint64`: IPs are
the exception — they are bytes) or **bytes** (`[][]byte`).

### Integer codecs

| Codec | Best for | How |
|-------|----------|-----|
| **plain** | incompressible | 8-byte LE per value (baseline) |
| **varint** | small magnitudes | LEB128 per value |
| **delta** | counters, near-sorted | first value + zigzag-varint successive deltas |
| **delta-of-delta** | timestamps | first value, first delta, then zigzag-varint of the change in delta — near-monotonic clocks collapse to a few bytes |
| **RLE** | long runs (repeated ports/ASNs) | (value, run-length) pairs |
| **bit-pack (FOR)** | bounded range (ports, status, country ids) | subtract per-chunk min, pack residuals at ⌈log₂(max−min+1)⌉ bits |
| **dictionary** | low cardinality (enums, ASN, repeated IPs) | sorted distinct table (delta-varint) + bit-packed ordinals |

### Byte codecs

| Codec | Best for | How |
|-------|----------|-----|
| **raw** | high-cardinality text (URLs, UAs) | (len, bytes) per value; entropy layer handles it |
| **dictionary** | enums, methods, countries, repeated IPs | value table + bit-packed ordinals |
| **RLE** | long runs | (value, run-length) pairs |

All integer codecs round-trip the **entire `uint64` range** exactly because the
delta/FOR arithmetic is performed modulo 2⁶⁴ identically on encode and decode —
verified by `FuzzRoundTripInts`.

## 3. Codec selection

The encoder is **trial-based**: for each column chunk it materializes a small set
of candidate encodings (steered by cheap statistics — cardinality, monotonicity,
run structure, value range) and keeps the one with the smallest pre-entropy
output. `plain`/`raw` are always candidates, so the chosen codec is never worse
than the baseline. This avoids brittle per-column heuristics while staying cheap
because segment sizes are bounded.

The selection minimizes pre-entropy size, which is a strong proxy for, but not
identical to, post-entropy size. Selecting by post-zstd size is a possible future
refinement (it roughly doubles encode cost); v1 takes the cheaper proxy.

## 4. Entropy layer (`internal/compress`)

After semantic encoding, each chunk is optionally compressed with **zstd**
(default, level 3), **lz4** (fastest), or **none**. The writer keeps entropy
compression only if it actually shrinks the chunk; otherwise the chunk stores the
semantic bytes verbatim with `compression=none`. Both codecs are **pure Go**
(klauspost/compress, pierrec/lz4), so the build needs no cgo.

### Why not a custom Huffman / arithmetic / range coder?

We evaluated hand-rolling an entropy stage:

- **Huffman** — simple, fast, but byte-granular and inferior to arithmetic/ANS on
  skewed distributions.
- **Arithmetic / range coding** — near-optimal, but slow and patent-historically
  fraught; a correct, fast, fuzz-hardened implementation is a multi-month effort.
- **ANS / FSE** — the modern sweet spot… and exactly what zstd already implements
  internally, tuned and battle-tested.

**Decision:** the marginal ratio gain from a bespoke coder over zstd is small and
workload-dependent, while the correctness and fuzzing burden is large. The
telemetry-specific value lives in the *semantic* layer, which NTCF owns. A custom
entropy coder remains documented research, not v1 production code.

## 5. Measured results

`ntcf bench`, 200k records, NTCF = semantic + zstd-3:

| Source | NTCF | gzip-6 | zstd-3 | lz4 | xz |
|--------|------|--------|--------|-----|-----|
| honeypot | **22.0×** | 9.9× | 9.0× | 5.6× | 14.0× |
| generic-flow | **13.9×** | 7.0× | 6.6× | 4.2× | 9.7× |
| web-access | **27.5×** | 10.6× | 10.1× | 6.1× | 14.4× |

Two honest caveats:

1. The NTCF size **includes its search indexes** (zone maps + Bloom filters). The
   other formats are inert — to search them you must store a separate index and
   decompress. NTCF still wins on ratio while being directly queryable.
2. On a column that is genuinely high-entropy free text and *dominates* a
   dataset, xz's larger window can win on that portion; NTCF then relies on its
   entropy layer for that column while still winning overall via the structured
   columns. We report where this happens rather than hiding it.

Bloom filters are sized to a column's **distinct** cardinality (not its row
count), which is the single biggest lever on index overhead and was the
difference between NTCF trailing and beating xz.
