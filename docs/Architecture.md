# NTCF Architecture

This document describes the components of NTCF and how data flows through them.
It complements [FileFormat.md](FileFormat.md) (on-disk bytes),
[Compression.md](Compression.md) (codecs), and [QueryEngine.md](QueryEngine.md)
(search/analytics).

## Layered design

```
                    ┌──────────────────────────────────────────────┐
  cmd/ntcf (CLI)    │  pack · info · search · query · ingest · gen  │
                    └───────────────┬──────────────────────────────┘
                                    │ depends on
                    ┌───────────────▼──────────────────────────────┐
  pkg/ntcf (public) │  Writer · Reader · Schema · Query · Search    │  STABLE API
                    └───────────────┬──────────────────────────────┘
                                    │
   internal/ingest ──────────┐      │      ┌────────── internal/query
   (streaming, tail, recover)│      │      │ (lex · parse · plan · exec)
                             ▼      ▼      ▼
                    ┌──────────────────────────────────────────────┐
   internal/store   │  file image → header/footer → column chunks  │
                    └───────────────┬──────────────────────────────┘
        ┌───────────────┬───────────┼────────────┬─────────────────┐
   internal/format  internal/column internal/index internal/schema  internal/adapter
   (framing)        (chunk model)   (bloom/bitmap) (types/registry)  (source decoders)
        └───────────────┴───────────┼────────────┴─────────────────┘
                                     ▼
              internal/encoding (semantic codecs) · internal/compress (zstd/lz4)
                                     ▼
                              internal/util (cursor, varint, hashing, limits)
```

The dependency direction is strictly downward. `internal/` is import-private:
only this module can use it, which lets the engine evolve while `pkg/ntcf` stays
a stable surface for SIEM vendors and other embedders.

## Package responsibilities

| Package | Responsibility |
|---------|----------------|
| `internal/util` | Bounds-checked binary `Cursor`, varint/zigzag, xxHash64/CRC32C, hard resource limits, typed errors, IP normalization. The safety floor. |
| `internal/encoding` | Semantic column codecs (plain, varint, delta, delta-of-delta, RLE, bit-pack/FOR, dictionary) for integer and byte columns, plus the size-minimizing codec selector. |
| `internal/compress` | Entropy layer: `none`, `zstd`, `lz4` behind one `Codec` interface, with decompression-bomb guards. |
| `internal/column` | In-memory column vector + null bitmap, summary `Stats`, and the self-describing **column chunk** framing (checksum + bomb guard). |
| `internal/index` | Bloom filters (sized to distinct cardinality), Roaring inverted indexes, and the combined per-column index blob. |
| `internal/schema` | Logical types, `Column`/`Schema`, validation, and the footer schema descriptor. |
| `internal/format` | File header, footer (schema + segment/column directory + stats), and backward-scanning crash recovery. |
| `internal/store` | The low-level read engine: parse header/footer, bounds-checked access to chunks and indexes. |
| `internal/adapter` | Source decoders (`generic-flow`, `honeypot`, `web-access`) + registry; the extension point for new sources. |
| `internal/query` | SQL-subset lexer, parser, and executor with predicate pushdown and aggregations; the `Search` helper. |
| `internal/ingest` | Streaming pipeline, context cancellation, periodic checkpointing, and the `tail -f` follower. |
| `internal/datagen` | Deterministic synthetic telemetry for demos and benchmarks. |
| `pkg/ntcf` | Public `Writer`, `Reader`, `Schema`, `Query`, `Search`. |
| `pkg/version` | Software and on-disk format version constants. |

## Write path

1. An **adapter** decodes a raw line (JSON or CLF) into a neutral `Record` —
   one `Value` per schema column.
2. `Writer.Append` distributes each value into a per-column **builder**
   (integer or byte domain), recording nulls in a lazily-allocated presence
   bitmap.
3. When a segment fills (`SegmentRows`), `flushSegment` runs. For each column it:
   - computes zone-map `Stats` (min/max over present values);
   - builds indexes for `Indexed` columns (always a right-sized Bloom filter;
     optionally a Roaring inverted index);
   - encodes the column via the **semantic selector**, then the **entropy
     codec**, keeping entropy compression only if it shrinks the payload;
   - writes the column chunk and any index blob, recording absolute offsets in
     the segment/column directory.
4. `Close` (and periodic `Checkpoint`) writes the **footer**: schema descriptor,
   segment directory with zone-map stats, and file-level totals.

A single goroutine owns the writer; there is no shared mutable state on the hot
path, so the design is race-free by construction.

## Read path

1. `store.New` parses and validates the header (magic, version, CRC) and footer
   (length, CRC, schema, directory). `store.Recover` falls back to scanning for
   the last valid checkpoint footer if the trailer is missing/corrupt.
2. A query or search consults footer **zone maps** and per-column **Bloom
   filters** to prune segments that cannot match — without reading their bodies.
3. Surviving segments have only the **needed columns** decoded: chunk checksum
   verified, decompression-bomb limits enforced, entropy layer undone, semantic
   codec reversed, nulls reapplied.
4. Predicates combine per-segment row bitmaps (AND/OR via Roaring); aggregations
   and projections operate over the matched rows.

## Concurrency & context

The writer is single-threaded by contract. The ingestion pipeline is
context-cancellable and applies natural backpressure (synchronous read→encode).
Decoding is independent per chunk and is safe to parallelize across segments
(the engine does this conservatively today; broader parallelism is a roadmap
performance item).
