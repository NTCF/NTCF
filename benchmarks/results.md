# NTCF Benchmark Results

All numbers are reproducible from this repository. They use **synthetic but
realistically-skewed** telemetry from `internal/datagen` (a small set of noisy
source IPs/ASNs dominate, ports cluster on common services, most honeypot events
are failed logins) — the skew real telemetry exhibits and that NTCF's encodings
exploit. Uniform-random data would understate real-world ratios.

> Hardware/build vary; treat absolute timings as indicative and ratios as the
> stable, comparable metric. Regenerate on your machine before quoting numbers.

## 1. Compression ratio vs. general compressors

Command: `ntcf bench --source <s> --count 200000`. NTCF = semantic columnar +
zstd level 3. Ratio = raw input bytes ÷ output bytes (NTCF output **includes its
search indexes**).

| Source        | Raw      | **NTCF**  | gzip-6 | zstd-3 | lz4   | xz     |
|---------------|----------|-----------|--------|--------|-------|--------|
| honeypot      | 39.5 MiB | **22.0×** | 9.9×   | 9.0×   | 5.6×  | 14.0×  |
| generic-flow  | 40.8 MiB | **13.9×** | 7.0×   | 6.6×   | 4.2×  | 9.7×   |
| web-access    | 25.0 MiB | **27.5×** | 10.6×  | 10.1×  | 6.1×  | 14.4×  |

NTCF beats even xz on ratio across all three sources while remaining directly
searchable — the other formats must be fully decompressed (and separately
indexed) to answer a query.

### Why NTCF wins
- The semantic layer discards JSON/CLF structure entirely and reduces enums, IPs,
  ASNs, ports to dictionary ordinals and bit-packed integers; timestamps collapse
  under delta-of-delta. The entropy layer then compresses the small residual.
- Bloom filters are sized to each column's **distinct** cardinality, keeping index
  overhead small.

### Honest caveats
- The NTCF size includes zone maps + Bloom filters; competitors are inert.
- On a dataset dominated by genuinely high-entropy free text, xz's large window
  can win on that column; NTCF still wins overall via the structured columns.

## 2. Pack throughput, query & search latency

Command: `go test ./benchmarks/ -bench=. -benchmem`. 100,000 records,
single goroutine (parse + semantic encode + zstd + index build).

| Benchmark | Result (indicative) | Notes |
|-----------|---------------------|-------|
| `BenchmarkPack/honeypot`     | ~20 MB/s | JSON (map) decode dominates allocations |
| `BenchmarkPack/generic-flow` | ~20 MB/s | |
| `BenchmarkPack/web-access`   | ~35 MB/s | CLF text parse is lighter than JSON |
| `BenchmarkQueryCount`        | ~4.8 ms  | `count(*) WHERE country='CN'` over 100k rows |
| `BenchmarkSearchIP`          | ~16 ms   | `search port 22`, materializing up to 100 rows |

Pack throughput is single-threaded and bounded largely by the adapter's JSON
decode; struct-based decoding and parallel segment encoding are roadmap
performance items. Query/search latencies are for a single in-memory file;
`count(*)` with no predicate is answered from the footer in microseconds.

## 3. Reproducing

```bash
# Ratio table (per source)
make bench
# or:  ./ntcf bench --source honeypot --count 200000

# Go micro-benchmarks
go test ./benchmarks/ -bench=. -benchmem

# End-to-end with your own data
./ntcf pack --source honeypot -o out.ntcf your-honeypot.jsonl
./ntcf info out.ntcf
```

`xz` is compared only if the `xz` binary is on `PATH`; otherwise it is omitted.
