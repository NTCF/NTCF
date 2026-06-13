# NTCF — Network & Telemetry Compression Format

> **Parquet for cybersecurity telemetry.** NTCF doesn't compress text — it
> compresses *meaning*. It understands IPs, ASNs, ports, countries, event types
> and timestamps, stores them in a columnar binary format with semantic
> encodings, and keeps the result **searchable and queryable without full
> decompression**.

[![Go Reference](https://pkg.go.dev/badge/github.com/ntcf/ntcf.svg)](https://pkg.go.dev/github.com/ntcf/ntcf)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](https://go.dev/dl/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Why NTCF?

General-purpose compressors (gzip, zstd, lz4, xz) treat a log file as an opaque
byte stream. They squeeze textual redundancy well, but the result is **inert**:
to find one IP address you must decompress everything, and you get no analytics.

NTCF takes the database approach. It parses telemetry into a typed, columnar
layout and applies **semantic encodings** — delta-of-delta timestamps,
dictionary-encoded enums, bit-packed ports, RLE'd repeats — *before* a final
entropy pass (zstd/lz4). Because data is columnar and indexed, NTCF can prune
whole segments with zone maps and Bloom filters and answer queries by touching
only the columns and segments that matter.

The payoff (see [Benchmarks](#benchmarks)): **higher compression than xz** while
remaining **instantly searchable**.

## Highlights

- **Columnar `.ntcf` container** with a self-describing, checksummed, versioned
  binary format and crash-recoverable streaming append.
- **Two-layer compression**: semantic column codecs (dictionary, delta,
  delta-of-delta, RLE, bit-packing / frame-of-reference, varint+zigzag) followed
  by a pluggable entropy layer (zstd, lz4, none) — all **pure Go, no cgo**.
- **Search without decompression** via zone maps (min/max), Bloom filters, and
  optional Roaring bitmap inverted indexes.
- **SQL-subset query engine** with predicate pushdown: `count(*)`, `top(col)`,
  projections, `WHERE` with `=, !=, <, >, IN, AND, OR`.
- **Streaming ingestion** from `tail -f`, `journalctl -f`, Suricata `eve.json`,
  honeypot feeds — context-cancellable with periodic crash-recovery checkpoints.
- **Pluggable source adapters**: `generic-flow`, `honeypot`, `web-access` ship
  today; new sources are a small adapter, not a format change.
- Built for **ISPs, MSSPs, SOCs, CSIRTs/CERTs, threat-intel platforms, honeypot
  operators, SIEM vendors, and cloud providers**.

## Install

```bash
go install github.com/ntcf/ntcf/cmd/ntcf@latest
# or build from source
git clone https://github.com/ntcf/ntcf && cd ntcf && make build
```

Requires Go 1.25+. The build is pure Go (no cgo); `CGO_ENABLED=0` works.

## Quickstart

```bash
# 1. Generate (or bring your own) telemetry
ntcf gen --source honeypot --count 200000 --seed 1 -o honeypot.jsonl

# 2. Pack it into a compressed, indexed .ntcf file
ntcf pack --source honeypot -o honeypot.ntcf honeypot.jsonl
#   packed 200000 records ... ratio: 22.0x

# 3. Inspect
ntcf info honeypot.ntcf

# 4. Search — segments that can't match are pruned, not decompressed
ntcf search ip 45.61.0.7 honeypot.ntcf
ntcf search country TR honeypot.ntcf
ntcf search port 22 honeypot.ntcf

# 5. Analytics
ntcf query "SELECT count(*) FROM events WHERE country='CN'" honeypot.ntcf
ntcf query "SELECT top(username, 10) FROM events" honeypot.ntcf
ntcf query "SELECT top(asn) FROM events WHERE dstport=22" honeypot.ntcf

# 6. Stream ingestion (crash-recoverable)
tail -F /var/log/suricata/eve.json | ntcf ingest --source generic-flow -o live.ntcf
```

## Benchmarks

Synthetic but realistically-skewed data (`ntcf bench`), 200,000 records,
NTCF = semantic columnar + zstd-3. Compression ratio = raw input ÷ output.

| Source        | Raw     | **NTCF** | gzip-6 | zstd-3 | lz4   | xz    |
|---------------|---------|----------|--------|--------|-------|-------|
| honeypot      | 39.5 MiB| **22.0×**| 9.9×   | 9.0×   | 5.6×  | 14.0× |
| generic-flow  | 40.8 MiB| **13.9×**| 7.0×   | 6.6×   | 4.2×  | 9.7×  |
| web-access    | 25.0 MiB| **27.5×**| 10.6×  | 10.1×  | 6.1×  | 14.4× |

NTCF beats even xz on ratio **and**, unlike all of them, the `.ntcf` file is
directly searchable: `SELECT count(*)` returns in well under a millisecond
without decompressing the payload. The NTCF size *includes* its search indexes.
Reproduce with `ntcf bench --source <name> --count <n>`; see
[benchmarks/results.md](benchmarks/results.md) for methodology and caveats.

## Use as a library

```go
import "github.com/ntcf/ntcf/pkg/ntcf"

sch := &ntcf.Schema{Name: "events", Version: 1, Columns: []ntcf.Column{
    {Name: "timestamp", Type: ntcf.TypeTimestamp},
    {Name: "srcip", Type: ntcf.TypeIP, Indexed: true},
    {Name: "country", Type: ntcf.TypeEnum, Indexed: true, Nullable: true},
}}

w, _ := ntcf.NewWriter(file, sch, ntcf.DefaultWriterOptions())
_ = w.Append(ntcf.Record{ntcf.IntVal(ts), ntcf.BytesVal(ip16), ntcf.BytesVal([]byte("TR"))})
_ = w.Close()

r, _ := ntcf.Open("events.ntcf")
res, _ := r.Query("SELECT count(*) FROM events WHERE country='TR'")
fmt.Println(res.Count)
```

See [examples/](examples/) for runnable programs.

## Architecture at a glance

```
 raw telemetry ─▶ adapter ─▶ Writer ─▶ column builders ─▶ semantic codec ─▶ entropy codec ─▶ segment
                                                            (dict/delta/RLE/    (zstd/lz4/none)
                                                             bitpack/varint)
                                            └▶ indexes (zone map + bloom [+ inverted]) ─▶ footer
```

A file is a header, a sequence of self-describing segments (row groups, columnar
inside), and a footer holding the schema, the segment/column directory, zone-map
statistics, and file-level metadata. Full details:

- [docs/Architecture.md](docs/Architecture.md) — components and data flow
- [docs/FileFormat.md](docs/FileFormat.md) — exact on-disk byte layout
- [docs/Compression.md](docs/Compression.md) — encodings, selection, entropy research
- [docs/QueryEngine.md](docs/QueryEngine.md) — indexes, planning, execution
- [docs/Security.md](docs/Security.md) — threat model and hardening
- [docs/RFC-0001-format.md](docs/RFC-0001-format.md) — the design RFC
- [docs/Roadmap.md](docs/Roadmap.md) — what's next

## Supported sources

Shipping adapters: **generic-flow** (the backbone schema), **honeypot**
(SSH/RDP/Telnet/SMTP/…), **web-access** (Apache/nginx Common & Combined Log
Format). The architecture targets NetFlow/IPFIX/sFlow, Suricata/Zeek, Syslog,
journald, Windows Event Log, BGP/RTBH/FlowSpec, DNS, and threat-intel feeds —
each as an additional adapter. See [docs/Roadmap.md](docs/Roadmap.md).

## Project layout

| Path           | Purpose |
|----------------|---------|
| `cmd/ntcf/`    | CLI: `pack`, `info`, `search`, `query`, `ingest`, `gen`, `bench` |
| `pkg/ntcf/`    | Stable public API (`Writer`, `Reader`, `Schema`) for embedders |
| `internal/`    | Engine internals (free to evolve; not importable externally) |
| `docs/`        | RFC and design documentation |
| `examples/`    | Runnable usage examples |
| `benchmarks/`  | Benchmark harness and results |
| `schemas/`     | JSON exports of the reference schemas |

## Status

NTCF is at **v0.1** — a complete, tested core (format, codecs, indexes, query
engine, streaming ingest, CLI) with a documented roadmap toward the full vision.
The on-disk format is versioned; pre-1.0 it may change with a format-version
bump. Not yet recommended as a system of record without your own validation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
