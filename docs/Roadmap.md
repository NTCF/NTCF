# NTCF Roadmap

NTCF v0.1 ships a complete, tested core: the `.ntcf` format, semantic + entropy
compression, zone-map/Bloom/inverted indexes, a SQL-subset query engine,
crash-recoverable streaming ingestion, and three source adapters. This roadmap
tracks the path from that core to the full "Parquet for telemetry" vision. Items
are grouped, not strictly time-ordered.

## Near term (v0.2 – v0.3)

**More source adapters** (each is an `internal/adapter`, not a format change):
- Suricata `eve.json` and Zeek logs (streaming JSON / TSV)
- Syslog (RFC 3164 / 5424), journald, Windows Event Log
- NetFlow v5/v9, IPFIX, sFlow (binary flow records)
- IIS W3C extended logs; HAProxy
- DNS query logs (Bind/PowerDNS/Unbound)
- BGP updates, RTBH, FlowSpec; threat-intel feeds (STIX/MISP)

**Query engine**
- Aggregates: `sum`, `avg`, `min`, `max`, `count(distinct)`
- `GROUP BY`, `ORDER BY`, `HAVING`, `LIMIT`/`OFFSET`
- Range indexes so `<`/`>`/`BETWEEN` use a sorted structure rather than a scan
- `CIDR` / subnet predicates (`srcip IN 45.0.0.0/8`)

**Format & performance**
- Memory-mapped / partial-IO reader for files larger than RAM
- Parallel segment decode for large scans
- Optional segment sort (`--sort`) to boost zone-map and delta effectiveness
- Compaction pass to reclaim dead checkpoint footers

## Mid term (v0.4 – v0.6)

- **Multi-file catalog / manifest** (VictoriaMetrics-style) so a query spans many
  `.ntcf` files with global time/zone pruning.
- **FSST / tokenized string compression** for high-cardinality URL and
  user-agent columns.
- **Cross-segment & file-level shared dictionaries** for ultra-low-cardinality
  columns.
- **Arrow / Parquet export** for interop with the broader analytics ecosystem.
- **Schema evolution**: add/rename columns across file versions.

## Longer term (v1.0 and beyond)

- **Authenticated containers**: signed footers / AEAD so integrity is a security
  boundary, not just corruption detection (see [Security.md](Security.md)).
- **Encryption at rest** with per-column keys.
- **Pushdown query service / daemon** with a network API and RBAC.
- **Distributed query** across a fleet of catalogs.
- **Language bindings** (C ABI, Python, Rust) over the format.
- **Retention & tiering** (hot/warm/cold) hooks for object storage.

## Stability commitments

- The on-disk format is versioned. Before v1.0 it may change with a
  format-version bump; readers always refuse versions they don't understand.
- `pkg/ntcf` is the stable API surface. `internal/` may change at any time.
- Each new codec, logical type, or index gets a stable on-disk identifier and is
  added without breaking existing files where possible.

Have a source or feature you need? Open an issue — adapters and query features
are the most common and most welcome contributions.
