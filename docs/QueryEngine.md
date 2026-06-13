# NTCF Query & Search Engine

NTCF answers searches and analytics directly against compressed files, touching
only the columns and segments that can possibly matter. This document covers the
indexes, the supported query grammar, and how a query executes.

## 1. Indexes

Three mechanisms, increasingly precise:

1. **Zone maps (min/max).** Stored per column per segment in the footer. A
   predicate `col = v` or `col < v` whose target falls outside `[min, max]`
   prunes the whole segment with no body read. Timestamp range filters are a
   special case of this and are very effective on time-ordered telemetry.
2. **Bloom filters.** Per indexed column per segment, sized to the column's
   distinct cardinality at a 1% false-positive rate. `MayContain == false` is a
   definitive "skip this segment" for equality predicates — ideal for
   high-cardinality columns like source IPs where a full posting list would be
   large.
3. **Inverted (Roaring bitmap) indexes.** *Opt-in* (`--inverted` / 
   `BuildInverted`). Map each value to the exact set of matching row positions,
   giving index-only equality resolution, fast AND/OR intersections, and O(1)
   `count`/`top` via bitmap cardinality. Off by default because for
   dictionary-encoded columns the posting lists are reconstructable from the
   column itself.

Without an inverted index, equality still avoids full decompression: zone maps
and Bloom filters prune segments, then the engine decodes the **single** relevant
column of each surviving segment and scans it.

## 2. Grammar (SQL subset)

```
SELECT  count(*) | top(col [, N]) | * | col [, col ...]
FROM    events
[WHERE  <expr>]
[LIMIT  n]

<expr>   := <or>
<or>     := <and> (OR <and>)*
<and>    := <factor> (AND <factor>)*
<factor> := '(' <expr> ')' | <cmp>
<cmp>    := col ('='|'!='|'<'|'>') value | col IN '(' value (',' value)* ')'
value    := 'quoted-string' | number
```

- `count(*)` — number of matching rows.
- `top(col [, N])` — top-N values of `col` by frequency (default N=10).
- projection / `*` — emit matching rows (capped by `LIMIT`, default 1000).
- Operators: `=`, `!=`, `<`, `>`, `IN`, combined with `AND`/`OR` and parentheses.
- Values: single-quoted strings (`''` escapes a quote) or numbers. IP and
  timestamp literals are written as strings and normalized to match storage.

Keywords are case-insensitive. The table name after `FROM` is accepted but
ignored — one file is one table.

### Examples

```sql
SELECT count(*) FROM events WHERE country='RU'
SELECT top(asn) FROM events WHERE dstport=22
SELECT top(username, 20) FROM events
SELECT srcip, dstport FROM events WHERE country='CN' AND dstport IN (22,3389) LIMIT 50
SELECT count(*) FROM events WHERE timestamp > '2024-06-01T00:00:00Z'
```

## 3. Execution plan

```
parse → logical Stmt → for each segment:
        ┌─ evaluate WHERE to a row bitmap ──────────────────────────────┐
        │  Cmp(col = v): zone-map prune → bloom prune → inverted lookup  │
        │                 → else decode column + scan                    │
        │  Cmp(col </>/!= v): decode column + scan (zone-map shortcut)   │
        │  Cmp(col IN (...)): union of equality bitmaps                  │
        │  And/Or: intersect / union child bitmaps (Roaring)            │
        └───────────────────────────────────────────────────────────────┘
   → aggregate (count = Σ cardinality; top = merged histograms)
   → or project matched rows until LIMIT
```

Key properties:

- **Predicate pushdown.** Index checks happen before any column body is read.
- **Column-decode caching.** A column referenced by multiple predicates in one
  segment is decompressed at most once.
- **Null semantics.** Comparisons against null are false; null rows never match
  and are excluded from `top`.
- **`count(*)` with no WHERE** is answered from footer totals — zero decoding.
- **`top` fast path:** with no WHERE and an inverted index present, per-segment
  histograms are merged directly from bitmap cardinalities.

Every result reports `Scanned`/`Pruned` segment counts so you can see pruning at
work (`ntcf query … ` prints `(N scanned, M pruned by index)`).

## 4. Search sugar

`ntcf search <field> <value>` compiles to the same engine. The field resolves
across schemas:

| field | resolves to |
|-------|-------------|
| `ip` | every `TypeIP` column (e.g. `srcip OR dstip`) |
| `port` | every `TypePort` column |
| `asn`, `country`, … | the column of that name |
| any column name | equality on that column |

```bash
ntcf search ip 203.0.113.5 events.ntcf
ntcf search asn 15169 events.ntcf
ntcf search country RU events.ntcf
ntcf search port 22 events.ntcf
```

## 5. Limitations (v1) → roadmap

- No joins, `GROUP BY`, `ORDER BY`, `HAVING`, or arithmetic expressions.
- Aggregates are `count` and `top`; `sum`/`avg`/`min`/`max`/`distinct` are next.
- A query spans a single file; a multi-file catalog is roadmap.
- Range predicates (`<`, `>`, `!=`) scan rather than use a sorted index.

See [Roadmap.md](Roadmap.md).
