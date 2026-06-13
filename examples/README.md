# NTCF Examples

Runnable programs demonstrating the public `pkg/ntcf` API.

| Example | What it shows |
|---------|---------------|
| [`writeread`](writeread/) | Define a schema, write records to a `.ntcf` file, reopen it, and run a search + an aggregate query. |

```bash
go run ./examples/writeread
```

For end-to-end CLI workflows (pack, search, query, stream-ingest), see the
[Quickstart](../README.md#quickstart) in the top-level README, or generate data
with `ntcf gen` and explore it with `ntcf info` / `ntcf query`.
