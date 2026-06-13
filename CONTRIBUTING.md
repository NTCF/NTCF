# Contributing to NTCF

Thanks for your interest in NTCF! Adapters for new telemetry sources and query
features are the most welcome contributions.

## Development setup

```bash
git clone https://github.com/ntcf/ntcf && cd ntcf
make all          # fmt + vet + test + build
make bench        # compression benchmarks
make fuzz         # short fuzz smoke run
```

Requires Go 1.25+ (the toolchain auto-downloads via `GOTOOLCHAIN=auto`). The
build is pure Go; `make test-race` needs a C toolchain for the race detector.

## Ground rules

- **Format & vet must be clean.** `gofmt -s` and `go vet ./...` are enforced in
  CI, as is `golangci-lint`.
- **Tests with changes.** New codecs, format changes, and query features need
  table tests. Anything that parses untrusted bytes needs a fuzz target that
  asserts the no-panic contract (see [docs/Security.md](docs/Security.md)).
- **Never panic on input.** Decoders return errors; they do not panic on hostile
  or truncated data. Gate every file-derived allocation through `internal/util`
  limits.
- **The on-disk format is versioned.** Changes to the byte layout require a
  format-version bump and a note in [docs/FileFormat.md](docs/FileFormat.md).
- **`pkg/ntcf` is a stable API.** Keep it backward-compatible; put churn in
  `internal/`.

## Adding a source adapter

1. Create `internal/adapter/<source>.go` implementing the `Adapter` interface
   (`Name`, `Schema`, `Decode`) and registering itself in `init()`.
2. Map raw fields to a canonical schema using the shared helpers (`ipValue`,
   `uintValue`, `strValue`, `parseTimeNanos`, …). Return `ErrSkip` for lines that
   should be dropped rather than error.
3. Add a table test decoding a representative line and a fuzz seed.
4. If useful for demos/benchmarks, add a generator branch in
   `internal/datagen` and a `schemas/<source>.json` export.

## Commit / PR conventions

- Keep PRs focused; describe the change and its rationale.
- Reference the relevant doc (RFC, FileFormat, …) when changing behavior.
- By contributing you agree your work is licensed under Apache-2.0.

## Reporting bugs

Open an issue with a minimal reproduction. For **security** issues, follow
[SECURITY.md](SECURITY.md) instead of filing a public issue.
