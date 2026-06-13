# Security Policy

## Supported versions

NTCF is pre-1.0. Security fixes are applied to the latest `main` and the most
recent tagged release.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public GitHub issue
for a vulnerability.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this
  repository, or
- email the maintainers at **security@ntcf.dev** (PGP welcome).

Include a description, affected version/commit, and a reproduction (a crafted
`.ntcf` file or input is ideal). We aim to acknowledge within 3 business days and
to provide a remediation timeline after triage.

## Scope

In scope: memory-safety or denial-of-service in the file readers, decoders,
query parser, or ingestion path triggered by crafted input (panics, unbounded
allocation, out-of-bounds access, decompression bombs, infinite loops).

Out of scope (by design — see [docs/Security.md](docs/Security.md)): the absence
of cryptographic authentication and encryption. NTCF's checksums detect
accidental corruption, not malicious tampering by an actor with write access.
Authenticated containers are on the roadmap; do not treat current integrity
checks as a security boundary against an active adversary.

## Hardening reference

The threat model, resource limits, and fuzzing strategy are documented in
[docs/Security.md](docs/Security.md). New parsers of untrusted bytes must ship
with a fuzz target asserting the no-panic contract.
