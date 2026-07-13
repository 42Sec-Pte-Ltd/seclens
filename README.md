# seclens — Email & Domain Security Assessor

A standalone Go CLI that measures email and domain security controls aligned with the [SecLens Top-1M study](https://seclens.one/research/2026-07-email-security-top1m/).

The assessor validates SPF, DMARC, DKIM, MTA-STS (including HTTPS policy fetch), TLS-RPT, DANE/TLSA, DNSSEC signals, and related RFC-defined controls. Protocol logic lives in `internal/assessor/rfc*/` packages (RFC-numbered modules); thin bridge files wire DNS lookups and scoring.

## Features

- **SPF** (RFC 7208) — presence, qualifiers, lookup limits, common misconfiguration hints
- **DMARC** (RFC 7489) — policy, reporting tags, enforcement level
- **DKIM** (RFC 6376) — common selector discovery
- **MTA-STS** (RFC 8461) — DNS advertisement plus HTTPS policy validation and MX matching
- **TLS-RPT** (RFC 8460) — `_smtp._tls` advertisement and reporting URIs
- **DANE** (RFC 7672) — TLSA records for discovered MX hosts
- **DNSSEC** (RFC 4034/4035) — DS presence and DoH AD-bit signal
- **Null MX** (RFC 7505) — non-receiving domain detection
- Bulk assessment with bounded concurrency; text, JSON, and JSONL output
- JSON DoH resolvers (Cloudflare default; Google and Quad9 supported)

## Dependencies

Core DNS and HTTP use the Go standard library. One small module dependency is required for internationalized domain names:

- [`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna) — punycode / IDNA handling for MTA-STS MX host matching

Run `go list -m all` after `go mod download` to inspect the module graph.

## Build

```bash
go build -o seclens ./cmd/seclens
```

## Assess (CLI)

```bash
./seclens assess cloudflare.com
./seclens assess --format jsonl example.com google.com
cat domains.txt | ./seclens assess --stdin --concurrency 12 --format jsonl > results.jsonl
./seclens assess --file domains.txt --resolver google,cloudflare
```

Resolver flag values: `cloudflare`, `google`, `quad9` (comma-separated for a pool).

## Tests

```bash
go test ./...
```

## Research context

This project is designed to reproduce measurement-style email/domain security studies. See the [SecLens Top-1M study](https://seclens.one/research/2026-07-email-security-top1m/) for methodology, control set, and prevalence findings.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
