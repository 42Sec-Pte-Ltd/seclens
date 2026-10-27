# SecLens.ONE email security assessor

Standalone Go CLI for the public email-security checks on [SecLens.ONE](https://seclens.one/).

Scored protocols are SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DANE, and DNSSEC. BIMI is informational and does not change the score. The assessor uses passive DNS and one HTTPS GET to the MTA-STS policy endpoint. It does not send mail.

Protocol logic lives in `internal/assessor/rfc*/` packages. Thin bridge files wire DNS lookups and scoring.

Source is https://github.com/42Sec-Pte-Ltd/seclens.

## Checks

- SPF (RFC 7208). Presence, qualifiers, lookup limits, and common misconfiguration hints.
- DMARC (RFC 7489). Policy, reporting tags, and enforcement.
- DKIM (RFC 6376). Common selector discovery.
- MTA-STS (RFC 8461). DNS advertisement, one HTTPS GET of the policy, and MX matching.
- TLS-RPT (RFC 8460). `_smtp._tls` advertisement and reporting URIs.
- DANE (RFC 7672). TLSA records for discovered MX hosts.
- DNSSEC (RFC 4034 and RFC 4035). DS presence and the DoH AD-bit signal.
- BIMI. Informational only. It does not change the score.
- Null MX (RFC 7505). Detects domains that do not receive mail.

Bulk assessment uses bounded concurrency. Output is text, JSON, or JSONL. JSON DoH resolvers default to Cloudflare. Google and Quad9 are supported.

## MCP Server

Anonymous Streamable HTTP at https://seclens.one/mcp.

Tools are `get_result`, `assess_domain`, and `get_summary`.

Cursor 1-Click Install opens [Add SecLens.ONE](cursor://anysphere.cursor-deeplink/mcp/install?name=seclens&config=eyJ1cmwiOiJodHRwczovL3NlY2xlbnMub25lL21jcCJ9).

`mcp.json`:

```json
{
  "mcpServers": {
    "seclens": {
      "type": "http",
      "url": "https://seclens.one/mcp"
    }
  }
}
```

## Dependencies

Core DNS and HTTP use the Go standard library. One module dependency handles internationalized domain names.

- [`golang.org/x/net/idna`](https://pkg.go.dev/golang.org/x/net/idna) handles punycode and IDNA for MTA-STS MX host matching.

Run `go list -m all` after `go mod download` to inspect the module graph.

## Build

```bash
go build -o seclens ./cmd/seclens
```

## Assess

```bash
./seclens assess cloudflare.com
./seclens assess --format jsonl example.com google.com
cat domains.txt | ./seclens assess --stdin --concurrency 12 --format jsonl > results.jsonl
./seclens assess --file domains.txt --resolver google,cloudflare
```

Resolver flag values are `cloudflare`, `google`, and `quad9`. Separate a pool with commas.

## Tests

```bash
go test ./...
```

## Research

The CLI measures the same controls as the SecLens Top-1M studies:

- [October 2026 Top-1M Email Security Study](https://seclens.one/research/2026-10-email-security-top1m/)
- [July 2026 Top-1M Email Security Study](https://seclens.one/research/2026-07-email-security-top1m/)

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
