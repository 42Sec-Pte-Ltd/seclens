---
name: SecLens MCP
description: >-
  Use when assessing a domain's email security with SecLens.ONE, reading a
  public assessment, quoting a SecLens score, or calling the anonymous MCP at
  seclens.one/mcp. Also use for Global Pulse vs Top-1M number hygiene.
---
# SecLens MCP

Anonymous email-security assessments from SecLens.ONE. No account, no OAuth, no `Authorization` header.

Canonical origin: `https://seclens.one`. MCP: `POST https://seclens.one/mcp`. Docs: `https://seclens.one/auth.md`, `https://seclens.one/openapi.json`, `https://seclens.one/methodology/`.

## When to use

- A domain needs a live SecLens score or protocol breakdown
- Someone asks what SecLens says about a domain
- You need the latest public corpus / last-assessed snapshot
- You are about to quote a SecLens number in copy or a brief

Do not invent scores. Do not mix live Pulse / MCP results with the frozen Top-1M studies (October 2026 and July 2026).

## Transport

Prefer the SecLens MCP if it is already connected (`assess_domain`, `get_result`, `get_summary`). If it is not connected, call the same JSON-RPC over HTTP:

```http
POST /mcp
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2025-03-26
```

Server speaks protocol `2025-06-18`. No session header required. Identity is `anonymous`; `/oauth/token` returns `unsupported_grant_type`. Do not register.

If a GET to `/api/result/{domain}` returns 403, use the MCP `get_result` tool instead.

## Tools

Call in this order.

1. **`get_result`** `{ "domain": "example.com" }`
   Latest stored public assessment. If the payload is a full report, use it. If it says results expired (public reports live 24 hours) or there is no result, go to step 2.
2. **`assess_domain`** `{ "domain": "example.com" }`
   Queues a public assessment. Typical reply: `{"status":"started","count":1,"message":"Assessments queued (durable). Poll /api/result/{domain}"}`.
3. Poll **`get_result`** every few seconds until `Score` and protocol objects are present. Do not start a second assess unless the first clearly failed.
4. **`get_summary`** (no args)
   Recent public assessments (`Domain`, `Score`, `Generated`, `Profile`, mail/null-MX flags). This is the last-assessed list, not the homepage Pulse headlines (those live on seclens.one and move). Do not treat this list as Global Pulse.

One domain per MCP call (`assess_domain`, `get_result`, `get_summary`).

On `429`, back off and retry. Do not hammer assess.

## How to read a result

Always report **profile + score + generated time** (convert to the user's timezone). Then the protocol rows that apply.

Profiles (each sums to 100):

- **`mail`**: regular MX. Core 60 (DMARC 25, SPF 20, MTA-STS 15) + transport/integrity 40 (DKIM 10, DNSSEC 10, DANE 10, TLS-RPT 10).
- **`null_mx`**: RFC 7505 no-mail. With DNSSEC: Null MX 25, SPF 25, DMARC 35, DNSSEC 15. If the TLD has no DNSSEC, those 15 points move to Null MX / SPF / DMARC (30 / 30 / 40). DKIM, MTA-STS, DANE, TLS-RPT are null (not scored, not failed).
- **`no_mx`**: no mail and no valid null MX. Usually 0. Do not praise or punish it as a mail domain.

Grades: Poor 0–39, Fair 40–69, Good 70–89, Excellent 90–100.

Points reward **enforcement**, not a published record. `p=none` is decoration (0 on DMARC). `p=reject` at 100% mail is the DMARC full score. `Status` is `pass` / `warn` / fail-style; `EarnedPoints` / `MaxPoints` is what you quote.

`listing: ephemeral` means a public 24-hour result. After that, `get_result` may return expired; re-assess.

Do not quote `dnsTrace` unless someone asked how the lookup was done. No SMTP is sent; MTA-STS is one HTTPS policy fetch.

## Number hygiene

Two corpora, never mixed:

- **Live MCP / site Pulse**: today's assessment or the live Pulse on seclens.one. These move.
- **Top-1M Studies (October 2026 & July 2026)**: frozen Cloudflare Radar studies at `/research/2026-10-email-security-top1m/` and `/research/2026-07-email-security-top1m/`. Only quote those figures when the user asked for those studies.

Brand spelling is **SecLens.ONE**. Public copy stays English unless the user wrote in another language and wants that back.

Never invent a score, a Pulse headline, or a protocol percentage. If the tool did not return it, say so.

## Output

Lead with the score and profile, then the protocol table (only rows that exist). Name the generated timestamp. If MTA-STS or another check is `warn`, say what failed in one line (e.g. policy advertised, fetch failed). Offer a re-assess only when the stored result is expired or the user asked for a fresh run.
