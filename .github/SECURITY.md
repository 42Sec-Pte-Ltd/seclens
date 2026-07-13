# Security Policy

## Supported versions

This repository publishes the SecLens email/domain security assessor CLI. The latest commit on `main` is the supported surface.

## Reporting a vulnerability

Please report security issues **privately** via GitHub Security Advisories for this repository:

https://github.com/seclens-one/seclens/security/advisories/new

Do not open public issues for unfixed vulnerabilities.

Include:

- Affected commit or release
- Description and impact
- Minimal reproduction steps if possible

We aim to acknowledge reports within a few business days.

## Automated checks

Pull requests and `main` run:

- `go test` / `go vet` / `go mod verify`
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [staticcheck](https://staticcheck.dev/)
- [gosec](https://github.com/securego/gosec)
- [CodeQL](https://codeql.github.com/) (security-extended + quality)

Dependabot opens weekly PRs for Go modules and GitHub Actions.
