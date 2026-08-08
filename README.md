# web-osint

A Go-based OSINT utility for collecting **publicly observable web intelligence** about a domain or website.

> This project does not access private systems, bypass authentication, or claim authoritative visitor counts from public HTTP responses. Traffic figures require an analytics source, server-side logs, or a third-party measurement provider.

## Current features

- HTTP/HTTPS status and redirect target
- Response time
- Server and Content-Type headers
- DNS A / AAAA / MX / NS / TXT lookups
- TLS version and leaf certificate metadata
- Basic technology fingerprinting from public response metadata
- Security-header presence checks
- Optional `robots.txt` and `sitemap.xml` checks
- Human-readable terminal report
- JSON output for automation
- No external dependencies

## Usage

```bash
go run ./cmd/web-osint example.com
go run ./cmd/web-osint --full example.com
go run ./cmd/web-osint --json example.com > report.json
```

Build a standalone binary:

```bash
go build -o web-osint ./cmd/web-osint
./web-osint --full example.com
```

## Traffic data

A website's real visitor count is normally not exposed by DNS or HTTP. The tool therefore does **not invent traffic numbers**. A future provider module can integrate an explicitly documented public measurement API/source and mark its values as estimates.

## Scope

Use the tool for domains you own, administer, or are authorized to assess, and for ordinary public-information research. It is intentionally limited to passive/public web intelligence.

## Roadmap

- [ ] RDAP / WHOIS metadata
- [ ] ASN and IP organization enrichment
- [ ] Certificate transparency subdomain discovery
- [ ] Better HTML/JavaScript technology detection
- [ ] Public traffic-estimate provider interface
- [ ] Structured report schema/versioning
- [ ] Rate limiting and concurrent scan controls
- [ ] Unit tests and integration tests
- [ ] Release binaries for Linux/macOS/Windows

## License

MIT
