# web-osint-traffic

Public traffic intelligence companion for `web-osint`.

## What it reports

- **Similarweb visits:** estimated monthly worldwide visits when `SIMILARWEB_API_KEY` is configured.
- **Cloudflare Radar rank:** domain popularity rank/bucket when `CLOUDFLARE_API_TOKEN` is configured.

These are not authoritative server analytics. The tool never presents third-party estimates as exact visitor counts.

## Usage

```bash
go run ./cmd/web-osint-traffic example.com
```

JSON:

```bash
go run ./cmd/web-osint-traffic --json example.com
```

Configure credentials through environment variables; never commit them:

```bash
export SIMILARWEB_API_KEY='...'
export CLOUDFLARE_API_TOKEN='...'
```

Similarweb documents the visits endpoint and identifies its values as estimated visits. Cloudflare Radar documents its domain ranking as a popularity ranking based on DNS-query data, not a direct visitor counter.
