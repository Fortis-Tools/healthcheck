# 🩺 @fortis-tools/healthcheck

A production-grade, miniature SRE observability CLI tool. It deeply inspects domains and provides a comprehensive diagnostic report covering DNS, SSL, HTTP/2, and Security Posture.

It goes far beyond a simple `ping` by tracking HTTP redirects, detecting ALPN negotiated protocols, evaluating strict security headers, and calculating an overall Health Score. It is built to be modular, supporting multiple domains and CI/CD pipelines natively.

## 🚀 Quick Start

Run it instantly against any domain using `npx`:

```bash
npx @fortis-tools/healthcheck google.com
```

## ✨ Features

- **DNS Diagnostics**: Concurrently resolves IPv4 (`A`) and IPv6 (`AAAA`) records, lists **CAA** records, and checks whether the zone is **DNSSEC**-signed (publishes `DNSKEY` records).
- **Deep SSL Inspection**: Issuer, expiry, cipher suite, negotiated TLS version, the names the certificate covers, and chain length. Failures say *why*: expired, hostname mismatch, incomplete chain, or self-signed. It also probes whether the server still accepts **TLS 1.0 / 1.1**.
- **ALPN HTTP/2 Detection**: Injects `ALPNProtocols` into the TLS socket to natively determine if the server supports HTTP/2 binary framing.
- **Actionable Security Posture**: Checks for 6 strict security headers (e.g. `Content-Security-Policy`, `HSTS`) and grades their quality: HSTS `max-age` / `preload` readiness, and CSP `'unsafe-inline'`, `'unsafe-eval'` and wildcard script sources.
- **Tech Stack & WAF Recon (`--discover`)**: Parses headers to identify the WAF/CDN (Cloudflare, AWS CloudFront, Vercel, Fastly, Azure Front Door, Akamai) and the server framework.
- **Port Scanner (`--ports`)**: Scans risky ports (SSH, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch 9200, Memcached 11211, Docker API 2375…). Pass your own list with `--ports 22,8080`.
- **Email Security (`--mail`)**: SPF, DMARC **and its policy** (`p=none` / `quarantine` / `reject`), and DKIM keys under common selectors.
- **Endpoint Spider (`--spider`)**: Parses `sitemap.xml` (including sitemap index files), samples 10 random endpoints, and concurrently measures TTFB latency across the application.
- **Smart Scoring Engine**: Calculates an Overall Health Score (out of 10) and provides a list of actionable recommendations.
- **CI/CD Ready**: thresholds (`--min-score`, `--ssl-warn-days`, `--timeout`, `--fail-on`), machine-readable output (`--json`, `--format markdown|sarif|junit`) and documented exit codes.
- **Watch mode (`--watch 60`)**: re-checks on an interval and prints one line per check, flagging changes and recoveries.
- **Config file**: commit a `healthcheck.json` with your fleet of domains and options.
- **Multi-Domain Support**: Pass several domains to generate a comparison table; the `--discover`, `--ports`, `--mail` and `--spider` results appear as extra columns.
- **HTTPS-only hosts**: If port 80 is closed, the HTTP check retries over HTTPS instead of reporting the site as down.

## 💻 Usage

### Single Domain Inspection (Standard)
```bash
npx @fortis-tools/healthcheck yourdomain.com
```

### Full Reconnaissance Mode
Run all the advanced diagnostic flags at once:
```bash
npx @fortis-tools/healthcheck yourdomain.com --discover --ports --mail --spider
```

### Choose the ports to scan
```bash
npx @fortis-tools/healthcheck yourdomain.com --ports 22,8080,9200
```

### Multi-Domain Comparison
```bash
npx @fortis-tools/healthcheck google.com github.com example.com
```

### Watch a site
```bash
npx @fortis-tools/healthcheck yourdomain.com --watch 30
```

## 🤖 CI/CD

### Output formats

| Flag | Output |
|---|---|
| `--json` / `--format json` | Full structured result (an array when you pass several domains). With `--watch`, one JSON object per line. |
| `--format markdown` | A summary table plus findings, ready to post as a PR comment. |
| `--format sarif` | SARIF 2.1.0, for GitHub code scanning and other dashboards. |
| `--format junit` | JUnit XML: one test case per check area, so CI test reports show what failed. |

### Thresholds

| Flag | Default | Meaning |
|---|---|---|
| `--min-score <n>` | off | Exit `6` when the score is below `n` (0–10). |
| `--ssl-warn-days <n>` | `30` | A certificate expiring within `n` days counts as an SSL warning. |
| `--timeout <ms>` | `5000` | Per-request timeout. |
| `--fail-on <list>` | `dns,http,ssl,security` | Which checks set the exit code. Add `ports` or `mail` to fail on open risky ports or missing SPF/DMARC. |

```bash
# Only fail the build when the site is down or the score drops below 8
npx @fortis-tools/healthcheck yourdomain.com --fail-on dns,http --min-score 8
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Healthy |
| `1` | Security header warnings |
| `2` | SSL warnings (invalid, or expiring within `--ssl-warn-days`) |
| `3` | HTTP errors |
| `4` | DNS failure |
| `5` | Internal or usage error |
| `6` | Score below `--min-score` |
| `7` | Dangerous ports open (only with `--fail-on ports`) |
| `8` | SPF or DMARC missing (only with `--fail-on mail`) |

With several domains, the most serious code wins (DNS > HTTP > SSL > ports > mail > score > security).

### Config file

Run with no domains and the tool reads `./healthcheck.json`, or pass `--config path/to/file.json`. Command-line flags override the file. See [`healthcheck.example.json`](healthcheck.example.json):

```json
{
  "domains": ["example.com", "example.org"],
  "discover": true,
  "mail": true,
  "ports": [22, 3306, 6379, 9200],
  "minScore": 6,
  "sslWarnDays": 14,
  "timeout": 5000,
  "failOn": ["dns", "http", "ssl", "ports"],
  "format": "text"
}
```

`ports` can also be `true` for the default list. `watch` takes a number of seconds.

### Upgrading from 3.x

- The `security` field in the JSON output was removed; it was an exact copy of `http`. Read `http` instead.
- New JSON fields: `checkedAt`, `findings`, `dns.caa`, `dns.dnssec`, `ssl.san`, `ssl.chainLength`, `ssl.legacyTls`, `http.hsts`, `http.csp`, `mail.dmarcPolicy`, `mail.dkimSelectors`.
- New exit codes `6`, `7`, `8` only appear when you use `--min-score` or add `ports` / `mail` to `--fail-on`.
- Unknown options are now an error (exit `5`) instead of being ignored.

## 🛠️ Built With

- [Node.js](https://nodejs.org/) Native Modules (`dns`, `dgram`, `tls`, `https`, `http`) — Node 20+
- [TypeScript](https://www.typescriptlang.org/)
- [Boxen](https://github.com/sindresorhus/boxen) & [Chalk](https://github.com/chalk/chalk) for the UI

## 📦 Local Development

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile the TypeScript:
   ```bash
   npm run build
   ```
4. Run the CLI:
   ```bash
   node dist/index.js google.com
   ```
5. Run the tests (`node:test` with local HTTP/HTTPS servers; the HTTPS test needs `openssl`):
   ```bash
   npm test
   ```

Code layout: `src/checks/` holds one file per check (dns, ssl, http, ports, mail, spider), `score.ts` the score, exit codes and findings, `render.ts` the terminal output, `formats.ts` the Markdown/SARIF/JUnit output, and `options.ts` the flags and config file.
---

## 👨‍💻 Maintainer

**Ganesh Angadi**
- 🐙 GitHub: [@ganeshak11](https://github.com/ganeshak11)
- 🌐 Portfolio: [ganeshangadi.online](https://ganeshangadi.online)
- 💼 LinkedIn: [Ganesh Angadi](https://linkedin.com/in/ganeshangadi1301)

---
*Built as part of the Fortis-Tools DevOps toolkit.*
