# 🩺 @fortis-tools/healthcheck

A production-grade, miniature SRE observability CLI tool. It deeply inspects domains and provides a comprehensive diagnostic report covering DNS, SSL, HTTP/2, and Security Posture.

It goes far beyond a simple `ping` by tracking HTTP redirects, detecting ALPN negotiated protocols, evaluating strict security headers, and calculating an overall Health Score. It is built to be modular, supporting multiple domains and CI/CD pipelines natively.

## 🚀 Quick Start

Run it instantly against any domain using `npx`:

```bash
npx @fortis-tools/healthcheck google.com
```

## ✨ Features

- **DNS Diagnostics**: Concurrently resolves IPv4 (`A`) and IPv6 (`AAAA`) records.
- **Deep SSL Inspection**: Evaluates the SSL Certificate issuer, exact expiry dates, Cipher Suite, and negotiated TLS Version.
- **ALPN HTTP/2 Detection**: Injects `ALPNProtocols` into the TLS socket to natively determine if the server supports HTTP/2 binary framing.
- **Actionable Security Posture**: Checks for 6 strict security headers (e.g. `Content-Security-Policy`, `HSTS`) and provides clear explanations for why they matter.
- **Tech Stack & WAF Recon (`--discover`)**: Parses headers to identify the underlying cloud provider, WAF (Cloudflare, AWS, Vercel), and framework.
- **Port Scanner (`--ports`)**: Concurrently scans standard vulnerable ports (22, 3306, 27017, etc.) with strict timeouts and alerts on dangerous internet exposure.
- **Email Security (`--mail`)**: Queries DNS TXT records to validate SPF and DMARC configurations against spoofing.
- **Endpoint Spider (`--spider`)**: Parses `sitemap.xml`, samples endpoints, and concurrently measures TTFB latency across the application.
- **Smart Scoring Engine**: Calculates an Overall Health Score (out of 10) and provides a list of actionable recommendations.
- **CI/CD Ready**: 
  - Supports `--json` flag to output raw structured data.
  - Returns standard exit codes (`0` for Healthy, `1` for Security warnings, `2` for SSL warnings, `3` for HTTP errors, `4` for DNS failures).
- **Multi-Domain Support**: Pass an array of domains to generate a sleek comparative score table.

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

### Multi-Domain Comparison
```bash
npx @fortis-tools/healthcheck google.com github.com example.com
```

### CI/CD JSON Output
```bash
npx @fortis-tools/healthcheck yourdomain.com --json
```

## 🛠️ Built With

- [Node.js](https://nodejs.org/) Native Modules (`dns`, `tls`, `https`, `http`)
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
---

## 👨‍💻 Maintainer

**Ganesh Angadi**
- 🐙 GitHub: [@ganeshak11](https://github.com/ganeshak11)
- 🌐 Portfolio: [ganeshangadi.online](https://ganeshangadi.online)
- 💼 LinkedIn: [Ganesh Angadi](https://linkedin.com/in/ganeshangadi1301)

---
*Built as part of the Fortis-Tools DevOps toolkit.*
