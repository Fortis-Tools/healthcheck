#!/usr/bin/env node

import process from 'node:process';
import dns from 'node:dns/promises';
import https from 'node:https';
import http from 'node:http';
import tls from 'node:tls';
import { performance } from 'node:perf_hooks';
import { URL } from 'node:url';
import boxen from 'boxen';
import chalk from 'chalk';
import ora from 'ora';

// --- Types ---
interface CheckResult {
    domain: string;
    dns: any;
    ssl: any;
    http: any;
    security: any;
    score: number;
    exitCode: number;
}

const SECURITY_HEADERS = [
    { key: 'strict-transport-security', name: 'Strict-Transport-Security', desc: 'Forces HTTPS connections' },
    { key: 'x-frame-options', name: 'X-Frame-Options', desc: 'Prevents clickjacking attacks' },
    { key: 'x-content-type-options', name: 'X-Content-Type-Options', desc: 'Prevents MIME sniffing' },
    { key: 'content-security-policy', name: 'Content-Security-Policy', desc: 'Prevents XSS attacks' },
    { key: 'referrer-policy', name: 'Referrer-Policy', desc: 'Protects referral privacy' },
    { key: 'permissions-policy', name: 'Permissions-Policy', desc: 'Restricts browser features' },
];

// --- Parsers ---
const args = process.argv.slice(2);
const isJson = args.includes('--json');
const isHelp = args.includes('--help') || args.includes('-h');
const targets = args.filter(a => !a.startsWith('-')).map(a => a.replace(/^https?:\/\//, '').split('/')[0]);

if (isHelp || targets.length === 0) {
    console.log(`
Usage: fortis-healthcheck [domain(s)] [options]

Options:
  --json      Output results in raw JSON format for CI/CD
  --help, -h  Show this help menu

Examples:
  fortis-healthcheck google.com
  fortis-healthcheck github.com ganeshangadi.online
  fortis-healthcheck mysite.com --json
`);
    process.exit(0);
}

// --- Check Functions ---
async function checkDNS(domain: string) {
    const start = performance.now();
    let ipv4 = 'N/A';
    let ipv6 = 'N/A';
    
    try {
        const [a, aaaa] = await Promise.allSettled([
            dns.resolve4(domain),
            dns.resolve6(domain)
        ]);

        if (a.status === 'fulfilled' && a.value.length > 0) ipv4 = a.value[0];
        if (aaaa.status === 'fulfilled' && aaaa.value.length > 0) ipv6 = aaaa.value[0];

        const latency = Math.round(performance.now() - start);
        const isSuccess = ipv4 !== 'N/A' || ipv6 !== 'N/A';
        return { 
            success: isSuccess, ipv4, ipv6, latency, 
            error: isSuccess ? undefined : 'No A or AAAA records found',
            score: isSuccess ? 10 : 0
        };
    } catch (error: any) {
        return { success: false, error: error.message || 'Resolution failed', score: 0 };
    }
}

async function checkSSL(domain: string) {
    return new Promise((resolve) => {
        const options = {
            host: domain,
            port: 443,
            servername: domain,
            rejectUnauthorized: true,
            timeout: 5000,
            ALPNProtocols: ['h2', 'http/1.1']
        };

        const socket = tls.connect(options, () => {
            const cert = socket.getPeerCertificate();
            
            if (!cert || Object.keys(cert).length === 0) {
                socket.end();
                resolve({ success: false, error: 'No certificate', score: 0 });
                return;
            }
            
            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const validDays = Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
            
            const rawIssuer = cert.issuer.O || cert.issuer.CN || 'Unknown';
            const issuer = Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer;
            const cipherObj = socket.getCipher();
            
            resolve({
                success: true,
                validDays,
                issuer,
                validFrom: validFrom.toISOString().split('T')[0],
                validTo: validTo.toISOString().split('T')[0],
                protocol: socket.getProtocol() || 'Unknown',
                cipher: cipherObj.name || 'Unknown',
                alpnProtocol: socket.alpnProtocol || 'http/1.1',
                score: validDays > 30 ? 10 : (validDays > 0 ? 5 : 0)
            });
            
            socket.end();
        });

        socket.on('error', (err) => resolve({ success: false, error: err.message, score: 0 }));
        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve({ success: false, error: 'Timeout', score: 0 });
        });
    });
}

async function checkHTTPAndHeaders(domain: string, alpnProtocol: string) {
    const start = performance.now();
    let currentUrl = `http://${domain}`;
    let redirects = 0;
    let maxRedirects = 5;

    while (redirects < maxRedirects) {
        try {
            const parsed = new URL(currentUrl);
            const client = parsed.protocol === 'https:' ? https : http;
            
            const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
                const req = client.request(currentUrl, { method: 'GET', timeout: 5000 }, resolve);
                req.on('error', reject);
                req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
                req.end();
            });

            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                redirects++;
                let nextUrl = res.headers.location;
                if (!nextUrl.startsWith('http')) {
                    nextUrl = new URL(nextUrl, currentUrl).href;
                }
                currentUrl = nextUrl;
                res.resume();
                continue;
            }

            res.resume();
            const latency = Math.round(performance.now() - start);

            const headerResults: any[] = [];
            let headersPresentCount = 0;
            
            for (const h of SECURITY_HEADERS) {
                const present = !!res.headers[h.key];
                if (present) headersPresentCount++;
                headerResults.push({ ...h, present });
            }

            // Detect compression
            const contentEncoding = res.headers['content-encoding'] || 'none';
            let compression = 'None';
            if (contentEncoding.includes('br')) compression = 'Brotli';
            else if (contentEncoding.includes('gzip')) compression = 'Gzip';
            else if (contentEncoding.includes('deflate')) compression = 'Deflate';

            // Determine HTTP Version mapping
            let finalProtocol = `HTTP/${res.httpVersion}`;
            if (alpnProtocol === 'h2') {
                finalProtocol = 'HTTP/2'; // ALPN confirmed HTTP/2 support even if Node used 1.1
            }

            return {
                success: true,
                status: res.statusCode || 0,
                statusMessage: res.statusMessage || '',
                protocol: finalProtocol,
                latency,
                redirects,
                contentLength: res.headers['content-length'] ? Math.round(parseInt(res.headers['content-length']) / 1024) + ' KB' : 'Unknown',
                compression,
                headerResults,
                headersPresentCount,
                maxHeaders: SECURITY_HEADERS.length,
                score: (res.statusCode && res.statusCode < 400) ? 10 : 0
            };

        } catch (error: any) {
            return { success: false, error: error.message, score: 0, headerResults: [], headersPresentCount: 0, maxHeaders: SECURITY_HEADERS.length };
        }
    }
    
    return { success: false, error: 'Too many redirects', score: 0, headerResults: [], headersPresentCount: 0, maxHeaders: SECURITY_HEADERS.length };
}

// --- Runner ---
async function runCheck(domain: string): Promise<CheckResult> {
    const dnsRes: any = await checkDNS(domain);
    const sslRes: any = await checkSSL(domain);
    const httpRes: any = await checkHTTPAndHeaders(domain, sslRes.alpnProtocol || 'http/1.1');

    let overallScore = 0;
    if (dnsRes.success) overallScore += 2;
    if (sslRes.success && sslRes.validDays > 30) overallScore += 3;
    else if (sslRes.success) overallScore += 1;
    if (httpRes.success && httpRes.status < 400) overallScore += 2;
    if (httpRes.success) overallScore += Math.round((httpRes.headersPresentCount / httpRes.maxHeaders) * 3);

    // Determine Exit Code
    let exitCode = 0;
    if (!dnsRes.success) exitCode = 4;
    else if (!httpRes.success || httpRes.status >= 400) exitCode = 3;
    else if (!sslRes.success || sslRes.validDays < 30) exitCode = 2;
    else if (httpRes.headersPresentCount < httpRes.maxHeaders) exitCode = 1;

    return { domain, dns: dnsRes, ssl: sslRes, http: httpRes, security: httpRes, score: overallScore, exitCode };
}

// --- UI Helpers ---
function renderProgressBar(score: number, max: number): string {
    const filled = Math.round((score / max) * 10);
    const bar = '█'.repeat(filled) + '░'.repeat(10 - filled);
    
    if (filled < 5) return chalk.red(bar) + ` ${score}/${max}`;
    if (filled < 8) return chalk.yellow(bar) + ` ${score}/${max}`;
    return chalk.green(bar) + ` ${score}/${max}`;
}

function getLatencyRating(ms: number) {
    if (ms < 100) return chalk.green('Excellent');
    if (ms < 250) return chalk.green('Good');
    if (ms < 500) return chalk.yellow('Fair');
    if (ms < 1000) return chalk.red('Slow');
    return chalk.red.bold('Critical');
}

// --- Main ---
async function main() {
    if (isJson) {
        const results = await Promise.all(targets.map(t => runCheck(t)));
        console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));
        const worstExit = Math.max(...results.map(r => r.exitCode));
        process.exit(worstExit);
    }

    if (targets.length > 1) {
        console.clear();
        let spinner = ora('Scanning multiple domains...').start();
        const results = await Promise.all(targets.map(t => runCheck(t)));
        spinner.stop();
        console.clear();

        console.log(chalk.cyan.bold('Domain                  Score'));
        console.log(chalk.gray('────────────────────────────────────'));
        
        results.forEach(r => {
            const paddedDomain = r.domain.padEnd(23, ' ');
            const scoreStr = `${r.score}/10`.padStart(5, ' ');
            let color = chalk.green;
            if (r.score < 5) color = chalk.red;
            else if (r.score < 8) color = chalk.yellow;
            console.log(`${paddedDomain} ${color(scoreStr)}`);
        });
        console.log('');
        process.exit(Math.max(...results.map(r => r.exitCode)));
    }

    // Single Target View
    const target = targets[0];
    console.clear();
    const spinner = ora(`Running diagnostics for ${chalk.cyan(target)}...`).start();
    const result = await runCheck(target);
    spinner.stop();
    console.clear();

    const d = result.dns;
    const s = result.ssl;
    const h = result.http;

    let out = `
${chalk.bold.cyan("Diagnostic Report for " + target)}

${chalk.bold.cyan("Overall Health")}

${renderProgressBar(result.score, 10)}

${d.success ? chalk.green('✓ DNS Healthy') : chalk.red('✗ DNS Failing')}
${s.success ? chalk.green('✓ SSL Valid') : chalk.red('✗ SSL Issue')}
${h.success && h.status < 400 ? chalk.green('✓ Reachable') : chalk.red('✗ Unreachable')}
${h.headersPresentCount < h.maxHeaders ? chalk.yellow(`! Missing ${h.maxHeaders - h.headersPresentCount} Security Headers`) : chalk.green('✓ Security Perfect')}

---${chalk.bold.cyan("DNS")} ${chalk.gray(`(${d.score}/10)`)}
`;
    if (d.success) {
        out += `
IPv4: ${d.ipv4}
IPv6: ${d.ipv6}
Lookup Time: ${d.latency} ms
`;
    } else {
        out += chalk.red(`\nFailed: ${d.error}\n`);
    }

    out += `
---${chalk.bold.cyan("SSL")} ${chalk.gray(`(${s.score}/10)`)}
`;
    if (s.success) {
        out += `
Issuer: ${s.issuer}
Valid From: ${s.validFrom}
Expires: ${s.validTo}\n`;

        if (s.validDays < 7) out += chalk.red.bold(`🚨 Expires in ${s.validDays} days\n`);
        else if (s.validDays < 30) out += chalk.yellow.bold(`⚠ Expires in ${s.validDays} days\n`);
        else out += `Days Remaining: ${s.validDays}\n`;
        
        out += `TLS Version: ${s.protocol}
Cipher: ${s.cipher}
`;
    } else {
        out += chalk.red(`\nFailed: ${s.error}\n`);
    }

    out += `
---${chalk.bold.cyan("HTTP")} ${chalk.gray(`(${h.score}/10)`)}
`;
    if (h.success) {
        const compLine = h.compression !== 'None' 
            ? chalk.green(`✓ ${h.compression}`) 
            : chalk.yellow(`None (Potential bandwidth savings available)`);
            
        const protoLine = h.protocol === 'HTTP/2'
            ? chalk.green(`HTTP/2 Enabled ✓`)
            : `${h.protocol} ${chalk.gray('(HTTP/2 not enabled)')}`;

        out += `
Status:          ${h.status} ${h.statusMessage}
Protocol:        ${protoLine}
Response Time:   ${h.latency} ms (Rating: ${getLatencyRating(h.latency)})
Redirects:       ${h.redirects}
Content Length:  ${h.contentLength}
Compression:     ${compLine}
`;
    } else {
        out += chalk.red(`\nFailed: ${h.error}\n`);
    }

    out += `
---${chalk.bold.cyan("Security Posture")}
`;
    if (h.success) {
        h.headerResults.forEach((hr: any) => {
            if (hr.present) out += chalk.green(`✓ ${hr.name}\n`);
            else out += chalk.red(`✗ ${hr.name}\n  ${chalk.gray(hr.desc)}\n`);
        });

        const secScore = Math.round((h.headersPresentCount / h.maxHeaders) * 10);
        out += `
${chalk.bold("Security Assessment")}

${renderProgressBar(secScore, 10)}
`;
    } else {
        out += chalk.red(`\nSkipped (HTTP request failed)\n`);
    }

    // Recommendations
    out += `
---${chalk.bold.cyan("Recommendations")}
`;
    let recsCount = 1;
    if (h.success && h.compression === 'None') {
        out += `${recsCount++}. Enable Brotli or Gzip Compression\n`;
    }
    if (h.success && h.headersPresentCount < h.maxHeaders) {
        h.headerResults.filter((hr: any) => !hr.present).forEach((hr: any) => {
            out += `${recsCount++}. Configure ${hr.name} (${hr.desc})\n`;
        });
    }
    if (s.success && s.validDays < 30) {
        out += `${recsCount++}. Renew SSL Certificate soon\n`;
    }
    if (!h.success) {
        out += chalk.red(`Critical: Target is completely unreachable. Please check DNS and server status.\n`);
    } else if (recsCount === 1) {
        out += chalk.green(`Overall system health is excellent. No immediate actions required.\n`);
    }

    console.log(boxen(out.trim(), {
        padding: 1,
        margin: 1,
        borderStyle: 'double',
        borderColor: 'cyan',
        title: 'Fortis HealthCheck',
        titleAlignment: 'center'
    }));

    process.exit(result.exitCode);
}

main().catch(console.error);
