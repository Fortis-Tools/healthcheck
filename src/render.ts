import boxen from 'boxen';
import chalk from 'chalk';
import { dangerousOpenPorts } from './score.js';
import type { CheckResult, Finding, Options } from './types.js';

export function renderProgressBar(score: number, max: number): string {
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

const SEVERITY_ORDER: Record<Finding['severity'], number> = { error: 0, warning: 1, note: 2 };
export const sortFindings = (findings: Finding[]) =>
    [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

const yesNo = (v: boolean | null, good: boolean) => {
    if (v === null) return chalk.gray('unknown');
    return v === good ? chalk.green(v ? 'Yes' : 'No') : chalk.red(v ? 'Yes' : 'No');
};

export function renderComparisonTable(results: CheckResult[], opts: Options): string {
    type Column = { title: string; width: number; cell: (r: CheckResult) => [string, (s: string) => string] };
    const plain = (s: string) => s;

    const columns: Column[] = [
        { title: 'Domain', width: 24, cell: r => [r.domain, plain] },
        {
            title: 'Score', width: 7, cell: r => {
                const color = r.score < 5 ? chalk.red : r.score < 8 ? chalk.yellow : chalk.green;
                return [`${r.score}/10`, color];
            },
        },
        {
            title: 'Exit', width: 5, cell: r => [String(r.exitCode), r.exitCode === 0 ? chalk.green : chalk.red],
        },
    ];

    if (opts.discover) {
        columns.push({ title: 'WAF / CDN', width: 18, cell: r => [r.http.success ? r.http.waf : 'N/A', plain] });
    }
    if (opts.ports) {
        columns.push({
            title: 'Risky Ports', width: 13, cell: r => {
                const open = dangerousOpenPorts(r.ports);
                return open.length ? [open.map(p => p.port).join(','), chalk.red.bold] : ['none', chalk.green];
            },
        });
    }
    if (opts.mail) {
        columns.push({
            title: 'SPF/DMARC', width: 11, cell: r => {
                const m = r.mail;
                if (!m) return ['N/A', chalk.gray];
                const text = `${m.spf ? '✓' : '✗'} / ${m.dmarc ? '✓' : '✗'}`;
                return [text, m.spf && m.dmarc ? chalk.green : chalk.red];
            },
        });
    }
    if (opts.spider) {
        columns.push({
            title: 'Spider OK', width: 10, cell: r => {
                const s = r.spider;
                if (!s || !s.success) return ['failed', chalk.red];
                const ok = s.endpoints.filter(e => e.status >= 200 && e.status < 400).length;
                return [`${ok}/${s.endpoints.length}`, ok === s.endpoints.length ? chalk.green : chalk.yellow];
            },
        });
    }

    const header = columns.map(c => c.title.padEnd(c.width)).join(' ');
    const lines = [chalk.cyan.bold(header), chalk.gray('─'.repeat(header.length))];
    for (const r of results) {
        lines.push(columns.map(c => {
            const [text, color] = c.cell(r);
            return color(text.padEnd(c.width));
        }).join(' '));
    }
    return lines.join('\n') + '\n';
}

/** One line per check, for --watch. */
export function renderWatchLine(r: CheckResult, previous: CheckResult | undefined): string {
    const time = new Date(r.checkedAt).toLocaleTimeString();
    const scoreColor = r.score < 5 ? chalk.red : r.score < 8 ? chalk.yellow : chalk.green;
    const http = r.http.success
        ? `${r.http.status} ${r.http.latency}ms`
        : chalk.red(`down (${r.http.error})`);
    const ssl = r.ssl.success ? `SSL ${r.ssl.validDays}d` : chalk.red('SSL failing');
    let change = '';
    if (previous && previous.exitCode !== r.exitCode) {
        change = r.exitCode === 0 ? chalk.green.bold('  RECOVERED') : chalk.red.bold(`  CHANGED (exit ${previous.exitCode} → ${r.exitCode})`);
    }
    return `${chalk.gray(time)}  ${r.domain.padEnd(24)} ${scoreColor(`${r.score}/10`.padEnd(6))} ${http.padEnd(14)} ${ssl}  exit ${r.exitCode}${change}`;
}

export function renderReport(result: CheckResult, opts: Options): string {
    const d = result.dns;
    const s = result.ssl;
    const h = result.http;

    let securityLine: string;
    if (!h.success) securityLine = chalk.gray('- Security headers not checked');
    else if (h.headersPresentCount < h.maxHeaders) securityLine = chalk.yellow(`! Missing ${h.maxHeaders - h.headersPresentCount} Security Headers`);
    else securityLine = chalk.green('✓ Security Perfect');

    let out = `
${chalk.bold.cyan('Diagnostic Report for ' + result.domain)}

${chalk.bold.cyan('Overall Health')}

${renderProgressBar(result.score, 10)}

${d.success ? chalk.green('✓ DNS Healthy') : chalk.red('✗ DNS Failing')}
${s.success ? chalk.green('✓ SSL Valid') : chalk.red('✗ SSL Issue')}
${h.success && h.status < 400 ? chalk.green('✓ Reachable') : chalk.red('✗ Unreachable')}
${securityLine}

---${chalk.bold.cyan('DNS')} ${chalk.gray(`(${d.score}/10)`)}
`;
    if (d.success) {
        out += `
IPv4: ${d.ipv4}
IPv6: ${d.ipv6}
Lookup Time: ${d.latency} ms
CAA: ${d.caa.length ? d.caa.join(', ') : chalk.yellow('none')}
DNSSEC: ${d.dnssec === null ? chalk.gray('unknown') : d.dnssec ? chalk.green('signed') : chalk.yellow('not signed')}
`;
    } else {
        out += chalk.red(`\nFailed: ${d.error}\n`);
    }

    out += `
---${chalk.bold.cyan('SSL')} ${chalk.gray(`(${s.score}/10)`)}
`;
    if (s.success) {
        out += `
Issuer: ${s.issuer}
Valid From: ${s.validFrom}
Expires: ${s.validTo}\n`;

        if (s.validDays < 7) out += chalk.red.bold(`🚨 Expires in ${s.validDays} days\n`);
        else if (s.validDays < opts.sslWarnDays) out += chalk.yellow.bold(`⚠ Expires in ${s.validDays} days\n`);
        else out += `Days Remaining: ${s.validDays}\n`;

        const names = s.san.length > 4 ? `${s.san.slice(0, 4).join(', ')} (+${s.san.length - 4} more)` : s.san.join(', ');
        out += `TLS Version: ${s.protocol}
Cipher: ${s.cipher}
Covers: ${names || 'Unknown'}
Chain: ${s.chainLength} certificate(s), verified
TLS 1.0 enabled: ${yesNo(s.legacyTls.tls10, false)}
TLS 1.1 enabled: ${yesNo(s.legacyTls.tls11, false)}
`;
    } else {
        out += chalk.red(`\nFailed: ${s.error}\n`);
    }

    out += `
---${chalk.bold.cyan('HTTP')} ${chalk.gray(`(${h.score}/10)`)}
`;
    if (h.success) {
        const compLine = h.compression !== 'None'
            ? chalk.green(`✓ ${h.compression}`)
            : chalk.yellow('None (Potential bandwidth savings available)');
        const protoLine = h.protocol === 'HTTP/2'
            ? chalk.green('HTTP/2 Enabled ✓')
            : `${h.protocol} ${chalk.gray('(HTTP/2 not enabled)')}`;

        out += `
Status:          ${h.status} ${h.statusMessage}
Final URL:       ${h.finalUrl}
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
---${chalk.bold.cyan('Security Posture')}
`;
    if (h.success) {
        h.headerResults.forEach(hr => {
            if (hr.present) out += chalk.green(`✓ ${hr.name}\n`);
            else out += chalk.red(`✗ ${hr.name}\n  ${chalk.gray(hr.desc)}\n`);
        });
        if (h.hsts) {
            const flags = [h.hsts.includeSubDomains && 'includeSubDomains', h.hsts.preload && 'preload'].filter(Boolean).join(', ');
            out += chalk.gray(`HSTS max-age ${h.hsts.maxAge}s${flags ? `, ${flags}` : ''}\n`);
        }
        for (const issue of [...(h.hsts?.issues ?? []), ...(h.csp?.issues ?? [])]) out += chalk.yellow(`! ${issue}\n`);

        const secScore = Math.round((h.headersPresentCount / h.maxHeaders) * 10);
        out += `
${chalk.bold('Security Assessment')}

${renderProgressBar(secScore, 10)}
`;
    } else {
        out += chalk.red('\nSkipped (HTTP request failed)\n');
    }

    if (opts.discover && h.success) {
        out += `
---${chalk.bold.cyan('Discovery')}
Tech Stack:      ${h.techStack}
WAF / CDN:       ${h.waf}
`;
    }

    if (result.ports) {
        out += `
---${chalk.bold.cyan('Port Scan')}
`;
        result.ports.forEach(p => {
            const status = p.open
                ? (p.dangerous ? chalk.red.bold('OPEN') : p.name === 'Custom' ? chalk.yellow('OPEN') : chalk.green('OPEN'))
                : chalk.gray('CLOSED');
            out += `${p.port.toString().padEnd(6, ' ')} (${p.name.padEnd(13, ' ')}): ${status}\n`;
        });
        const dangerCount = dangerousOpenPorts(result.ports).length;
        if (dangerCount > 0) out += chalk.red.bold(`\nCRITICAL: ${dangerCount} dangerous port(s) open to the internet!\n`);
    }

    if (result.mail) {
        const m = result.mail;
        out += `
---${chalk.bold.cyan('Email Security (DNS)')}
`;
        if (m.error) out += chalk.red(`Error: ${m.error}\n`);
        out += `SPF:   ${m.spf ? chalk.green('✓ Protected') : chalk.red('✗ Missing or invalid')}\n`;
        out += `DMARC: ${m.dmarc ? chalk.green('✓ Protected') : chalk.red('✗ Missing or invalid')}`;
        if (m.dmarcPolicy) {
            const color = m.dmarcPolicy === 'reject' ? chalk.green : m.dmarcPolicy === 'quarantine' ? chalk.yellow : chalk.red;
            out += ` ${chalk.gray('policy')} ${color(`p=${m.dmarcPolicy}`)}`;
        }
        out += `\nDKIM:  ${m.dkimSelectors.length ? chalk.green(`✓ selectors: ${m.dkimSelectors.join(', ')}`) : chalk.yellow('not found under common selectors')}\n`;
    }

    if (result.spider) {
        out += `
---${chalk.bold.cyan('Spider (Random Endpoints)')}
`;
        if (result.spider.success) {
            out += chalk.gray(`Sampled ${result.spider.endpoints.length} of ${result.spider.totalUrls} URLs\n`);
            result.spider.endpoints.forEach(ep => {
                const statusStr = ep.status >= 200 && ep.status < 400 ? chalk.green(ep.status) : chalk.red(ep.status || 'ERR');
                const latStr = (ep.latency + 'ms').padEnd(6, ' ');
                out += `${statusStr} | ${latStr} | ${ep.url}\n`;
            });
        } else {
            out += chalk.red(`Spider failed: ${result.spider.error}\n`);
        }
    }

    out += `
---${chalk.bold.cyan('Recommendations')}
`;
    // Failures already shown in their own section are not repeated as recommendations.
    const skip = new Set(['dns-failure', 'ssl-error', 'http-unreachable', 'spider-failed']);
    const recs = sortFindings(result.findings).filter(f => !skip.has(f.id));
    recs.forEach((f, i) => {
        const color = f.severity === 'error' ? chalk.red : f.severity === 'warning' ? plain : chalk.gray;
        out += color(`${i + 1}. ${f.message}`) + '\n';
    });
    if (!h.success) {
        out += chalk.red('Critical: Target is completely unreachable. Please check DNS and server status.\n');
    } else if (recs.length === 0) {
        out += chalk.green('Overall system health is excellent. No immediate actions required.\n');
    }

    return boxen(out.trim(), {
        padding: { top: 1, bottom: 1, left: 1, right: 14 },
        margin: 1,
        borderStyle: 'double',
        borderColor: 'cyan',
        title: 'Fortis HealthCheck',
        titleAlignment: 'center',
    });
}

const plain = (s: string) => s;
