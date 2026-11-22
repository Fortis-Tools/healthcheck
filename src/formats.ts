import { VERSION } from './version.js';
import { sortFindings } from './render.js';
import type { CheckResult, Finding, OutputFormat } from './types.js';

const mdEscape = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const xmlEscape = (s: string) => s
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;');

const ICON: Record<Finding['severity'], string> = { error: '🔴', warning: '🟡', note: '🔵' };

export function toMarkdown(results: CheckResult[]): string {
    const lines: string[] = ['## 🩺 Fortis HealthCheck', ''];
    lines.push('| Domain | Score | Exit | DNS | SSL | HTTP | Security headers |');
    lines.push('|---|---|---|---|---|---|---|');
    for (const r of results) {
        const ssl = r.ssl.success ? `✅ ${r.ssl.validDays}d left` : '❌';
        const http = r.http.success ? `${r.http.status < 400 ? '✅' : '❌'} ${r.http.status} (${r.http.latency} ms)` : '❌ unreachable';
        const headers = r.http.success ? `${r.http.headersPresentCount}/${r.http.maxHeaders}` : 'n/a';
        lines.push(`| ${mdEscape(r.domain)} | ${r.score}/10 | ${r.exitCode} | ${r.dns.success ? '✅' : '❌'} | ${ssl} | ${http} | ${headers} |`);
    }

    for (const r of results) {
        lines.push('', `### ${r.domain}`, '');
        if (r.findings.length === 0) {
            lines.push('No findings. ✅');
            continue;
        }
        for (const f of sortFindings(r.findings)) lines.push(`- ${ICON[f.severity]} **${f.severity}** ${mdEscape(f.message)}`);
    }
    lines.push('', `<sub>@fortis-tools/healthcheck v${VERSION}</sub>`);
    return lines.join('\n') + '\n';
}

const SARIF_LEVEL: Record<Finding['severity'], string> = { error: 'error', warning: 'warning', note: 'note' };

/** Turns per-instance ids (missing-x-frame-options, open-port-22, csp-weak-2) into stable rule ids. */
const ruleId = (id: string) => id.replace(/-\d+$/, '');

export function toSarif(results: CheckResult[]): string {
    const rules = new Map<string, Finding>();
    for (const r of results) for (const f of r.findings) if (!rules.has(ruleId(f.id))) rules.set(ruleId(f.id), f);

    const sarif = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'fortis-healthcheck',
                    version: VERSION,
                    informationUri: 'https://github.com/Fortis-Tools/healthcheck',
                    rules: [...rules.entries()].map(([id, f]) => ({
                        id,
                        name: id,
                        shortDescription: { text: id.replace(/-/g, ' ') },
                        defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
                        properties: { category: f.category },
                    })),
                },
            },
            results: results.flatMap(r => r.findings.map(f => ({
                ruleId: ruleId(f.id),
                level: SARIF_LEVEL[f.severity],
                message: { text: f.message },
                locations: [{ physicalLocation: { artifactLocation: { uri: `https://${r.domain}/` } } }],
                properties: { domain: r.domain, category: f.category },
            }))),
        }],
    };
    return JSON.stringify(sarif, null, 2) + '\n';
}

export function toJUnit(results: CheckResult[]): string {
    // One test case per check area; it fails if that area has an error or warning finding.
    const areas: { name: string; categories: Finding['category'][]; applies: (r: CheckResult) => boolean }[] = [
        { name: 'dns', categories: ['dns'], applies: () => true },
        { name: 'ssl', categories: ['ssl'], applies: () => true },
        { name: 'http', categories: ['http', 'performance'], applies: () => true },
        { name: 'security-headers', categories: ['security'], applies: r => r.http.success },
        { name: 'ports', categories: ['ports'], applies: r => r.ports !== null },
        { name: 'mail', categories: ['mail'], applies: r => r.mail !== null },
        { name: 'spider', categories: ['spider'], applies: r => r.spider !== null },
    ];

    const suites = results.map(r => {
        const cases = areas.filter(a => a.applies(r)).map(a => {
            const relevant = r.findings.filter(f => a.categories.includes(f.category) && f.severity !== 'note');
            const notes = r.findings.filter(f => a.categories.includes(f.category) && f.severity === 'note');
            let body = '';
            if (relevant.length) {
                const type = relevant.some(f => f.severity === 'error') ? 'error' : 'warning';
                body += `\n      <failure message="${xmlEscape(relevant[0].message)}" type="${type}">${xmlEscape(relevant.map(f => `[${f.severity}] ${f.message}`).join('\n'))}</failure>`;
            }
            if (notes.length) body += `\n      <system-out>${xmlEscape(notes.map(f => f.message).join('\n'))}</system-out>`;
            const failed = relevant.length > 0;
            return { xml: `    <testcase classname="${xmlEscape(r.domain)}" name="${a.name}">${body}${body ? '\n    ' : ''}</testcase>`, failed };
        });
        const failures = cases.filter(c => c.failed).length;
        return {
            failures,
            tests: cases.length,
            xml: `  <testsuite name="${xmlEscape(r.domain)}" tests="${cases.length}" failures="${failures}" timestamp="${r.checkedAt}">\n${cases.map(c => c.xml).join('\n')}\n  </testsuite>`,
        };
    });

    const tests = suites.reduce((n, s) => n + s.tests, 0);
    const failures = suites.reduce((n, s) => n + s.failures, 0);
    return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="fortis-healthcheck" tests="${tests}" failures="${failures}">\n${suites.map(s => s.xml).join('\n')}\n</testsuites>\n`;
}

export function toJson(results: CheckResult[]): string {
    return JSON.stringify(results.length === 1 ? results[0] : results, null, 2) + '\n';
}

export function formatResults(format: Exclude<OutputFormat, 'text'>, results: CheckResult[]): string {
    switch (format) {
        case 'json': return toJson(results);
        case 'markdown': return toMarkdown(results);
        case 'sarif': return toSarif(results);
        case 'junit': return toJUnit(results);
    }
}
