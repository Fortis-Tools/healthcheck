import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeExitCode, computeFindings, computeScore, worstExitCode, EXIT } from '../src/score.js';
import { toJUnit, toMarkdown, toSarif } from '../src/formats.js';
import type { CheckResult, DnsResult, HttpResult, SslResult } from '../src/types.js';
import { options } from './helpers.js';

const dns: DnsResult = { success: true, ipv4: '1.2.3.4', ipv6: 'N/A', latency: 5, score: 10, caa: ['issue letsencrypt.org'], dnssec: true };
const ssl = (validDays: number): SslResult => ({
    success: true, validDays, issuer: 'LE', validFrom: '2026-01-01', validTo: '2027-01-01', protocol: 'TLSv1.3',
    cipher: 'X', alpnProtocol: 'h2', san: ['a.com'], chainLength: 3, legacyTls: { tls10: false, tls11: false }, score: 10,
});
const http = (present: number, status = 200): HttpResult => ({
    success: true, status, statusMessage: 'OK', finalUrl: 'https://a.com/', protocol: 'HTTP/2', latency: 50, redirects: 1,
    contentLength: '1 KB', compression: 'Brotli', techStack: 'nginx', waf: 'None Detected', hsts: null, csp: null, score: 10,
    headersPresentCount: present, maxHeaders: 6,
    headerResults: ['a', 'b', 'c', 'd', 'e', 'f'].map((k, i) => ({ key: k, name: k.toUpperCase(), desc: 'd', present: i < present })),
});
const partial = (over: Partial<CheckResult> = {}) => ({
    domain: 'a.com', checkedAt: '2026-11-22T00:00:00.000Z', dns, ssl: ssl(90), http: http(6), ports: null, mail: null, spider: null, ...over,
});

test('score formula is unchanged', () => {
    assert.equal(computeScore(dns, ssl(90), http(6)), 10);
    assert.equal(computeScore(dns, ssl(10), http(3)), 2 + 1 + 2 + 2);
    assert.equal(computeScore(dns, ssl(20), http(6), 14), 10); // --ssl-warn-days 14
});

test('exit codes follow --fail-on, --min-score and --ssl-warn-days', () => {
    const o = options();
    assert.equal(computeExitCode(partial(), 10, o), EXIT.HEALTHY);
    assert.equal(computeExitCode(partial({ http: http(4) }), 9, o), EXIT.SECURITY);
    assert.equal(computeExitCode(partial({ http: http(4) }), 9, options({ failOn: ['http', 'ssl'] })), EXIT.HEALTHY);
    assert.equal(computeExitCode(partial({ ssl: ssl(20) }), 8, o), EXIT.SSL);
    assert.equal(computeExitCode(partial({ ssl: ssl(20) }), 8, options({ sslWarnDays: 14 })), EXIT.HEALTHY);
    assert.equal(computeExitCode(partial({ http: http(6, 503) }), 8, o), EXIT.HTTP);
    assert.equal(computeExitCode(partial(), 7, options({ minScore: 8 })), EXIT.MIN_SCORE);
    const ports = [{ port: 22, name: 'SSH', dangerous: true, open: true }];
    assert.equal(computeExitCode(partial({ ports }), 10, o), EXIT.HEALTHY);
    assert.equal(computeExitCode(partial({ ports }), 10, options({ failOn: ['ports'] })), EXIT.PORTS);
    const mail = { spf: true, dmarc: false, dmarcPolicy: null, dkimSelectors: [], error: '' };
    assert.equal(computeExitCode(partial({ mail }), 10, options({ failOn: ['mail'] })), EXIT.MAIL);
});

test('worst exit code uses severity, not the largest number', () => {
    assert.equal(worstExitCode([1, 6, 3]), 3);
    assert.equal(worstExitCode([1, 8]), 8);
    assert.equal(worstExitCode([]), 0);
});

test('findings cover headers, legacy TLS, ports, DMARC policy', () => {
    const p = partial({
        ssl: { ...ssl(90), legacyTls: { tls10: true, tls11: false } } as SslResult,
        http: http(5),
        ports: [{ port: 6379, name: 'Redis', dangerous: true, open: true }],
        mail: { spf: true, dmarc: true, dmarcPolicy: 'none', dkimSelectors: [], error: '' },
    });
    const ids = computeFindings(p).map(f => f.id);
    assert.deepEqual(ids.sort(), ['dkim-not-found', 'dmarc-policy-none', 'legacy-tls', 'missing-f', 'open-port-6379'].sort());
});

test('markdown, SARIF and JUnit outputs are well formed', () => {
    const p = partial({ http: http(5) });
    const result: CheckResult = { ...p, score: 9, exitCode: 1, findings: computeFindings(p) };

    const md = toMarkdown([result]);
    assert.match(md, /\| a\.com \| 9\/10 \| 1 \|/);
    assert.match(md, /Configure F/);

    const sarif = JSON.parse(toSarif([result]));
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].ruleId, 'missing-f');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'https://a.com/');

    const xml = toJUnit([result]);
    assert.match(xml, /<testsuites name="fortis-healthcheck" tests="4" failures="1">/);
    assert.match(xml, /<testcase classname="a.com" name="security-headers">\n\s+<failure/);
});
