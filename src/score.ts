import type { CheckResult, DnsResult, FailCategory, Finding, HttpResult, Options, PortResult, SslResult } from './types.js';

export const EXIT = {
    HEALTHY: 0,
    SECURITY: 1,
    SSL: 2,
    HTTP: 3,
    DNS: 4,
    INTERNAL: 5,
    MIN_SCORE: 6,
    PORTS: 7,
    MAIL: 8,
} as const;

/** Most serious first. Used to pick one exit code when several domains or checks fail. */
const EXIT_PRIORITY: number[] = [EXIT.INTERNAL, EXIT.DNS, EXIT.HTTP, EXIT.SSL, EXIT.PORTS, EXIT.MAIL, EXIT.MIN_SCORE, EXIT.SECURITY, EXIT.HEALTHY];

export const DEFAULT_FAIL_ON: FailCategory[] = ['dns', 'http', 'ssl', 'security'];

export function worstExitCode(codes: number[]): number {
    const rank = (c: number) => {
        const i = EXIT_PRIORITY.indexOf(c);
        return i === -1 ? EXIT_PRIORITY.length : i;
    };
    return codes.reduce((worst, c) => (rank(c) < rank(worst) ? c : worst), EXIT.HEALTHY as number);
}

export function computeScore(dns: DnsResult, ssl: SslResult, http: HttpResult, sslWarnDays = 30): number {
    let score = 0;
    if (dns.success) score += 2;
    if (ssl.success && ssl.validDays > sslWarnDays) score += 3;
    else if (ssl.success) score += 1;
    if (http.success && http.status < 400) score += 2;
    if (http.success) score += Math.round((http.headersPresentCount / http.maxHeaders) * 3);
    return score;
}

export const dangerousOpenPorts = (ports: PortResult[] | null) => (ports || []).filter(p => p.open && p.dangerous);

type Partial = Omit<CheckResult, 'score' | 'exitCode' | 'findings'>;

export function computeExitCode(r: Partial, score: number, opts: Pick<Options, 'failOn' | 'minScore' | 'sslWarnDays'>): number {
    const on = (c: FailCategory) => opts.failOn.includes(c);
    const failing: number[] = [];
    if (on('dns') && !r.dns.success) failing.push(EXIT.DNS);
    if (on('http') && (!r.http.success || r.http.status >= 400)) failing.push(EXIT.HTTP);
    if (on('ssl') && (!r.ssl.success || r.ssl.validDays < opts.sslWarnDays)) failing.push(EXIT.SSL);
    if (on('ports') && dangerousOpenPorts(r.ports).length > 0) failing.push(EXIT.PORTS);
    if (on('mail') && r.mail && (!r.mail.spf || !r.mail.dmarc)) failing.push(EXIT.MAIL);
    if (opts.minScore !== null && score < opts.minScore) failing.push(EXIT.MIN_SCORE);
    if (on('security') && r.http.success && r.http.headersPresentCount < r.http.maxHeaders) failing.push(EXIT.SECURITY);
    return worstExitCode(failing);
}

export function computeFindings(r: Partial, sslWarnDays = 30): Finding[] {
    const f: Finding[] = [];
    const add = (id: string, category: Finding['category'], severity: Finding['severity'], message: string) =>
        f.push({ id, category, severity, message });

    if (!r.dns.success) add('dns-failure', 'dns', 'error', `DNS lookup failed: ${r.dns.error}`);
    if (r.dns.success && r.dns.caa.length === 0 && r.dns.dnssec !== null) {
        add('no-caa', 'dns', 'note', 'Publish a CAA record to limit which certificate authorities may issue for this domain');
    }
    if (r.dns.dnssec === false) add('no-dnssec', 'dns', 'note', 'Enable DNSSEC so resolvers can detect forged DNS answers');

    const s = r.ssl;
    if (!s.success) {
        add('ssl-error', 'ssl', 'error', `SSL check failed: ${s.error}`);
    } else {
        if (s.validDays <= 0) add('ssl-expired', 'ssl', 'error', 'SSL certificate has expired; renew it now');
        else if (s.validDays < sslWarnDays) add('ssl-expiring', 'ssl', 'warning', `Renew SSL Certificate soon (expires in ${s.validDays} days)`);
        const legacy = [s.legacyTls.tls10 && 'TLS 1.0', s.legacyTls.tls11 && 'TLS 1.1'].filter(Boolean);
        if (legacy.length) add('legacy-tls', 'ssl', 'warning', `Disable ${legacy.join(' and ')} on the server; both are deprecated`);
    }

    const h = r.http;
    if (!h.success) {
        add('http-unreachable', 'http', 'error', `HTTP request failed: ${h.error}`);
    } else {
        if (h.status >= 400) add('http-status', 'http', 'error', `Site returned HTTP ${h.status} ${h.statusMessage}`.trim());
        if (h.compression === 'None') add('no-compression', 'performance', 'note', 'Enable Brotli or Gzip Compression');
        for (const hr of h.headerResults.filter(x => !x.present)) {
            add(`missing-${hr.key}`, 'security', 'warning', `Configure ${hr.name} (${hr.desc})`);
        }
        h.hsts?.issues.forEach((msg, i) => add(`hsts-weak-${i + 1}`, 'security', 'warning', msg));
        h.csp?.issues.forEach((msg, i) => add(`csp-weak-${i + 1}`, 'security', 'warning', msg));
    }

    for (const p of dangerousOpenPorts(r.ports)) {
        add(`open-port-${p.port}`, 'ports', 'error', `Port ${p.port} (${p.name}) is open to the internet; firewall it off`);
    }

    const m = r.mail;
    if (m) {
        const missing = [!m.spf && 'SPF', !m.dmarc && 'DMARC'].filter(Boolean);
        if (missing.length) add('mail-records-missing', 'mail', 'warning', `Publish ${missing.join(' and ')} records to stop email spoofing`);
        if (m.dmarcPolicy === 'none') {
            add('dmarc-policy-none', 'mail', 'warning', 'DMARC policy is p=none (monitor only); move to quarantine or reject');
        }
        if (m.spf && m.dkimSelectors.length === 0) {
            add('dkim-not-found', 'mail', 'note', 'No DKIM key found under common selectors (it may use a custom selector)');
        }
    }

    const sp = r.spider;
    if (sp && !sp.success) add('spider-failed', 'spider', 'warning', `Spider failed: ${sp.error}`);
    if (sp && sp.success) {
        const broken = sp.endpoints.filter(e => !(e.status >= 200 && e.status < 400));
        if (broken.length) add('spider-broken', 'spider', 'warning', `${broken.length} of ${sp.endpoints.length} sampled sitemap URLs failed`);
    }

    return f;
}
