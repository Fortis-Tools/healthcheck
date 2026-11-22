import { checkDNS } from './checks/dns.js';
import { checkSSL } from './checks/ssl.js';
import { checkHTTP } from './checks/http.js';
import { checkPorts } from './checks/ports.js';
import { checkMailSecurity } from './checks/mail.js';
import { spiderSitemap } from './checks/spider.js';
import { computeExitCode, computeFindings, computeScore } from './score.js';
import type { CheckResult, Options } from './types.js';

export async function runCheck(domain: string, opts: Options): Promise<CheckResult> {
    const requestOpts = { timeoutMs: opts.timeoutMs, insecure: opts.insecureHttp };
    const [dnsRes, sslRes] = await Promise.all([
        checkDNS(domain, opts.timeoutMs),
        checkSSL(domain, { timeoutMs: opts.timeoutMs, warnDays: opts.sslWarnDays }),
    ]);
    const httpRes = await checkHTTP(domain, sslRes.success ? sslRes.alpnProtocol : 'http/1.1', requestOpts);

    const [portsRes, mailRes, spiderRes] = await Promise.all([
        opts.ports ? checkPorts(domain, opts.ports, Math.min(opts.timeoutMs, 2000)) : null,
        opts.mail ? checkMailSecurity(domain) : null,
        opts.spider ? spiderSitemap(domain, requestOpts) : null,
    ]);

    const partial = {
        domain,
        checkedAt: new Date().toISOString(),
        dns: dnsRes, ssl: sslRes, http: httpRes,
        ports: portsRes, mail: mailRes, spider: spiderRes,
    };
    const score = computeScore(dnsRes, sslRes, httpRes, opts.sslWarnDays);
    return {
        ...partial,
        score,
        exitCode: computeExitCode(partial, score, opts),
        findings: computeFindings(partial, opts.sslWarnDays),
    };
}
