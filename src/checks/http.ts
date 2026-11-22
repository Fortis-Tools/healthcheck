import http from 'node:http';
import { performance } from 'node:perf_hooks';
import { URL } from 'node:url';
import { errorMessage, request, type RequestOptions } from '../net.js';
import type { CspAnalysis, HstsAnalysis, HttpResult } from '../types.js';

export const SECURITY_HEADERS = [
    { key: 'strict-transport-security', name: 'Strict-Transport-Security', desc: 'Forces HTTPS connections' },
    { key: 'x-frame-options', name: 'X-Frame-Options', desc: 'Prevents clickjacking attacks' },
    { key: 'x-content-type-options', name: 'X-Content-Type-Options', desc: 'Prevents MIME sniffing' },
    { key: 'content-security-policy', name: 'Content-Security-Policy', desc: 'Prevents XSS attacks' },
    { key: 'referrer-policy', name: 'Referrer-Policy', desc: 'Protects referral privacy' },
    { key: 'permissions-policy', name: 'Permissions-Policy', desc: 'Restricts browser features' },
];

const ONE_YEAR = 31536000;
const SIX_MONTHS = 15768000;

const firstValue = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

export function analyzeHsts(value: string): HstsAnalysis {
    const parts = value.split(';').map(p => p.trim().toLowerCase());
    const maxAgePart = parts.find(p => p.startsWith('max-age='));
    const maxAge = maxAgePart ? parseInt(maxAgePart.slice('max-age='.length).replace(/"/g, ''), 10) || 0 : 0;
    const includeSubDomains = parts.includes('includesubdomains');
    const preload = parts.includes('preload');

    const issues: string[] = [];
    if (!maxAgePart) issues.push('HSTS has no max-age, so browsers ignore it');
    else if (maxAge < SIX_MONTHS) issues.push(`HSTS max-age is ${maxAge}s; use at least 6 months (${SIX_MONTHS}), ideally 1 year`);
    if (preload && (!includeSubDomains || maxAge < ONE_YEAR)) {
        issues.push('HSTS preload needs includeSubDomains and max-age of at least 1 year to be accepted');
    }
    return { maxAge, includeSubDomains, preload, issues };
}

export function analyzeCsp(value: string): CspAnalysis {
    const directives = new Map<string, string[]>();
    for (const part of value.split(';')) {
        const [name, ...sources] = part.trim().split(/\s+/);
        if (name) directives.set(name.toLowerCase(), sources.map(s => s.toLowerCase()));
    }
    // script-src falls back to default-src when it is absent.
    const scriptSources = directives.get('script-src') ?? directives.get('default-src') ?? [];
    const hasNonceOrHash = scriptSources.some(s => s.startsWith("'nonce-") || s.startsWith("'sha"));
    // With a nonce or hash, CSP3 browsers ignore 'unsafe-inline', so it's only a fallback for old browsers.
    const unsafeInline = scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash;
    const unsafeEval = scriptSources.includes("'unsafe-eval'");
    const wildcardSource = scriptSources.some(s => s === '*' || s === 'http:' || s === 'https:' || s === 'data:');

    const issues: string[] = [];
    if (!directives.has('script-src') && !directives.has('default-src')) issues.push('CSP sets neither script-src nor default-src, so scripts are unrestricted');
    if (unsafeInline) issues.push("CSP allows 'unsafe-inline' scripts, which defeats most XSS protection");
    if (unsafeEval) issues.push("CSP allows 'unsafe-eval'");
    if (wildcardSource) issues.push('CSP allows scripts from any host (*, http:, https: or data:)');
    return { unsafeInline, unsafeEval, wildcardSource, issues };
}

export function detectWaf(headers: http.IncomingHttpHeaders): string {
    if (headers['cf-ray']) return 'Cloudflare';
    if (headers['x-amz-cf-id']) return 'AWS CloudFront';
    if (headers['x-vercel-id']) return 'Vercel';
    if (headers['x-fastly-request-id'] || headers['fastly-client-ip']) return 'Fastly';
    if (headers['x-azure-ref']) return 'Azure Front Door';
    if (headers['x-akamai-transformed'] || headers['akamai-grn']) return 'Akamai';
    return 'None Detected';
}

export async function checkHTTP(domain: string, alpnProtocol: string, opts: RequestOptions = {}): Promise<HttpResult> {
    const start = performance.now();
    const failed = (error: string): HttpResult => ({
        success: false, error, score: 0, headerResults: [], headersPresentCount: 0, maxHeaders: SECURITY_HEADERS.length,
    });

    let currentUrl = `http://${domain}`;
    let triedHttpsFallback = false;
    let redirects = 0;
    const maxRedirects = 5;

    while (redirects <= maxRedirects) {
        let res: http.IncomingMessage;
        try {
            res = await request(currentUrl, 'GET', opts);
        } catch (error) {
            // Port 80 closed or filtered on an HTTPS-only host: retry the first hop over HTTPS.
            if (redirects === 0 && !triedHttpsFallback && currentUrl.startsWith('http://')) {
                triedHttpsFallback = true;
                currentUrl = `https://${domain}`;
                continue;
            }
            return failed(errorMessage(error, 'Request failed'));
        }

        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
            res.resume();
            redirects++;
            currentUrl = new URL(res.headers.location, currentUrl).href;
            continue;
        }

        res.resume();
        const latency = Math.round(performance.now() - start);

        const headerResults = SECURITY_HEADERS.map(h => ({ ...h, present: !!res.headers[h.key] }));
        const headersPresentCount = headerResults.filter(h => h.present).length;

        const contentEncoding = firstValue(res.headers['content-encoding']) || '';
        let compression = 'None';
        if (contentEncoding.includes('br')) compression = 'Brotli';
        else if (contentEncoding.includes('zstd')) compression = 'Zstd';
        else if (contentEncoding.includes('gzip')) compression = 'Gzip';
        else if (contentEncoding.includes('deflate')) compression = 'Deflate';

        // Node's client speaks HTTP/1.1; ALPN tells us whether the server offers HTTP/2.
        const protocol = alpnProtocol === 'h2' ? 'HTTP/2' : `HTTP/${res.httpVersion}`;
        const techStack = firstValue(res.headers['x-powered-by']) || firstValue(res.headers['server']) || 'Unknown';

        const hstsHeader = firstValue(res.headers['strict-transport-security']);
        const cspHeader = firstValue(res.headers['content-security-policy']);
        const contentLength = res.headers['content-length'];

        return {
            success: true,
            status,
            statusMessage: res.statusMessage || '',
            finalUrl: currentUrl,
            protocol,
            latency,
            redirects,
            contentLength: contentLength ? Math.round(parseInt(contentLength, 10) / 1024) + ' KB' : 'Unknown',
            compression,
            headerResults,
            headersPresentCount,
            maxHeaders: SECURITY_HEADERS.length,
            techStack,
            waf: detectWaf(res.headers),
            hsts: hstsHeader ? analyzeHsts(hstsHeader) : null,
            csp: cspHeader ? analyzeCsp(cspHeader) : null,
            score: status < 400 ? 10 : 0,
        };
    }

    return failed('Too many redirects');
}
