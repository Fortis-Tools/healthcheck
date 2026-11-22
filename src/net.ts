import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import { USER_AGENT } from './version.js';

export interface RequestOptions {
    timeoutMs?: number;
    /** Accept self-signed certificates. Only the test suite sets this. */
    insecure?: boolean;
}

export const errorMessage = (err: unknown, fallback = 'Unknown error') =>
    err instanceof Error && err.message ? err.message : fallback;

export function request(url: string, method: 'GET' | 'HEAD', opts: RequestOptions = {}): Promise<http.IncomingMessage> {
    const { timeoutMs = 5000, insecure = false } = opts;
    return new Promise((resolve, reject) => {
        const isHttps = new URL(url).protocol === 'https:';
        const client = isHttps ? https : http;
        const options: https.RequestOptions = { method, timeout: timeoutMs, headers: { 'User-Agent': USER_AGENT } };
        if (isHttps && insecure) options.rejectUnauthorized = false;
        const req = client.request(url, options, resolve);
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Timeout')));
        req.end();
    });
}

export async function fetchText(url: string, opts: RequestOptions = {}, maxRedirects = 3): Promise<string> {
    let current = url;
    for (let i = 0; i <= maxRedirects; i++) {
        const res = await request(current, 'GET', opts);
        const status = res.statusCode || 0;
        if (status >= 300 && status < 400 && res.headers.location) {
            res.resume();
            current = new URL(res.headers.location, current).href;
            continue;
        }
        if (status !== 200) {
            res.resume();
            throw new Error(`Status ${status}`);
        }
        res.setEncoding('utf8');
        let data = '';
        for await (const chunk of res) data += chunk;
        return data;
    }
    throw new Error('Too many redirects');
}
