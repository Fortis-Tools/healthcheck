import { performance } from 'node:perf_hooks';
import { errorMessage, fetchText, request, type RequestOptions } from '../net.js';
import type { SpiderEndpoint, SpiderResult } from '../types.js';

export function extractLocs(xml: string): string[] {
    const urls: string[] = [];
    const regex = /<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*<\/loc>/gs;
    let match;
    while ((match = regex.exec(xml)) !== null) {
        urls.push(match[1].replace(/&amp;/g, '&'));
    }
    return urls;
}

export function shuffle<T>(items: T[]): T[] {
    const a = [...items];
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

export async function pingEndpoint(url: string, opts: RequestOptions = {}): Promise<SpiderEndpoint> {
    const start = performance.now();
    try {
        let res = await request(url, 'HEAD', opts);
        res.resume();
        // Some servers reject HEAD; fall back to GET so the endpoint isn't reported as broken.
        if (res.statusCode === 405 || res.statusCode === 501) {
            res = await request(url, 'GET', opts);
            res.resume();
        }
        return { url, status: res.statusCode || 0, latency: Math.round(performance.now() - start) };
    } catch (err) {
        return { url, status: 0, latency: 0, error: errorMessage(err) };
    }
}

export async function spiderSitemap(domain: string, opts: RequestOptions & { scheme?: 'http' | 'https' } = {}): Promise<SpiderResult> {
    const { scheme = 'https', ...requestOpts } = opts;
    try {
        const root = await fetchText(`${scheme}://${domain}/sitemap.xml`, requestOpts);
        let urls = extractLocs(root);

        // Sitemap index: follow up to 3 child sitemaps to collect page URLs.
        if (/<sitemapindex[\s>]/i.test(root)) {
            const children = await Promise.allSettled(urls.slice(0, 3).map(u => fetchText(u, requestOpts)));
            urls = children.flatMap(c => (c.status === 'fulfilled' ? extractLocs(c.value) : []));
        }

        if (urls.length === 0) return { success: false, error: 'No URLs found in sitemap' };

        const endpoints = await Promise.all(shuffle(urls).slice(0, 10).map(u => pingEndpoint(u, requestOpts)));
        return { success: true, totalUrls: urls.length, endpoints };
    } catch (e) {
        return { success: false, error: errorMessage(e, 'Failed to fetch sitemap') };
    }
}
