import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHTTP } from '../src/checks/http.js';
import { pingEndpoint, spiderSitemap } from '../src/checks/spider.js';
import { ALL_HEADERS, httpServer, httpsServer, selfSignedCert } from './helpers.js';

test('follows redirects and reports the final URL', async () => {
    const srv = await httpServer((req, res) => {
        if (req.url === '/') return void res.writeHead(301, { location: '/a' }).end();
        if (req.url === '/a') return void res.writeHead(302, { location: '/b' }).end();
        res.writeHead(200, ALL_HEADERS).end('ok');
    });
    try {
        const r = await checkHTTP(srv.host, 'http/1.1');
        assert.ok(r.success);
        assert.equal(r.status, 200);
        assert.equal(r.redirects, 2);
        assert.equal(r.finalUrl, `http://${srv.host}/b`);
        assert.equal(r.headersPresentCount, 6);
        assert.equal(r.hsts?.maxAge, 31536000);
        assert.deepEqual(r.hsts?.issues, []);
    } finally {
        await srv.close();
    }
});

test('counts missing security headers and detects compression and WAF', async () => {
    const srv = await httpServer((_req, res) => {
        res.writeHead(200, { 'x-frame-options': 'DENY', 'content-encoding': 'gzip', 'cf-ray': 'abc', server: 'nginx' }).end();
    });
    try {
        const r = await checkHTTP(srv.host, 'h2');
        assert.ok(r.success);
        assert.equal(r.headersPresentCount, 1);
        assert.equal(r.compression, 'Gzip');
        assert.equal(r.waf, 'Cloudflare');
        assert.equal(r.techStack, 'nginx');
        assert.equal(r.protocol, 'HTTP/2');
        assert.equal(r.hsts, null);
    } finally {
        await srv.close();
    }
});

test('gives up after too many redirects', async () => {
    const srv = await httpServer((_req, res) => void res.writeHead(302, { location: '/' }).end());
    try {
        const r = await checkHTTP(srv.host, 'http/1.1');
        assert.equal(r.success, false);
        assert.ok(!r.success && r.error === 'Too many redirects');
    } finally {
        await srv.close();
    }
});

test('falls back to HTTPS when plain HTTP fails to connect', async (t) => {
    const cert = selfSignedCert();
    if (!cert) return t.skip('openssl not installed');
    const srv = await httpsServer((_req, res) => void res.writeHead(200, ALL_HEADERS).end('secure'), cert);
    try {
        const r = await checkHTTP(srv.host, 'http/1.1', { insecure: true, timeoutMs: 3000 });
        assert.ok(r.success, !r.success ? r.error : '');
        assert.equal(r.finalUrl, `https://${srv.host}`);
        assert.equal(r.status, 200);
    } finally {
        await srv.close();
    }
});

test('reports a connection failure when nothing is listening', async () => {
    const srv = await httpServer(() => {});
    const host = srv.host;
    await srv.close();
    const r = await checkHTTP(host, 'http/1.1', { timeoutMs: 1000 });
    assert.equal(r.success, false);
});

test('spider falls back to GET when HEAD is rejected', async () => {
    const srv = await httpServer((req, res) => {
        if (req.method === 'HEAD') return void res.writeHead(405).end();
        res.writeHead(200).end('ok');
    });
    try {
        const ep = await pingEndpoint(`http://${srv.host}/page`);
        assert.equal(ep.status, 200);
    } finally {
        await srv.close();
    }
});

test('spider follows a sitemap index into child sitemaps', async () => {
    let host = '';
    const srv = await httpServer((req, res) => {
        if (req.url === '/sitemap.xml') {
            return void res.writeHead(200).end(`<?xml version="1.0"?><sitemapindex><sitemap><loc>http://${host}/child.xml</loc></sitemap></sitemapindex>`);
        }
        if (req.url === '/child.xml') {
            return void res.writeHead(200).end(`<urlset><url><loc><![CDATA[http://${host}/a?x=1&amp;y=2]]></loc></url><url><loc>http://${host}/missing</loc></url></urlset>`);
        }
        if (req.url === '/a?x=1&y=2') return void res.writeHead(200).end();
        res.writeHead(404).end();
    });
    host = srv.host;
    try {
        const r = await spiderSitemap(host, { scheme: 'http' });
        assert.ok(r.success, !r.success ? r.error : '');
        assert.equal(r.totalUrls, 2);
        const statuses = r.endpoints.map(e => e.status).sort();
        assert.deepEqual(statuses, [200, 404]);
    } finally {
        await srv.close();
    }
});
