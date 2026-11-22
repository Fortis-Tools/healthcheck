import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import type { Options } from '../src/types.js';

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

export async function listen(server: http.Server | https.Server): Promise<string> {
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    return `127.0.0.1:${(server.address() as AddressInfo).port}`;
}

export async function httpServer(handler: Handler) {
    const server = http.createServer(handler);
    const host = await listen(server);
    return { host, close: () => new Promise<void>(r => server.close(() => r())) };
}

/** A self-signed certificate made with the openssl CLI, or null when openssl is not installed. */
export function selfSignedCert(): { key: string; cert: string } | null {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hc-cert-'));
    try {
        execFileSync('openssl', [
            'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
            '-subj', '/CN=localhost', '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem'),
        ], { stdio: 'ignore' });
        return { key: fs.readFileSync(path.join(dir, 'key.pem'), 'utf8'), cert: fs.readFileSync(path.join(dir, 'cert.pem'), 'utf8') };
    } catch {
        return null;
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

export async function httpsServer(handler: Handler, cert: { key: string; cert: string }) {
    const server = https.createServer(cert, handler);
    const host = await listen(server);
    return { host, close: () => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }) };
}

export const ALL_HEADERS: Record<string, string> = {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'self'",
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=()',
};

export function options(overrides: Partial<Options> = {}): Options {
    return {
        targets: [], format: 'text', discover: false, spider: false, mail: false, ports: null,
        minScore: null, sslWarnDays: 30, timeoutMs: 3000, failOn: ['dns', 'http', 'ssl', 'security'], watch: null,
        ...overrides,
    };
}
