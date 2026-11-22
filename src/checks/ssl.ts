import tls from 'node:tls';
import net from 'node:net';
import type { LegacyTls, SslResult } from '../types.js';

type FailReason = Extract<SslResult, { success: false }>['reason'];

export function splitHost(target: string, defaultPort: number): { host: string; port: number } {
    const m = target.match(/^(.*):(\d+)$/);
    if (m && !net.isIPv6(target)) return { host: m[1], port: Number(m[2]) };
    return { host: target, port: defaultPort };
}

export function classifyAuthError(code: string): FailReason {
    if (code === 'CERT_HAS_EXPIRED') return 'expired';
    if (code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || code === 'SELF_SIGNED_CERT_IN_CHAIN') return 'self-signed';
    if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' || code === 'UNABLE_TO_GET_ISSUER_CERT') {
        return 'incomplete-chain';
    }
    if (code === 'ERR_TLS_CERT_ALTNAME_INVALID' || /altname|hostname/i.test(code)) return 'hostname-mismatch';
    return 'untrusted';
}

const REASON_TEXT: Record<NonNullable<FailReason>, string> = {
    'hostname-mismatch': 'Certificate does not cover this hostname',
    'incomplete-chain': 'Incomplete certificate chain (intermediate certificate missing)',
    'expired': 'Certificate has expired',
    'self-signed': 'Self-signed certificate',
    'untrusted': 'Certificate is not trusted',
};

function parseSan(raw: string | undefined): string[] {
    if (!raw) return [];
    return raw.split(',').map(s => s.trim().replace(/^(DNS|IP Address):/, '')).filter(Boolean);
}

function chainLength(cert: tls.DetailedPeerCertificate): number {
    let length = 1;
    let current = cert;
    const seen = new Set<string>([cert.fingerprint256]);
    while (current.issuerCertificate && !seen.has(current.issuerCertificate.fingerprint256)) {
        current = current.issuerCertificate;
        seen.add(current.fingerprint256);
        length++;
    }
    return length;
}

/** Tries a handshake limited to one old protocol version. */
function probeVersion(host: string, port: number, version: 'TLSv1' | 'TLSv1.1', timeoutMs: number): Promise<boolean | null> {
    return new Promise(resolve => {
        let settled = false;
        const finish = (value: boolean | null) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(value);
        };
        const socket = tls.connect({
            host,
            port,
            servername: net.isIP(host) ? undefined : host,
            minVersion: version,
            maxVersion: version,
            // OpenSSL 3 refuses TLS 1.0/1.1 at the default security level; lower it for the probe only.
            ciphers: 'DEFAULT:@SECLEVEL=0',
            rejectUnauthorized: false,
        }, () => finish(true));
        socket.on('error', (err: NodeJS.ErrnoException) => {
            const text = `${err.code ?? ''} ${err.message}`;
            // The local OpenSSL can't speak this version at all, so the result says nothing about the server.
            finish(/NO_PROTOCOLS_AVAILABLE|no protocols available|UNSUPPORTED_PROTOCOL/i.test(text) ? null : false);
        });
        socket.setTimeout(timeoutMs, () => finish(null));
    });
}

export async function probeLegacyTls(host: string, port: number, timeoutMs: number): Promise<LegacyTls> {
    const [tls10, tls11] = await Promise.all([
        probeVersion(host, port, 'TLSv1', timeoutMs),
        probeVersion(host, port, 'TLSv1.1', timeoutMs),
    ]);
    return { tls10, tls11 };
}

export function checkSSL(target: string, opts: { timeoutMs?: number; warnDays?: number } = {}): Promise<SslResult> {
    const { timeoutMs = 5000, warnDays = 30 } = opts;
    const { host, port } = splitHost(target, 443);

    const handshake = new Promise<Omit<Extract<SslResult, { success: true }>, 'legacyTls'> | Extract<SslResult, { success: false }>>(resolve => {
        const socket = tls.connect({
            host,
            port,
            servername: net.isIP(host) ? undefined : host,
            // Verify by hand below so a failure can say *why* (expired, chain, hostname).
            rejectUnauthorized: false,
            ALPNProtocols: ['h2', 'http/1.1'],
        }, () => {
            const cert = socket.getPeerCertificate(true);
            if (!cert || Object.keys(cert).length === 0) {
                socket.end();
                resolve({ success: false, error: 'No certificate', score: 0 });
                return;
            }

            let authError = socket.authorized ? '' : String(socket.authorizationError || 'untrusted');
            if (!authError && !net.isIP(host)) {
                const identityError = tls.checkServerIdentity(host, cert);
                if (identityError) authError = 'ERR_TLS_CERT_ALTNAME_INVALID';
            }
            const san = parseSan(cert.subjectaltname);

            if (authError) {
                const reason = classifyAuthError(authError);
                let error = `${REASON_TEXT[reason!]} (${authError})`;
                if (reason === 'hostname-mismatch' && san.length) error += `. Certificate covers: ${san.slice(0, 5).join(', ')}${san.length > 5 ? ', …' : ''}`;
                socket.end();
                resolve({ success: false, error, reason, score: 0 });
                return;
            }

            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const validDays = Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
            const rawIssuer: string | string[] = cert.issuer.O || cert.issuer.CN || 'Unknown';
            const issuer = Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer;

            resolve({
                success: true,
                validDays,
                issuer,
                validFrom: validFrom.toISOString().split('T')[0],
                validTo: validTo.toISOString().split('T')[0],
                protocol: socket.getProtocol() || 'Unknown',
                cipher: socket.getCipher().name || 'Unknown',
                alpnProtocol: socket.alpnProtocol || 'http/1.1',
                san,
                chainLength: chainLength(cert),
                score: validDays > warnDays ? 10 : (validDays > 0 ? 5 : 0),
            });
            socket.end();
        });

        socket.on('error', (err: NodeJS.ErrnoException) => {
            const legacyOnly = /unsupported protocol|UNSUPPORTED_PROTOCOL/i.test(`${err.code ?? ''} ${err.message}`);
            resolve({
                success: false,
                error: legacyOnly ? 'Server only offers outdated TLS versions (TLS 1.0/1.1 or SSL)' : err.message.split('\n')[0],
                score: 0,
            });
        });
        socket.setTimeout(timeoutMs, () => {
            socket.destroy();
            resolve({ success: false, error: 'Timeout', score: 0 });
        });
    });

    return handshake.then(async result => {
        if (!result.success) return result;
        const legacyTls = await probeLegacyTls(host, port, Math.min(timeoutMs, 4000));
        return { ...result, legacyTls };
    });
}
