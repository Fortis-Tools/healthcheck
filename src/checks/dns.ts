import dns from 'node:dns/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import type { DnsResult } from '../types.js';

const DNSKEY = 48;

/** Builds a DNS query for `name`/`type` with the EDNS DO bit set, so signed zones return their keys. */
export function buildQuery(name: string, type: number, id = Math.floor(Math.random() * 0xffff)): Buffer {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(0x0100, 2); // recursion desired
    header.writeUInt16BE(1, 4); // one question
    header.writeUInt16BE(1, 10); // one additional record (OPT)

    const labels = name.replace(/\.$/, '').split('.').filter(Boolean);
    const qname = Buffer.concat([
        ...labels.map(l => Buffer.concat([Buffer.from([Buffer.byteLength(l)]), Buffer.from(l)])),
        Buffer.from([0]),
    ]);
    const question = Buffer.alloc(4);
    question.writeUInt16BE(type, 0);
    question.writeUInt16BE(1, 2); // class IN

    const opt = Buffer.alloc(11);
    opt.writeUInt8(0, 0); // root name
    opt.writeUInt16BE(41, 1); // OPT
    opt.writeUInt16BE(4096, 3); // UDP payload size
    opt.writeUInt32BE(0x00008000, 5); // ext rcode 0, version 0, DO bit
    opt.writeUInt16BE(0, 9); // no options

    return Buffer.concat([header, qname, question, opt]);
}

function skipName(buf: Buffer, offset: number): number {
    while (offset < buf.length) {
        const len = buf[offset];
        if (len === 0) return offset + 1;
        if ((len & 0xc0) === 0xc0) return offset + 2;
        offset += len + 1;
    }
    throw new Error('Malformed DNS name');
}

/** Counts answer records of `type` in a DNS response. Returns -1 when the response was truncated. */
export function countAnswers(buf: Buffer, type: number): number {
    if (buf.length < 12) throw new Error('Short DNS response');
    const flags = buf.readUInt16BE(2);
    const rcode = flags & 0x0f;
    if (flags & 0x0200) return -1; // TC: answer too big for UDP, so records exist
    if (rcode !== 0 && rcode !== 3) throw new Error(`DNS rcode ${rcode}`);

    const qdcount = buf.readUInt16BE(4);
    const ancount = buf.readUInt16BE(6);
    let offset = 12;
    for (let i = 0; i < qdcount; i++) offset = skipName(buf, offset) + 4;

    let count = 0;
    for (let i = 0; i < ancount; i++) {
        offset = skipName(buf, offset);
        const rrType = buf.readUInt16BE(offset);
        const rdlen = buf.readUInt16BE(offset + 8);
        if (rrType === type) count++;
        offset += 10 + rdlen;
    }
    return count;
}

function rawQuery(name: string, type: number, timeoutMs: number): Promise<Buffer> {
    const server = dns.getServers()[0];
    if (!server) return Promise.reject(new Error('No DNS server configured'));
    // getServers() returns "1.2.3.4", "1.2.3.4:53", "::1" or "[::1]:53".
    let host = server;
    let port = 53;
    const bracketed = server.match(/^\[(.+)\](?::(\d+))?$/);
    if (bracketed) {
        host = bracketed[1];
        if (bracketed[2]) port = Number(bracketed[2]);
    } else if (net.isIPv4(server.split(':')[0]) && server.includes(':')) {
        [host, port] = [server.split(':')[0], Number(server.split(':')[1])];
    }

    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
        const timer = setTimeout(() => {
            socket.close();
            reject(new Error('Timeout'));
        }, timeoutMs);
        socket.on('message', msg => {
            clearTimeout(timer);
            socket.close();
            resolve(msg);
        });
        socket.on('error', err => {
            clearTimeout(timer);
            socket.close();
            reject(err);
        });
        socket.send(buildQuery(name, type), port, host);
    });
}

async function checkDnssec(domain: string, timeoutMs: number): Promise<boolean | null> {
    try {
        const count = countAnswers(await rawQuery(domain, DNSKEY, timeoutMs), DNSKEY);
        return count !== 0;
    } catch {
        return null;
    }
}

async function checkCaa(domain: string): Promise<string[]> {
    try {
        const records = await dns.resolveCaa(domain);
        return records.map(r => {
            const tag = r.issue !== undefined ? 'issue' : r.issuewild !== undefined ? 'issuewild' : r.iodef !== undefined ? 'iodef' : 'other';
            const value = r.issue ?? r.issuewild ?? r.iodef ?? r.contactemail ?? r.contactphone ?? '';
            return `${tag} ${value}`.trim();
        });
    } catch {
        return [];
    }
}

export async function checkDNS(domain: string, timeoutMs = 5000): Promise<DnsResult> {
    const host = domain.split(':')[0];
    const start = performance.now();
    let ipv4 = 'N/A';
    let ipv6 = 'N/A';

    if (net.isIP(host)) {
        // An IP address (used by the tests and for direct checks) needs no lookup.
        if (net.isIPv4(host)) ipv4 = host;
        else ipv6 = host;
    } else {
        const [a, aaaa] = await Promise.allSettled([dns.resolve4(host), dns.resolve6(host)]);
        if (a.status === 'fulfilled' && a.value.length > 0) ipv4 = a.value[0];
        if (aaaa.status === 'fulfilled' && aaaa.value.length > 0) ipv6 = aaaa.value[0];
    }
    const latency = Math.round(performance.now() - start);
    const success = ipv4 !== 'N/A' || ipv6 !== 'N/A';

    const [caa, dnssec] = net.isIP(host) || !success
        ? [[], null]
        : await Promise.all([checkCaa(host), checkDnssec(host, Math.min(timeoutMs, 3000))]);

    return {
        success, ipv4, ipv6, latency,
        error: success ? undefined : 'No A or AAAA records found',
        score: success ? 10 : 0,
        caa,
        dnssec,
    };
}
