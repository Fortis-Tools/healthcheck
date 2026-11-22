import net from 'node:net';
import type { PortResult, PortSpec } from '../types.js';

/** Ports with a known service name. `dangerous` means it should not be reachable from the internet. */
export const KNOWN_PORTS: Record<number, { name: string; dangerous: boolean }> = {
    21: { name: 'FTP', dangerous: true },
    22: { name: 'SSH', dangerous: true },
    23: { name: 'Telnet', dangerous: true },
    80: { name: 'HTTP', dangerous: false },
    443: { name: 'HTTPS', dangerous: false },
    445: { name: 'SMB', dangerous: true },
    1433: { name: 'MSSQL', dangerous: true },
    2375: { name: 'Docker API', dangerous: true },
    2376: { name: 'Docker TLS', dangerous: true },
    3306: { name: 'MySQL', dangerous: true },
    3389: { name: 'RDP', dangerous: true },
    5432: { name: 'PostgreSQL', dangerous: true },
    5900: { name: 'VNC', dangerous: true },
    6379: { name: 'Redis', dangerous: true },
    8080: { name: 'HTTP-Alt', dangerous: false },
    8443: { name: 'HTTPS-Alt', dangerous: false },
    9200: { name: 'Elasticsearch', dangerous: true },
    11211: { name: 'Memcached', dangerous: true },
    27017: { name: 'MongoDB', dangerous: true },
};

/** Scanned by a bare --ports. */
export const DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 27017, 6379, 9200, 11211, 2375];

export function portSpecs(ports: number[]): PortSpec[] {
    return ports.map(port => {
        const known = KNOWN_PORTS[port];
        return { port, name: known?.name ?? 'Custom', dangerous: known?.dangerous ?? false };
    });
}

export async function checkPorts(domain: string, ports: PortSpec[], timeoutMs = 2000): Promise<PortResult[]> {
    const host = domain.split(':')[0];
    return Promise.all(ports.map(p => new Promise<PortResult>(resolve => {
        const socket = new net.Socket();
        const done = (open: boolean) => {
            socket.destroy();
            resolve({ ...p, open });
        };
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => done(true));
        socket.on('timeout', () => done(false));
        socket.on('error', () => done(false));
        socket.connect(p.port, host);
    })));
}
