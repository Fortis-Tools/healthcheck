import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_PORTS, portSpecs } from './checks/ports.js';
import { DEFAULT_FAIL_ON } from './score.js';
import type { FailCategory, Options, OutputFormat } from './types.js';

export class UsageError extends Error {
    name = 'UsageError';
}

export const FORMATS: OutputFormat[] = ['text', 'json', 'markdown', 'sarif', 'junit'];
export const FAIL_CATEGORIES: FailCategory[] = ['dns', 'http', 'ssl', 'security', 'ports', 'mail'];
export const CONFIG_FILE = 'healthcheck.json';
const DEFAULT_WATCH_SECONDS = 60;

/** Shape of healthcheck.json. Every key is optional; command-line flags win. */
export interface ConfigFile {
    domains?: string[];
    discover?: boolean;
    spider?: boolean;
    mail?: boolean;
    ports?: boolean | number[];
    minScore?: number;
    sslWarnDays?: number;
    timeout?: number;
    failOn?: FailCategory[];
    format?: OutputFormat;
    watch?: number;
}

export interface ParsedArgs {
    help: boolean;
    version: boolean;
    configPath: string | null;
    /** Only the options the user actually passed, so a config file can fill the rest. */
    cli: Partial<ConfigFile> & { targets: string[] };
}

export function normalizeTarget(raw: string): string {
    return raw.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
}

function parsePositiveInt(flag: string, value: string | undefined, { allowZero = false } = {}): number {
    if (value === undefined || !/^\d+$/.test(value)) throw new UsageError(`${flag} needs a whole number, got "${value ?? ''}"`);
    const n = Number(value);
    if (!allowZero && n === 0) throw new UsageError(`${flag} must be greater than 0`);
    return n;
}

export function parsePortList(value: string): number[] {
    const ports = value.split(',').map(p => p.trim()).filter(Boolean).map(p => parsePositiveInt('--ports', p));
    for (const p of ports) if (p > 65535) throw new UsageError(`--ports: ${p} is not a valid port`);
    return [...new Set(ports)];
}

export function parseFailOn(value: string): FailCategory[] {
    const list = value.split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    for (const v of list) {
        if (!FAIL_CATEGORIES.includes(v as FailCategory)) {
            throw new UsageError(`--fail-on: unknown category "${v}" (use ${FAIL_CATEGORIES.join(', ')})`);
        }
    }
    return list as FailCategory[];
}

function parseFormat(value: string | undefined): OutputFormat {
    if (!value || !FORMATS.includes(value as OutputFormat)) {
        throw new UsageError(`--format must be one of ${FORMATS.join(', ')}`);
    }
    return value as OutputFormat;
}

export function parseArgs(argv: string[]): ParsedArgs {
    const out: ParsedArgs = { help: false, version: false, configPath: null, cli: { targets: [] } };
    const cli = out.cli;

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (!arg.startsWith('-')) {
            cli.targets.push(normalizeTarget(arg));
            continue;
        }
        const eq = arg.indexOf('=');
        const flag = eq === -1 ? arg : arg.slice(0, eq);
        const inline = eq === -1 ? undefined : arg.slice(eq + 1);
        const next = () => {
            if (inline !== undefined) return inline;
            const v = argv[i + 1];
            if (v === undefined || v.startsWith('--')) throw new UsageError(`${flag} needs a value`);
            i++;
            return v;
        };
        /** For flags whose value is optional: take the next arg only if it looks like a value. */
        const optional = (pattern: RegExp) => {
            if (inline !== undefined) return inline;
            const v = argv[i + 1];
            if (v !== undefined && pattern.test(v)) {
                i++;
                return v;
            }
            return undefined;
        };

        switch (flag) {
            case '-h': case '--help': out.help = true; break;
            case '-v': case '--version': out.version = true; break;
            case '--json': cli.format = 'json'; break;
            case '--format': cli.format = parseFormat(next()); break;
            case '--discover': cli.discover = true; break;
            case '--spider': cli.spider = true; break;
            case '--mail': cli.mail = true; break;
            case '--ports': {
                const v = optional(/^\d+(,\d+)*$/);
                cli.ports = v === undefined ? true : parsePortList(v);
                break;
            }
            case '--min-score': {
                const n = parsePositiveInt(flag, next(), { allowZero: true });
                if (n > 10) throw new UsageError('--min-score must be between 0 and 10');
                cli.minScore = n;
                break;
            }
            case '--ssl-warn-days': cli.sslWarnDays = parsePositiveInt(flag, next(), { allowZero: true }); break;
            case '--timeout': cli.timeout = parsePositiveInt(flag, next()); break;
            case '--fail-on': cli.failOn = parseFailOn(next()); break;
            case '--watch': {
                const v = optional(/^\d+$/);
                cli.watch = v === undefined ? DEFAULT_WATCH_SECONDS : parsePositiveInt(flag, v);
                break;
            }
            case '--config': out.configPath = next(); break;
            default: throw new UsageError(`Unknown option: ${arg}`);
        }
    }
    return out;
}

export function validateConfig(raw: unknown, source: string): ConfigFile {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new UsageError(`${source}: expected a JSON object`);
    const c = raw as Record<string, unknown>;
    const fail = (msg: string) => { throw new UsageError(`${source}: ${msg}`); };
    const known = ['domains', 'discover', 'spider', 'mail', 'ports', 'minScore', 'sslWarnDays', 'timeout', 'failOn', 'format', 'watch', '$schema'];
    for (const key of Object.keys(c)) if (!known.includes(key)) fail(`unknown key "${key}"`);

    if (c.domains !== undefined && (!Array.isArray(c.domains) || c.domains.some(d => typeof d !== 'string'))) fail('"domains" must be a list of strings');
    for (const key of ['discover', 'spider', 'mail'] as const) {
        if (c[key] !== undefined && typeof c[key] !== 'boolean') fail(`"${key}" must be true or false`);
    }
    if (c.ports !== undefined && typeof c.ports !== 'boolean') {
        if (!Array.isArray(c.ports) || c.ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535)) fail('"ports" must be true, false or a list of port numbers');
    }
    for (const key of ['minScore', 'sslWarnDays', 'timeout', 'watch'] as const) {
        if (c[key] !== undefined && (!Number.isInteger(c[key]) || (c[key] as number) < 0)) fail(`"${key}" must be a whole number`);
    }
    if (typeof c.minScore === 'number' && c.minScore > 10) fail('"minScore" must be between 0 and 10');
    if (c.failOn !== undefined) {
        if (!Array.isArray(c.failOn)) fail('"failOn" must be a list');
        parseFailOn((c.failOn as string[]).join(','));
    }
    if (c.format !== undefined) parseFormat(c.format as string);

    return {
        ...(c as ConfigFile),
        domains: (c.domains as string[] | undefined)?.map(normalizeTarget),
    };
}

export function loadConfig(configPath: string): ConfigFile {
    let text: string;
    try {
        text = fs.readFileSync(configPath, 'utf8');
    } catch (e) {
        throw new UsageError(`Cannot read config file ${configPath}: ${(e as Error).message}`);
    }
    let raw: unknown;
    try {
        raw = JSON.parse(text);
    } catch (e) {
        throw new UsageError(`${configPath} is not valid JSON: ${(e as Error).message}`);
    }
    return validateConfig(raw, path.basename(configPath));
}

/** Combines config-file values with command-line values. Command-line values win. */
export function resolveOptions(cli: ParsedArgs['cli'], config: ConfigFile = {}): Options {
    const pick = <K extends keyof ConfigFile>(key: K): ConfigFile[K] => (cli[key] !== undefined ? cli[key] : config[key]);

    // A bare --ports keeps the port list from the config file when it has one.
    const portsSetting = cli.ports === true && Array.isArray(config.ports) ? config.ports : pick('ports');
    const ports = portsSetting === true
        ? portSpecs(DEFAULT_PORTS)
        : Array.isArray(portsSetting) ? portSpecs(portsSetting) : null;

    const format = pick('format') ?? 'text';
    const watch = pick('watch') || null;
    if (watch !== null && format !== 'text' && format !== 'json') {
        throw new UsageError('--watch works with text or json output only');
    }

    return {
        targets: cli.targets.length ? cli.targets : (config.domains ?? []),
        format,
        discover: pick('discover') ?? false,
        spider: pick('spider') ?? false,
        mail: pick('mail') ?? false,
        ports,
        minScore: pick('minScore') ?? null,
        sslWarnDays: pick('sslWarnDays') ?? 30,
        timeoutMs: pick('timeout') ?? 5000,
        failOn: pick('failOn') ?? DEFAULT_FAIL_ON,
        watch,
    };
}

/** Finds the config file to use: --config, else ./healthcheck.json when no domains were given. */
export function findConfig(parsed: ParsedArgs, cwd = process.cwd()): string | null {
    if (parsed.configPath) return parsed.configPath;
    if (parsed.cli.targets.length > 0) return null;
    const candidate = path.join(cwd, CONFIG_FILE);
    return fs.existsSync(candidate) ? candidate : null;
}
