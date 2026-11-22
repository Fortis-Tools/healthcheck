export type OutputFormat = 'text' | 'json' | 'markdown' | 'sarif' | 'junit';

/** Checks that can be told to break the build through --fail-on. */
export type FailCategory = 'dns' | 'http' | 'ssl' | 'security' | 'ports' | 'mail';

export interface PortSpec {
    port: number;
    name: string;
    dangerous: boolean;
}

export interface Options {
    targets: string[];
    format: OutputFormat;
    discover: boolean;
    spider: boolean;
    mail: boolean;
    /** null when the port scan is off. */
    ports: PortSpec[] | null;
    minScore: number | null;
    sslWarnDays: number;
    timeoutMs: number;
    failOn: FailCategory[];
    /** Seconds between runs, or null for a single run. */
    watch: number | null;
    /** Accept self-signed certificates on HTTP requests. Used by the test suite only. */
    insecureHttp?: boolean;
}

export interface DnsResult {
    success: boolean;
    ipv4: string;
    ipv6: string;
    latency: number;
    error?: string;
    score: number;
    /** CAA records as "tag value", empty when none are published. */
    caa: string[];
    /** true when the zone publishes DNSKEY records, null when the lookup failed. */
    dnssec: boolean | null;
}

export interface LegacyTls {
    /** null when the probe could not tell (for example the local OpenSSL refuses the version). */
    tls10: boolean | null;
    tls11: boolean | null;
}

export type SslResult =
    | {
        success: true;
        validDays: number;
        issuer: string;
        validFrom: string;
        validTo: string;
        protocol: string;
        cipher: string;
        alpnProtocol: string;
        /** Names from the certificate's subjectAltName. */
        san: string[];
        /** Number of certificates the server sent, leaf included. */
        chainLength: number;
        legacyTls: LegacyTls;
        score: number;
    }
    | {
        success: false;
        error: string;
        /** Set when the certificate could be read but failed verification. */
        reason?: 'hostname-mismatch' | 'incomplete-chain' | 'expired' | 'self-signed' | 'untrusted';
        score: number;
    };

export interface HeaderResult {
    key: string;
    name: string;
    desc: string;
    present: boolean;
}

export interface HstsAnalysis {
    maxAge: number;
    includeSubDomains: boolean;
    preload: boolean;
    issues: string[];
}

export interface CspAnalysis {
    unsafeInline: boolean;
    unsafeEval: boolean;
    wildcardSource: boolean;
    issues: string[];
}

interface HttpCommon {
    headerResults: HeaderResult[];
    headersPresentCount: number;
    maxHeaders: number;
}

export type HttpResult =
    | (HttpCommon & {
        success: true;
        status: number;
        statusMessage: string;
        finalUrl: string;
        protocol: string;
        latency: number;
        redirects: number;
        contentLength: string;
        compression: string;
        techStack: string;
        waf: string;
        hsts: HstsAnalysis | null;
        csp: CspAnalysis | null;
        score: number;
    })
    | (HttpCommon & { success: false; error: string; score: number });

export interface PortResult extends PortSpec {
    open: boolean;
}

export interface MailResult {
    spf: boolean;
    dmarc: boolean;
    /** The DMARC p= value (none, quarantine, reject), or null when there is no record. */
    dmarcPolicy: string | null;
    /** Common DKIM selectors that returned a key. */
    dkimSelectors: string[];
    error: string;
}

export interface SpiderEndpoint {
    url: string;
    status: number;
    latency: number;
    error?: string;
}

export type SpiderResult =
    | { success: true; totalUrls: number; endpoints: SpiderEndpoint[] }
    | { success: false; error: string };

export interface CheckResult {
    domain: string;
    checkedAt: string;
    dns: DnsResult;
    ssl: SslResult;
    http: HttpResult;
    ports: PortResult[] | null;
    mail: MailResult | null;
    spider: SpiderResult | null;
    score: number;
    exitCode: number;
    findings: Finding[];
}

export type Severity = 'error' | 'warning' | 'note';

/** One problem or recommendation. Drives the text recommendations, SARIF and JUnit output. */
export interface Finding {
    id: string;
    category: FailCategory | 'performance' | 'spider';
    severity: Severity;
    message: string;
}
