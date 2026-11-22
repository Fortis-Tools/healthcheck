import dns from 'node:dns/promises';
import type { MailResult } from '../types.js';

/** Selectors used by the big mail providers and common defaults. DKIM has no discovery, so this is a guess list. */
export const DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim', 's1', 's2',
    'smtp', 'mandrill', 'mxvault', 'zoho', 'protonmail', 'fm1', 'everlytickey1',
];

type TxtResolver = (name: string) => Promise<string[][]>;

export function parseDmarcPolicy(record: string): string | null {
    const m = record.match(/(?:^|;)\s*p\s*=\s*([a-z]+)/i);
    return m ? m[1].toLowerCase() : null;
}

export async function checkMailSecurity(domain: string, resolveTxt: TxtResolver = dns.resolveTxt): Promise<MailResult> {
    const host = domain.split(':')[0];
    const lookup = async (name: string, marker: string, label: string): Promise<[string | null, string]> => {
        try {
            const records = (await resolveTxt(name)).map(r => r.join(''));
            return [records.find(r => r.includes(marker)) ?? null, ''];
        } catch (e) {
            const code = (e as NodeJS.ErrnoException).code;
            return [null, code === 'ENODATA' || code === 'ENOTFOUND' ? '' : `${label} lookup failed. `];
        }
    };

    const [[spf, spfErr], [dmarc, dmarcErr], dkimSelectors] = await Promise.all([
        lookup(host, 'v=spf1', 'SPF'),
        lookup('_dmarc.' + host, 'v=DMARC1', 'DMARC'),
        Promise.all(DKIM_SELECTORS.map(async sel => {
            try {
                const records = (await resolveTxt(`${sel}._domainkey.${host}`)).map(r => r.join(''));
                return records.some(r => /v=DKIM1|(^|;)\s*p=/i.test(r)) ? sel : null;
            } catch {
                return null;
            }
        })).then(found => found.filter((s): s is string => s !== null)),
    ]);

    return {
        spf: spf !== null,
        dmarc: dmarc !== null,
        dmarcPolicy: dmarc ? parseDmarcPolicy(dmarc) : null,
        dkimSelectors,
        error: (spfErr + dmarcErr).trim(),
    };
}
