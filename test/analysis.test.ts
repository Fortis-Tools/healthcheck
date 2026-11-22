import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCsp, analyzeHsts } from '../src/checks/http.js';
import { checkMailSecurity, parseDmarcPolicy } from '../src/checks/mail.js';
import { buildQuery, countAnswers } from '../src/checks/dns.js';
import { classifyAuthError, splitHost } from '../src/checks/ssl.js';
import { portSpecs } from '../src/checks/ports.js';

test('HSTS: short max-age and bad preload are flagged', () => {
    assert.deepEqual(analyzeHsts('max-age=63072000; includeSubDomains; preload').issues, []);
    const weak = analyzeHsts('max-age=300');
    assert.equal(weak.maxAge, 300);
    assert.equal(weak.issues.length, 1);
    assert.match(analyzeHsts('max-age=31536000; preload').issues[0], /includeSubDomains/);
    assert.match(analyzeHsts('includeSubDomains').issues[0], /no max-age/);
});

test('CSP: unsafe-inline, unsafe-eval and wildcards are flagged', () => {
    assert.deepEqual(analyzeCsp("default-src 'self'").issues, []);
    const bad = analyzeCsp("script-src 'self' 'unsafe-inline' 'unsafe-eval' https:");
    assert.ok(bad.unsafeInline && bad.unsafeEval && bad.wildcardSource);
    // A nonce makes modern browsers ignore 'unsafe-inline'.
    assert.equal(analyzeCsp("script-src 'nonce-abc' 'unsafe-inline'").unsafeInline, false);
    // script-src falls back to default-src.
    assert.equal(analyzeCsp("default-src * ").wildcardSource, true);
    assert.match(analyzeCsp('frame-ancestors none').issues[0], /neither script-src nor default-src/);
});

test('DMARC policy is parsed', () => {
    assert.equal(parseDmarcPolicy('v=DMARC1; p=reject; rua=mailto:a@b.c'), 'reject');
    assert.equal(parseDmarcPolicy('v=DMARC1;p=None'), 'none');
    assert.equal(parseDmarcPolicy('v=DMARC1; sp=reject'), null);
});

test('mail check reads SPF, DMARC policy and DKIM selectors', async () => {
    const records: Record<string, string[][]> = {
        'example.test': [['v=spf1 include:_spf.google.com ~all']],
        '_dmarc.example.test': [['v=DMARC1; p=quarantine']],
        'google._domainkey.example.test': [['v=DKIM1; k=rsa; ', 'p=MIGf']],
    };
    const resolveTxt = async (name: string) => {
        if (records[name]) return records[name];
        throw Object.assign(new Error('nope'), { code: 'ENOTFOUND' });
    };
    const r = await checkMailSecurity('example.test', resolveTxt);
    assert.deepEqual(r, { spf: true, dmarc: true, dmarcPolicy: 'quarantine', dkimSelectors: ['google'], error: '' });
});

test('DNS query packet round-trips through the answer counter', () => {
    const q = buildQuery('example.com', 48, 0x1234);
    assert.equal(q.readUInt16BE(0), 0x1234);
    assert.equal(q.readUInt16BE(4), 1);
    // Fake response: the query with QR set, one answer pointing back at the question name.
    const answer = Buffer.alloc(12 + 4);
    answer.writeUInt16BE(0xc00c, 0);
    answer.writeUInt16BE(48, 2);
    answer.writeUInt16BE(1, 4);
    answer.writeUInt32BE(300, 6);
    answer.writeUInt16BE(4, 10);
    const questionEnd = q.length - 11; // strip the OPT record
    const res = Buffer.concat([q.subarray(0, questionEnd), answer]);
    res.writeUInt16BE(0x8180, 2);
    res.writeUInt16BE(1, 6);
    res.writeUInt16BE(0, 10);
    assert.equal(countAnswers(res, 48), 1);
    assert.equal(countAnswers(res, 1), 0);
    res.writeUInt16BE(0x8380, 2); // truncated
    assert.equal(countAnswers(res, 48), -1);
});

test('certificate errors are classified', () => {
    assert.equal(classifyAuthError('CERT_HAS_EXPIRED'), 'expired');
    assert.equal(classifyAuthError('UNABLE_TO_VERIFY_LEAF_SIGNATURE'), 'incomplete-chain');
    assert.equal(classifyAuthError('ERR_TLS_CERT_ALTNAME_INVALID'), 'hostname-mismatch');
    assert.equal(classifyAuthError('DEPTH_ZERO_SELF_SIGNED_CERT'), 'self-signed');
    assert.equal(classifyAuthError('SOMETHING_ELSE'), 'untrusted');
});

test('host and port are split', () => {
    assert.deepEqual(splitHost('example.com', 443), { host: 'example.com', port: 443 });
    assert.deepEqual(splitHost('example.com:8443', 443), { host: 'example.com', port: 8443 });
});

test('port specs name known ports and mark unknown ones safe', () => {
    assert.deepEqual(portSpecs([9200, 4000]), [
        { port: 9200, name: 'Elasticsearch', dangerous: true },
        { port: 4000, name: 'Custom', dangerous: false },
    ]);
});
