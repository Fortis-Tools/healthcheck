import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { UsageError, findConfig, loadConfig, parseArgs, resolveOptions } from '../src/options.js';

test('targets are normalized', () => {
    assert.deepEqual(parseArgs(['https://Example.com/path', 'foo.dev']).cli.targets, ['example.com', 'foo.dev']);
});

test('--ports takes an optional list', () => {
    assert.equal(parseArgs(['a.com', '--ports']).cli.ports, true);
    assert.deepEqual(parseArgs(['--ports', '22,8080', 'a.com']).cli.ports, [22, 8080]);
    assert.deepEqual(parseArgs(['--ports=443']).cli.ports, [443]);
    // A domain after a bare --ports is not swallowed.
    assert.deepEqual(parseArgs(['--ports', 'a.com']).cli.targets, ['a.com']);
    assert.throws(() => parseArgs(['--ports', '70000']), UsageError);
});

test('threshold flags are parsed and validated', () => {
    const { cli } = parseArgs(['a.com', '--min-score', '8', '--ssl-warn-days=14', '--timeout', '2500', '--fail-on', 'http,ssl']);
    assert.equal(cli.minScore, 8);
    assert.equal(cli.sslWarnDays, 14);
    assert.equal(cli.timeout, 2500);
    assert.deepEqual(cli.failOn, ['http', 'ssl']);
    assert.throws(() => parseArgs(['--min-score', '11']), UsageError);
    assert.throws(() => parseArgs(['--fail-on', 'nope']), UsageError);
    assert.throws(() => parseArgs(['--timeout']), UsageError);
    assert.throws(() => parseArgs(['--bogus']), UsageError);
});

test('--json, --format and --watch', () => {
    assert.equal(parseArgs(['--json']).cli.format, 'json');
    assert.equal(parseArgs(['--format', 'sarif']).cli.format, 'sarif');
    assert.equal(parseArgs(['--watch']).cli.watch, 60);
    assert.equal(parseArgs(['--watch', '15', 'a.com']).cli.watch, 15);
    assert.throws(() => resolveOptions(parseArgs(['a.com', '--watch', '--format', 'junit']).cli), UsageError);
});

test('defaults match the old behaviour', () => {
    const o = resolveOptions(parseArgs(['a.com']).cli);
    assert.equal(o.format, 'text');
    assert.equal(o.ports, null);
    assert.equal(o.sslWarnDays, 30);
    assert.equal(o.timeoutMs, 5000);
    assert.deepEqual(o.failOn, ['dns', 'http', 'ssl', 'security']);
    assert.equal(resolveOptions(parseArgs(['a.com', '--ports']).cli).ports?.length, 10);
});

test('config file supplies domains and options; flags win', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hc-config-'));
    try {
        const file = path.join(dir, 'healthcheck.json');
        fs.writeFileSync(file, JSON.stringify({ domains: ['https://one.com', 'two.com'], mail: true, ports: [22], minScore: 7, failOn: ['http'] }));

        const bare = parseArgs([]);
        assert.equal(findConfig(bare, dir), file);
        const o = resolveOptions(bare.cli, loadConfig(file));
        assert.deepEqual(o.targets, ['one.com', 'two.com']);
        assert.equal(o.mail, true);
        assert.deepEqual(o.ports?.map(p => p.port), [22]);
        assert.equal(o.minScore, 7);

        const withFlags = parseArgs(['--min-score', '9', '--ports']);
        const o2 = resolveOptions(withFlags.cli, loadConfig(file));
        assert.equal(o2.minScore, 9);
        assert.deepEqual(o2.ports?.map(p => p.port), [22]);

        // Domains on the command line mean the config file is not picked up automatically.
        assert.equal(findConfig(parseArgs(['x.com']), dir), null);

        fs.writeFileSync(file, JSON.stringify({ domain: ['typo.com'] }));
        assert.throws(() => loadConfig(file), /unknown key "domain"/);
        fs.writeFileSync(file, '{ not json');
        assert.throws(() => loadConfig(file), /not valid JSON/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
