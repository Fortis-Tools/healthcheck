import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_HEADERS, httpServer } from './helpers.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'index.js');

function run(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise(resolve => {
        const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, FORCE_COLOR: '0' } });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', d => (stdout += d));
        child.stderr.on('data', d => (stderr += d));
        child.on('close', code => resolve({ code, stdout, stderr }));
    });
}

test('--version prints the package version', async () => {
    const r = await run(['--version']);
    assert.equal(r.code, 0);
    assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('unknown options exit 5 with a message', async () => {
    const r = await run(['a.com', '--nope']);
    assert.equal(r.code, 5);
    assert.match(r.stderr, /Unknown option: --nope/);
});

test('--json against a local server; --fail-on decides the exit code', async () => {
    const srv = await httpServer((_req, res) => void res.writeHead(200, ALL_HEADERS).end('ok'));
    try {
        // No TLS on the test server, so SSL fails; only HTTP counts here.
        const ok = await run([srv.host, '--json', '--fail-on', 'http', '--timeout', '2000']);
        assert.equal(ok.code, 0, ok.stderr);
        const json = JSON.parse(ok.stdout);
        assert.equal(json.http.status, 200);
        assert.equal(json.http.headersPresentCount, 6);
        assert.equal('security' in json, false);

        const strict = await run([srv.host, '--json', '--timeout', '2000']);
        assert.equal(strict.code, 2); // default --fail-on includes ssl
    } finally {
        await srv.close();
    }
});
