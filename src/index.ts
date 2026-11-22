#!/usr/bin/env node

import process from 'node:process';
import chalk from 'chalk';
import ora from 'ora';
import { errorMessage } from './net.js';
import { UsageError, findConfig, loadConfig, parseArgs, resolveOptions } from './options.js';
import { formatResults } from './formats.js';
import { renderComparisonTable, renderReport, renderWatchLine } from './render.js';
import { runCheck } from './runner.js';
import { EXIT, worstExitCode } from './score.js';
import { VERSION } from './version.js';
import type { CheckResult, Options } from './types.js';

const HELP = `
Usage: @fortis-tools/healthcheck [domain(s)] [options]

Output:
  --json                 Same as --format json
  --format <fmt>         text (default), json, markdown, sarif, junit
  --watch [seconds]      Re-check every N seconds (default 60); text or json (one line per result)

Checks:
  --discover             Detect Cloud Provider, Tech Stack, and WAF
  --spider               Fetch sitemap.xml and ping 10 random endpoints
  --ports [list]         Scan risky ports; pass a list to choose them (--ports 22,8080)
  --mail                 Check SPF, DMARC (and its policy) and common DKIM selectors

CI thresholds:
  --min-score <n>        Fail with exit 6 if the score is below n (0-10)
  --ssl-warn-days <n>    Treat a certificate as expiring this many days ahead (default 30)
  --timeout <ms>         Per-request timeout (default 5000)
  --fail-on <list>       Which checks set the exit code: dns,http,ssl,security,ports,mail
                         (default dns,http,ssl,security)

Config:
  --config <file>        Read domains and options from a JSON file.
                         With no domains given, ./healthcheck.json is used if it exists.

  --version, -v          Print the version
  --help, -h             Show this help menu

Exit codes:
  0 Healthy   1 Security warnings   2 SSL warnings   3 HTTP errors   4 DNS failure
  5 Internal or usage error   6 Score below --min-score
  7 Dangerous ports open (with --fail-on ports)   8 SPF/DMARC missing (with --fail-on mail)

Examples:
  @fortis-tools/healthcheck google.com
  @fortis-tools/healthcheck mysite.com --discover --ports --mail
  @fortis-tools/healthcheck mysite.com --ports 22,8080,9200
  @fortis-tools/healthcheck github.com --spider --json
  @fortis-tools/healthcheck mysite.com --format markdown > report.md
  @fortis-tools/healthcheck mysite.com --min-score 8 --fail-on http,ssl
  @fortis-tools/healthcheck mysite.com --watch 30
`;

/**
 * ora divides by stdout.columns to count the lines it must clear. Some ptys (IDE and agent
 * terminals, some CI runners) report 0 columns, which makes that Infinity: ora then writes
 * "cursor up + clear line" forever and the buffered output grows by gigabytes.
 */
export const spinnerSafe = () => Boolean(process.stdout.isTTY && (process.stdout.columns ?? 0) > 0);

const checkAll = (opts: Options) => Promise.all(opts.targets.map(t => runCheck(t, opts)));

async function watch(opts: Options): Promise<never> {
    const previous = new Map<string, CheckResult>();
    process.on('SIGINT', () => process.exit(0));
    if (opts.format === 'text') {
        console.log(chalk.cyan(`Watching ${opts.targets.join(', ')} every ${opts.watch}s. Ctrl+C to stop.\n`));
    }
    while (true) {
        const results = await checkAll(opts);
        for (const r of results) {
            console.log(opts.format === 'json' ? JSON.stringify(r) : renderWatchLine(r, previous.get(r.domain)));
            previous.set(r.domain, r);
        }
        await new Promise(resolve => setTimeout(resolve, opts.watch! * 1000));
    }
}

async function main() {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.version) {
        console.log(VERSION);
        process.exit(0);
    }
    const configPath = findConfig(parsed);
    const opts = resolveOptions(parsed.cli, configPath ? loadConfig(configPath) : {});

    if (parsed.help || opts.targets.length === 0) {
        console.log(HELP);
        process.exit(0);
    }

    if (opts.watch) await watch(opts);

    if (opts.format !== 'text') {
        const results = await checkAll(opts);
        process.stdout.write(formatResults(opts.format, results));
        process.exit(worstExitCode(results.map(r => r.exitCode)));
    }

    const interactive = process.stdout.isTTY;
    if (interactive) console.clear();
    const label = opts.targets.length > 1 ? 'Scanning multiple domains...' : `Running diagnostics for ${chalk.cyan(opts.targets[0])}...`;
    const spinner = ora({ text: label, isEnabled: spinnerSafe() }).start();
    const results = await checkAll(opts);
    spinner.stop();
    if (interactive) console.clear();

    console.log(results.length > 1 ? renderComparisonTable(results, opts) : renderReport(results[0], opts));
    process.exit(worstExitCode(results.map(r => r.exitCode)));
}

main().catch((err) => {
    if (err instanceof UsageError) {
        console.error(chalk.red(`healthcheck: ${err.message}`));
        console.error('Run with --help to see the options.');
    } else {
        console.error(chalk.red(`healthcheck crashed: ${errorMessage(err)}`));
    }
    process.exit(EXIT.INTERNAL);
});
