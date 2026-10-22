// Runs the deployable ldap-monitor.js once, unmodified, under the stub ThousandEyes runtime.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(new URL('../../ldap-monitor.js', import.meta.url));
const registerPath = fileURLToPath(new URL('./register-stub.js', import.meta.url));

/**
 * @typedef {object} ProbeResult
 * @property {'pass'|'fail'|'timeout'|'no-verdict'} verdict
 * @property {number|null} exitCode
 * @property {string|null} failure  message the script reported with "Test failed:"
 * @property {string} stdout
 * @property {string} stderr
 * @property {object[]} trace      stub events (connect, tx, rx, markers, credentials, ...)
 */

/**
 * @param {object} config  TE_STUB_CONFIG: { credentials, settings, routes, enforceSocketTimeout,
 *   stallCleanup, peerCertificate, failWrite }; see thousandeyes-stub.js
 * @param {{ timeLimitMs?: number, env?: Record<string, string> }} [options]  timeLimitMs: kill the
 *   run after this long, like the ThousandEyes transaction time limit; env: extra environment
 *   variables for the script, such as TZ
 * @returns {Promise<ProbeResult>}
 */
export async function runProbe(config, { timeLimitMs = 10_000, env = {} } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'ldap-monitor-probe-'));
  const tracePath = path.join(dir, 'trace.jsonl');
  try {
    const child = spawn(process.execPath, ['--import', registerPath, scriptPath], {
      env: { ...process.env, ...env, TE_STUB_CONFIG: JSON.stringify(config), TE_STUB_TRACE: tracePath },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });

    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeLimitMs);
    const exitCode = await new Promise((resolve) => child.on('close', resolve));
    clearTimeout(timer);

    const trace = existsSync(tracePath)
      ? readFileSync(tracePath, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line))
      : [];
    const failure = /^Test failed: (.*)$/m.exec(stderr)?.[1] ?? null;
    let verdict = 'no-verdict';
    if (timedOut) verdict = 'timeout';
    else if (exitCode !== 0) verdict = 'fail';
    else if (/LDAP Monitor: PASS/.test(stdout)) verdict = 'pass';

    return { verdict, exitCode, failure, stdout, stderr, trace };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Events of one type from a probe trace. */
export const eventsOf = (result, type) => result.trace.filter((e) => e.type === type);
