// scripts/te-runtime-facts.js under the stub runtime. On a real agent it reports what the stub
// assumes; here it must report the stub's own behaviour, which shows each fact is measured.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startFakeLdap } from './support/fake-ldap-server.js';

const scriptPath = fileURLToPath(new URL('../scripts/te-runtime-facts.js', import.meta.url));
const registerPath = fileURLToPath(new URL('./support/register-stub.js', import.meta.url));

async function runFacts(config) {
  const child = spawn(process.execPath, ['--import', registerPath, scriptPath], {
    env: { ...process.env, TE_STUB_CONFIG: JSON.stringify(config) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 30_000);
  const exitCode = await new Promise((resolve) => child.on('close', resolve));
  clearTimeout(timer);
  const facts = {};
  for (const [, name, json] of stdout.matchAll(/^runtime-fact (\S+): (.*)$/gm)) facts[name] = JSON.parse(json);
  return { exitCode, facts, stdout, stderr };
}

describe('runtime facts script', () => {
  it('reports settings, markers, credentials, socket methods, read() at end of stream and setTimeout()', async () => {
    const server = await startFakeLdap();
    try {
      const { exitCode, facts, stderr } = await runFacts({
        settings: { url: 'ldap://ldap.test:389', timeout: 60 },
        routes: { 'ldap.test:389': `127.0.0.1:${server.port}` },
        enforceSocketTimeout: true,
      });
      assert.equal(exitCode, 0, stderr);

      assert.equal(facts.settings.timeout, 60);
      assert.equal(facts.settings.timeoutType, 'number');
      assert.equal(facts.settings.urlScheme, 'ldap');
      assert.deepEqual(facts.target, { parsed: true, tls: false, port: 389 });

      assert.equal(facts.markers.start.threw, false);
      assert.equal(facts.markers.restartAfterStop.threw, true);
      assert.equal(facts.markers.stopNeverStarted.threw, true);

      // The stub throws for a credential that is not associated with the test.
      assert.equal(facts.credentials.unassociated.threw, true);
      assert.match(facts.credentials.unassociated.error.message, /not associated/);

      assert.equal(facts.socket.methods.read, 'function');
      assert.equal(facts.socket.methods.setTimeout, 'function');
      assert.equal(facts.socket.methods.getPeerCertificate, 'undefined', 'plain sockets have no certificate');

      // The stub resolves read() with null once the server has closed the connection.
      assert.equal(facts['read-at-end'].reads[0].outcome, 'resolved');
      assert.equal(facts['read-at-end'].reads[0].value, 'null');

      // With enforceSocketTimeout the stub applies Node's idle timeout, in milliseconds:
      // setTimeout(2) rejects the idle read after about 2 ms.
      assert.equal(facts.setTimeout.argument, 2);
      assert.equal(facts.setTimeout.read.outcome, 'rejected');
      assert.equal(facts.setTimeout.read.error.code, 'ETIMEDOUT');
      assert.equal(facts.setTimeout.unit, 'milliseconds');

      assert.ok(facts.done);
    } finally {
      await server.close();
    }
  });

  it('reports a refused connection instead of failing', async () => {
    const { exitCode, facts } = await runFacts({ settings: { url: 'ldaps://ldap.test' } });
    assert.equal(exitCode, 0);
    assert.deepEqual(facts.target, { parsed: true, tls: true, port: 636 });
    assert.equal(facts['read-at-end-connect'].outcome, 'rejected');
    assert.equal(facts['read-at-end-connect'].error.code, 'ECONNREFUSED');
    assert.ok(facts.done);
  });
});
