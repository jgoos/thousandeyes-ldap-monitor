// ldap-monitor.js against a real 389 Directory Server. Run with `npm run test:integration`,
// which starts the container and sets the LDAP_IT_* variables. Skipped when they are unset.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import { eventsOf, runProbe } from '../support/run-probe.js';

const env = process.env;
const configured = ['LDAP_IT_HOSTNAME', 'LDAP_IT_LDAP_PORT', 'LDAP_IT_LDAPS_PORT', 'LDAP_IT_CA_FILE',
  'LDAP_IT_BIND_DN', 'LDAP_IT_BIND_PASSWORD'].every((name) => env[name]);

describe('389 Directory Server', { skip: configured ? false : 'run via npm run test:integration' }, () => {
  const host = env.LDAP_IT_HOSTNAME;
  const routes = {
    [`${host}:389`]: `127.0.0.1:${env.LDAP_IT_LDAP_PORT}`,
    [`${host}:636`]: `127.0.0.1:${env.LDAP_IT_LDAPS_PORT}`,
  };
  const caBase64 = () => Buffer.from(readFileSync(env.LDAP_IT_CA_FILE)).toString('base64');
  const run = (credentials, settings) => runProbe({
    credentials: {
      ldapMonUser: env.LDAP_IT_BIND_DN, ldapMonPass: env.LDAP_IT_BIND_PASSWORD, ldapHost: host, ldapPort: '389',
      ldapAllowCleartext: 'true', ...credentials,
    },
    settings,
    routes,
  });

  it('passes a bind-only check over LDAP', async () => {
    const result = await run({ ldapBindOnly: 'true' });
    assert.equal(result.verdict, 'pass', result.failure ?? result.stdout);
  });

  it('fails with invalidCredentials for a wrong password', async () => {
    const result = await run({ ldapMonPass: 'wrong-password' });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /invalidCredentials/);
  });

  it('passes bind and search over LDAP', async () => {
    const result = await run({});
    assert.equal(result.verdict, 'pass', result.failure ?? result.stdout);
  });

  it('passes bind and search over LDAPS with the server CA', async () => {
    const result = await run({ ldapPort: '636', ldapCaBase64: caBase64() });
    assert.equal(result.verdict, 'pass', result.failure ?? result.stdout);
  });

  it('fails over LDAPS when the server CA is not trusted', async () => {
    const result = await run({ ldapPort: '636', ldapBindOnly: 'true' });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /^TLS handshake with .* failed: .*(self[- ]signed|unable to verify)/i);
  });

  it('searches the base DN given in an ldaps:// test URL', async () => {
    const result = await run({ ldapCaBase64: caBase64() }, { url: `ldaps://${host}/dc=example,dc=com` });
    assert.equal(result.verdict, 'pass', result.failure ?? result.stdout);
  });

  it('reports noSuchObject with the matched DN for a missing base DN', async () => {
    const result = await run({ ldapCaBase64: caBase64() }, { url: `ldaps://${host}/ou=missing,dc=example,dc=com` });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /^Search failed: noSuchObject \(32\/0x20\).*matchedDN: "dc=example,dc=com"/);
  });

  it('refuses a cleartext bind unless ldapAllowCleartext is set', async () => {
    const result = await run({ ldapAllowCleartext: '' });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /^Configuration error: refusing to send the bind password/);
  });

  it('reaches a search pass without the "response corruption" fallback (B2/S1)', async () => {
    const result = await run({});
    assert.equal(result.verdict, 'pass');
    assert.doesNotMatch(result.stdout, /corrupt/i);
  });

  it('does not receive the account password hash in the search response (S3)', async () => {
    const result = await run({});
    const received = eventsOf(result, 'rx').map((e) => Buffer.from(e.hex, 'hex').toString('latin1')).join('');
    assert.doesNotMatch(received, /userPassword/i);
  });
});
