// Behaviour of ldap-monitor.js against a scripted LDAP server.
//
// Plain `it` tests pin down behaviour that is correct today. Tests marked `todo` describe the
// correct behaviour for a known bug (IDs from the audit) and are expected to fail until it is
// fixed; `node --test` reports them without failing the run. Remove `todo` when fixing a bug.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TAG, ldap } from './support/ber.js';
import { startFakeLdap } from './support/fake-ldap-server.js';
import { eventsOf, runProbe } from './support/run-probe.js';
import { createTlsFixture } from './support/tls-fixture.js';

const DN = 'cn=monitor,ou=svc,dc=example,dc=com';
const PASSWORD = 'not-a-real-secret';
const HOST = 'ldap.test';

const bindOk = () => [ldap.bindResponse(1, 0)];
const entry = (size = 300) => ldap.searchEntry(2, DN, { cn: ['monitor'], description: ['x'.repeat(size)] });

/**
 * Start a fake server for `scenario`, run the script against it once, then stop the server.
 * `credentials` are merged over a working default set; `settings` feed test.getSettings().
 */
async function probe(scenario, { credentials = {}, settings, tls, routes, timeLimitMs, enforceSocketTimeout } = {}) {
  const server = await startFakeLdap({ ...scenario, tls });
  const port = tls ? 636 : 389;
  try {
    const result = await runProbe({
      credentials: {
        ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: HOST, ldapPort: String(port), ...credentials,
      },
      settings,
      enforceSocketTimeout,
      routes: { [`${HOST}:${port}`]: `127.0.0.1:${server.port}`, ...routes?.(server.port) },
    }, { timeLimitMs });
    return { ...result, requests: server.requests };
  } finally {
    await server.close();
  }
}

const requestsOf = (result, opTag) => result.requests.filter((r) => r.opTag === opTag);

describe('configuration checks', () => {
  it('fails before connecting when the bind credentials are missing', async () => {
    const result = await runProbe({ credentials: { ldapHost: HOST, ldapPort: '389' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Missing credentials/);
    assert.equal(eventsOf(result, 'connect').length, 0);
  });

  it('refuses an empty password instead of sending an unauthenticated bind (RFC 4513 5.1.2)', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: '', ldapHost: HOST, ldapPort: '389' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Missing credentials/);
    assert.equal(eventsOf(result, 'connect').length, 0);
  });

  it('rejects ports other than 389 and 636', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: HOST, ldapPort: '1389' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Invalid port 1389/);
  });

  it('targets the host and port from the test URL (B4)', { todo: 'B4: host/port come from credentials only' }, async () => {
    const server = await startFakeLdap({ bind: bindOk });
    try {
      const result = await runProbe({
        credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapBindOnly: 'true' },
        settings: { url: 'ldap://ldap-b.test:389' },
        routes: { 'ldap-b.test:389': `127.0.0.1:${server.port}` },
      });
      assert.equal(result.verdict, 'pass');
    } finally {
      await server.close();
    }
  });

  it('converts the test timeout from seconds to milliseconds (B7)', { todo: 'B7: seconds used as milliseconds' }, async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' }, settings: { timeout: 30 } });
    assert.deepEqual(eventsOf(result, 'setTimeout').map((e) => e.value), [30_000]);
  });
});

describe('bind', () => {
  it('sends an RFC 4511 simple BindRequest with messageID 1', async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    const [bindReq] = requestsOf(result, TAG.bindRequest);
    assert.equal(bindReq.messageId, 1);
    assert.equal(bindReq.version, 3);
    assert.equal(bindReq.name, DN);
    assert.equal(bindReq.authTag, 0x80);
    assert.equal(bindReq.password, PASSWORD);
  });

  it('passes in bind-only mode when the bind succeeds', async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.equal(result.verdict, 'pass');
    assert.match(result.stdout, /PASS \(Bind-Only\)/);
    assert.equal(requestsOf(result, TAG.searchRequest).length, 0);
  });

  it('records connect and bind markers, each started and stopped once', async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.deepEqual(eventsOf(result, 'marker.start').map((e) => e.name), ['ldap-attempt-1', 'ldap-tcp-connect', 'ldap-bind']);
    assert.equal(eventsOf(result, 'marker.stop').length, 3);
    assert.equal(eventsOf(result, 'marker.error').length, 0);
  });

  for (const [code, name] of [[49, 'invalidCredentials'], [13, 'confidentialityRequired'], [8, 'strongerAuthRequired']]) {
    it(`fails with ${name} (${code}) from a short-form BindResponse`, async () => {
      const result = await probe({ bind: () => [ldap.bindResponse(1, code)] }, { credentials: { ldapBindOnly: 'true' } });
      assert.equal(result.verdict, 'fail');
      assert.match(result.failure, new RegExp(`${name} \\(${code}/`));
    });
  }

  it('fails on invalidCredentials from a BindResponse with long-form lengths (B1)', { todo: 'B1: result code read at a fixed offset' }, async () => {
    const result = await probe(
      { bind: () => [ldap.bindResponse(1, 49, { diagnostic: 'data 52e', longForm: true })] },
      { credentials: { ldapBindOnly: 'true' } },
    );
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /invalidCredentials/);
  });

  it('includes the server diagnosticMessage in the failure (B21)', { todo: 'B21: diagnosticMessage not surfaced' }, async () => {
    const result = await probe(
      { bind: () => [ldap.bindResponse(1, 49, { diagnostic: 'AcceptSecurityContext error, data 52e' })] },
      { credentials: { ldapBindOnly: 'true' } },
    );
    assert.match(result.failure, /data 52e/);
  });

  it('handles a BindResponse split across TCP segments (B15)', { todo: 'B15: single read() for the bind' }, async () => {
    const response = ldap.bindResponse(1, 0);
    const result = await probe(
      { bind: () => [response.subarray(0, 4), { waitMs: 50 }, response.subarray(4)] },
      { credentials: { ldapBindOnly: 'true' } },
    );
    assert.equal(result.verdict, 'pass');
  });
});

describe('search', () => {
  it('passes when the server returns an entry and SearchResultDone (success)', async () => {
    const result = await probe({ bind: bindOk, search: () => [entry(), ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass');
  });

  it('sends a base-scope (objectClass=*) search on the bind DN with messageID 2', async () => {
    const result = await probe({ bind: bindOk, search: () => [entry(), ldap.searchDone(2, 0)] });
    const [searchReq] = requestsOf(result, TAG.searchRequest);
    assert.equal(searchReq.messageId, 2);
    assert.equal(searchReq.baseObject, DN);
    assert.equal(searchReq.scope.value, 0);
    assert.equal(searchReq.filterTag, 0x87);
  });

  it('does not attribute a normal pass to "response corruption" (B2/S1)', { todo: 'B2: verdict comes from a fixed offset plus a corruption heuristic' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [entry(), ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass');
    assert.doesNotMatch(result.stdout, /corrupt/i);
  });

  it('passes when SearchResultDone (success) arrives without entries (B2)', { todo: 'B2: reports "Operations error"' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass');
  });

  it('passes when a short entry and SearchResultDone share one segment (B2)', { todo: 'B2: reports "Unexpected response type"' }, async () => {
    const result = await probe({
      bind: bindOk,
      search: () => [Buffer.concat([ldap.searchEntry(2, DN, { cn: ['monitor'] }), ldap.searchDone(2, 0)])],
    });
    assert.equal(result.verdict, 'pass');
  });

  it('fails when SearchResultDone after an entry carries an error (B2/B3)', { todo: 'B3: stops reading after the first PDU' }, async () => {
    const result = await probe({
      bind: bindOk,
      search: () => [entry(), { waitMs: 50 }, ldap.searchDone(2, 11, { diagnostic: 'admin limit exceeded' })],
    });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /adminLimitExceeded/);
  });

  for (const [code, name] of [[51, 'busy'], [32, 'noSuchObject'], [50, 'insufficientAccessRights']]) {
    it(`reports ${name} (${code}) from SearchResultDone (B2)`, { todo: 'B2: every short Done is reported as "Operations error"' }, async () => {
      const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, code)] });
      assert.equal(result.verdict, 'fail');
      assert.match(result.failure, new RegExp(name));
    });
  }

  it('reports a Notice of Disconnection as such (B2/B14)', { todo: 'B2: messageID 0 / ExtendedResponse not handled' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.noticeOfDisconnection(52, 'shutting down'), { close: true }] });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /disconnect|unavailable/i);
  });

  it('fails a search slower than slowMs on every response path (B6)', { todo: 'B6: some success paths skip the threshold' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [{ waitMs: 400 }, entry(), ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Slow search/);
  });

  it('encodes scope and derefAliases as ENUMERATED (RFC 4511 4.5.1) (B14)', { todo: 'B14: sent as INTEGER' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, 0)] });
    const [searchReq] = requestsOf(result, TAG.searchRequest);
    assert.equal(searchReq.scope.tag, TAG.enumerated);
    assert.equal(searchReq.derefAliases.tag, TAG.enumerated);
  });

  it('requests no attributes ("1.1") so no entry data is returned (B16/S3)', { todo: 'B16: empty list requests all user attributes' }, async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, 0)] });
    const [searchReq] = requestsOf(result, TAG.searchRequest);
    assert.deepEqual(searchReq.attributes, ['1.1']);
  });

  it('uses ldapBaseDN as the search base when it is set (B17)', { todo: 'B17: ldapBaseDN is read but never used' }, async () => {
    const result = await probe(
      { bind: bindOk, search: () => [ldap.searchDone(2, 0)] },
      { credentials: { ldapBaseDN: 'dc=example,dc=com' } },
    );
    const [searchReq] = requestsOf(result, TAG.searchRequest);
    assert.equal(searchReq.baseObject, 'dc=example,dc=com');
  });

  it('sends an UnbindRequest before closing (RFC 4511 4.3) (B26)', { todo: 'B26: no UnbindRequest' }, async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.equal(requestsOf(result, TAG.unbindRequest).length, 1);
  });
});

describe('connection failures', () => {
  it('fails after three attempts when the connection is refused', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Connection failed after 3 attempts/);
  });

  it('includes the network error in the failure (B13)', { todo: 'B13: cause is dropped' }, async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.match(result.failure, /ECONNREFUSED/);
  });

  it('retries without restarting markers that were already used (B12)', { todo: 'B12: retry restarts the connect marker, which ThousandEyes rejects' }, async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.equal(eventsOf(result, 'marker.error').length, 0);
  });

  it('fails a connect that never completes before the test time limit (B11)', { todo: 'B11: no connect timeout' }, async () => {
    const result = await runProbe(
      {
        credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: HOST, ldapPort: '389' },
        settings: { timeout: 1 },
        routes: { [`${HOST}:389`]: 'hang' },
      },
      { timeLimitMs: 5_000 },
    );
    assert.equal(result.verdict, 'fail');
  });

  it('fails a bind that never gets a response once the socket timeout expires', async () => {
    const result = await probe(
      { bind: () => [] },
      { credentials: { ldapBindOnly: 'true' }, settings: { timeout: 1 }, enforceSocketTimeout: true, timeLimitMs: 5_000 },
    );
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /timed out/i);
  });
});

describe('LDAPS', () => {
  // Built while the suite is defined, so `skip` below can see whether openssl worked.
  const fixture = createTlsFixture(['DNS:ldap.test', 'IP:127.0.0.1']);
  const skip = () => (fixture ? false : 'openssl is not available');
  const tlsProbe = (scenario, opts = {}) =>
    probe(scenario, { tls: { key: fixture.key, cert: fixture.cert }, ...opts });
  const caBase64 = () => Buffer.from(fixture.caPem).toString('base64');

  it('passes with a trusted CA and matching hostname, using TLS 1.2+ with verification', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true', ldapCaBase64: caBase64() } });
    assert.equal(result.verdict, 'pass');
    const [connect] = eventsOf(result, 'connectTls');
    assert.equal(connect.options.minVersion, 'TLSv1.2');
    assert.equal(connect.options.rejectUnauthorized, true);
    assert.equal(connect.options.servername, HOST);
  });

  it('fails when the certificate is not trusted', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.equal(result.verdict, 'fail');
    // The final message is "Connection failed after 3 attempts": the retry trips over its own
    // marker (B12) before reaching the TLS-specific message, so only the first attempt says why.
    assert.match(result.stdout, /Certificate\/TLS error on attempt 1/);
  });

  it('fails when the certificate does not match the hostname', { skip: skip() }, async () => {
    const result = await tlsProbe(
      { bind: bindOk },
      {
        credentials: { ldapBindOnly: 'true', ldapCaBase64: caBase64(), ldapHost: 'other.test' },
        routes: (port) => ({ 'other.test:636': `127.0.0.1:${port}` }),
      },
    );
    assert.equal(result.verdict, 'fail');
  });

  it('includes the TLS verification error in the failure (B13)', { skip: skip(), todo: 'B13: cause is dropped' }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.match(result.failure, /self[- ]signed|unable to verify|UNABLE_TO_VERIFY/i);
  });

  it('accepts a CA certificate stored as PEM text (B22)', { skip: skip(), todo: 'B22: only base64-of-PEM is accepted' }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true', ldapCaBase64: fixture.caPem } });
    assert.equal(result.verdict, 'pass');
  });

  it('connects to an IP address without setting it as SNI servername (B18)', { skip: skip(), todo: 'B18: IP servername throws on current Node' }, async () => {
    const result = await tlsProbe(
      { bind: bindOk },
      {
        credentials: { ldapBindOnly: 'true', ldapCaBase64: caBase64(), ldapHost: '127.0.0.1' },
        routes: (port) => ({ '127.0.0.1:636': `127.0.0.1:${port}` }),
      },
    );
    assert.equal(result.verdict, 'pass');
  });
});
