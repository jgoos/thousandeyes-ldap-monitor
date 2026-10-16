// Behaviour of ldap-monitor.js against a scripted LDAP server.
//
// Plain `it` tests pin down behaviour that is correct today. Tests marked `todo` describe the
// correct behaviour for a known bug (IDs from the audit) and are expected to fail until it is
// fixed; `node --test` reports them without failing the run. Remove `todo` when fixing a bug.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TAG, ldap, tlv } from './support/ber.js';
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

  it('converts the test timeout from seconds to milliseconds (B7)', async () => {
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

  it('fails on invalidCredentials from a BindResponse with long-form lengths (B1)', async () => {
    const result = await probe(
      { bind: () => [ldap.bindResponse(1, 49, { diagnostic: 'data 52e', longForm: true })] },
      { credentials: { ldapBindOnly: 'true' } },
    );
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /invalidCredentials/);
  });

  it('includes the server diagnosticMessage in the failure (B21)', async () => {
    const result = await probe(
      { bind: () => [ldap.bindResponse(1, 49, { diagnostic: 'AcceptSecurityContext error, data 52e' })] },
      { credentials: { ldapBindOnly: 'true' } },
    );
    assert.match(result.failure, /data 52e/);
  });

  it('handles a BindResponse split across TCP segments (B15)', async () => {
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
    assert.equal(searchReq.derefAliases.value, 0);
    assert.equal(searchReq.sizeLimit, 1);
    assert.equal(searchReq.timeLimit, 5);
    assert.equal(searchReq.typesOnly, false);
    assert.equal(searchReq.filterTag, 0x87);
  });

  it('does not attribute a normal pass to "response corruption" (B2/S1)', async () => {
    const result = await probe({ bind: bindOk, search: () => [entry(), ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass');
    assert.doesNotMatch(result.stdout, /corrupt/i);
  });

  it('passes when SearchResultDone (success) arrives without entries (B2)', async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass');
  });

  it('passes when a short entry and SearchResultDone share one segment (B2)', async () => {
    const result = await probe({
      bind: bindOk,
      search: () => [Buffer.concat([ldap.searchEntry(2, DN, { cn: ['monitor'] }), ldap.searchDone(2, 0)])],
    });
    assert.equal(result.verdict, 'pass');
  });

  it('fails when SearchResultDone after an entry carries an error (B2/B3)', async () => {
    const result = await probe({
      bind: bindOk,
      search: () => [entry(), { waitMs: 50 }, ldap.searchDone(2, 11, { diagnostic: 'admin limit exceeded' })],
    });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /adminLimitExceeded/);
  });

  for (const [code, name] of [[51, 'busy'], [32, 'noSuchObject'], [50, 'insufficientAccessRights']]) {
    it(`reports ${name} (${code}) from SearchResultDone (B2)`, async () => {
      const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, code)] });
      assert.equal(result.verdict, 'fail');
      assert.match(result.failure, new RegExp(name));
    });
  }

  it('reports a Notice of Disconnection as such (B2)', async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.noticeOfDisconnection(52, 'shutting down'), { close: true }] });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /disconnect|unavailable/i);
  });

  it('fails a search slower than slowMs on every response path (B6)', async () => {
    const result = await probe({ bind: bindOk, search: () => [{ waitMs: 400 }, entry(), ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Slow search/);
  });

  it('encodes scope and derefAliases as ENUMERATED (RFC 4511 4.5.1) (B14)', async () => {
    const result = await probe({ bind: bindOk, search: () => [ldap.searchDone(2, 0)] });
    const [searchReq] = requestsOf(result, TAG.searchRequest);
    assert.equal(searchReq.scope.tag, TAG.enumerated);
    assert.equal(searchReq.derefAliases.tag, TAG.enumerated);
  });

  it('requests no attributes ("1.1") so no entry data is returned (B16/S3)', async () => {
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

  it('sends an UnbindRequest before closing (RFC 4511 4.3) (B26)', async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.equal(requestsOf(result, TAG.unbindRequest).length, 1);
  });
});

describe('response framing and decoding', () => {
  const bindOnly = { credentials: { ldapBindOnly: 'true' } };

  it('passes with valid credentials when every length uses the 4-byte long form', async () => {
    const longForm = { longForm: true };
    const result = await probe({
      bind: () => [ldap.bindResponse(1, 0, longForm)],
      search: () => [ldap.searchEntry(2, DN, {}, longForm), ldap.searchDone(2, 0, longForm)],
    });
    assert.equal(result.verdict, 'pass', result.failure ?? '');
  });

  it('reassembles a search response delivered in small segments', async () => {
    const response = Buffer.concat([entry(), ldap.searchDone(2, 0)]);
    const segments = [];
    for (let i = 0; i < response.length; i += 7) segments.push(response.subarray(i, i + 7), { waitMs: 1 });
    const result = await probe({ bind: bindOk, search: () => segments });
    assert.equal(result.verdict, 'pass', result.failure ?? '');
  });

  it('skips SearchResultReference and IntermediateResponse before SearchResultDone', async () => {
    const reference = ldap.message(2, tlv(0x73, tlv(0x04, Buffer.from('ldap://other.test/dc=example,dc=com'))));
    const intermediate = ldap.message(2, tlv(0x79, Buffer.alloc(0)));
    const result = await probe({ bind: bindOk, search: () => [reference, intermediate, ldap.searchDone(2, 0)] });
    assert.equal(result.verdict, 'pass', result.failure ?? '');
  });

  it('fails on a response for an unexpected message ID', async () => {
    const result = await probe({ bind: () => [ldap.bindResponse(7, 0)] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Bind failed: unexpected message ID 7/);
  });

  it('fails when the bind is answered with another operation', async () => {
    const result = await probe({ bind: () => [ldap.searchDone(1, 0)] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /expected a BindResponse/);
  });

  it('fails on indefinite-length BER, which LDAP does not allow', async () => {
    const result = await probe({ bind: () => [Buffer.from([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00])] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /indefinite-length/);
  });

  it('fails at once on a declared length above the response size limit', async () => {
    const result = await probe({ bind: () => [Buffer.from([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02])] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /exceeds the \d+-byte limit/);
  });

  it('fails on a reply that is not LDAP', async () => {
    const result = await probe({ bind: () => [Buffer.from('HTTP/1.1 400 Bad Request\r\n\r\n')] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /not LDAP/);
  });

  it('fails when the server closes the connection before SearchResultDone', async () => {
    const result = await probe({ bind: bindOk, search: () => [entry(), { close: true }] });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Search failed: connection closed by the server/);
  });

  it('names unknown result codes without guessing', async () => {
    const result = await probe({ bind: () => [ldap.bindResponse(1, 99)] }, bindOnly);
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Unknown LDAP result code 99 \(0x63\)/);
  });

  it('keeps the server diagnosticMessage on one line', async () => {
    const result = await probe({ bind: () => [ldap.bindResponse(1, 49, { diagnostic: 'line one\nline two' })] }, bindOnly);
    assert.match(result.failure, /server: "line one line two"/);
  });
});

describe('connection failures', () => {
  it('fails after three attempts when the connection is refused', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Connection failed after 3 attempts/);
  });

  it('includes the network error in the failure (B13)', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.match(result.failure, /ECONNREFUSED/);
  });

  it('retries without restarting markers that were already used (B12)', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.equal(eventsOf(result, 'marker.error').length, 0);
  });

  it('fails a connect that never completes before the test time limit (B11)', async () => {
    const result = await runProbe(
      {
        credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: HOST, ldapPort: '389' },
        settings: { timeout: 1 },
        routes: { [`${HOST}:389`]: 'hang' },
      },
      { timeLimitMs: 5_000 },
    );
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /Connection failed after 1 attempt: connect to ldap\.test:389 timed out after \d+ ms/);
  });

  it('records each attempt under its own marker and the connect marker once', async () => {
    const result = await runProbe({ credentials: { ldapMonUser: DN, ldapMonPass: PASSWORD, ldapHost: 'down.test', ldapPort: '389' } });
    assert.equal(eventsOf(result, 'connect').length, 3);
    assert.deepEqual(eventsOf(result, 'marker.start').map((e) => e.name),
      ['ldap-attempt-1', 'ldap-tcp-connect', 'ldap-attempt-2', 'ldap-attempt-3']);
    assert.equal(eventsOf(result, 'marker.stop').length, 4);
  });

  it('fails a stalled bind with a timeout error before the test time limit', async () => {
    const started = Date.now();
    const result = await probe({ bind: () => [] }, { credentials: { ldapBindOnly: 'true' }, settings: { timeout: 2 }, timeLimitMs: 5_000 });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /^Bind failed: waiting for the server response timed out after \d+ ms/);
    assert.ok(Date.now() - started < 2_000, 'the probe must give up before the 2 s time limit');
  });

  it('treats a timeout above the 180 s maximum as milliseconds', async () => {
    const result = await probe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' }, settings: { timeout: 45_000 } });
    assert.deepEqual(eventsOf(result, 'setTimeout').map((e) => e.value), [45_000]);
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
    assert.match(result.failure, /^TLS handshake with ldap\.test:636 failed: /);
    assert.match(result.failure, /provide it in the ldapCaBase64 credential/);
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

  it('includes the TLS verification error in the failure (B13)', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.match(result.failure, /self[- ]signed|unable to verify|UNABLE_TO_VERIFY/i);
  });

  it('accepts a CA certificate stored as PEM text (B22)', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true', ldapCaBase64: fixture.caPem } });
    assert.equal(result.verdict, 'pass');
  });

  it('connects to an IP address without setting it as SNI servername (B18)', { skip: skip() }, async () => {
    const result = await tlsProbe(
      { bind: bindOk },
      {
        credentials: { ldapBindOnly: 'true', ldapCaBase64: caBase64(), ldapHost: '127.0.0.1' },
        routes: (port) => ({ '127.0.0.1:636': `127.0.0.1:${port}` }),
      },
    );
    assert.equal(result.verdict, 'pass');
    assert.equal(eventsOf(result, 'connectTls')[0].options.servername, undefined);
  });

  it('does not retry a certificate verification failure', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true' } });
    assert.equal(eventsOf(result, 'connectTls').length, 1);
  });

  it('accepts PEM whose line breaks were flattened to spaces', { skip: skip() }, async () => {
    const flattened = fixture.caPem.replace(/\n/g, ' ');
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true', ldapCaBase64: flattened } });
    assert.equal(result.verdict, 'pass', result.failure ?? '');
  });

  it('reports a CA credential without a certificate as a configuration error, before connecting', { skip: skip() }, async () => {
    const result = await tlsProbe({ bind: bindOk }, { credentials: { ldapBindOnly: 'true', ldapCaBase64: 'bm90IGEgY2VydGlmaWNhdGU=' } });
    assert.equal(result.verdict, 'fail');
    assert.match(result.failure, /^Configuration error: ldapCaBase64 holds no certificate/);
    assert.equal(eventsOf(result, 'connectTls').length, 0);
  });
});
