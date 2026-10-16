/**
 * ThousandEyes runtime facts: a diagnostic transaction script, not a monitor.
 *
 * Records how the ThousandEyes transaction runtime behaves where its documentation is silent, so
 * the assumptions in test/support/thousandeyes-stub.js can be checked on a real agent. Run it as
 * an instant test with an ldap:// or ldaps:// test URL (docs/REAL_AGENT_VALIDATION.md). It opens
 * two connections to that server and sends only an UnbindRequest: no bind, no credentials, and
 * no certificate check (it reports on the runtime, not on the server).
 *
 * Each fact is one console line, `runtime-fact <name>: <JSON>`. Values are described by type and
 * size, not content; only error messages are quoted.
 */
import { markers, net, test } from 'thousandeyes';

const UNBIND_REQUEST = [0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00]; // LDAPMessage: messageID 1, UnbindRequest
const IDLE_TIMEOUT_MS = 1500; // the socket idle timeout under test
const READ_WAIT_MS = 6000; // a read still unsettled after this long counts as pending
const CONNECT_WAIT_MS = 8000;
const CLEANUP_WAIT_MS = 2000;
const MAX_READS_AT_END = 3;

const fact = (name, value) => console.log(`runtime-fact ${name}: ${JSON.stringify(value)}`);

const errorInfo = (err) => ({
  name: err && err.name || null,
  code: err && err.code || null,
  message: String(err && err.message || err),
});

/** What a call returned, by type and size only. */
const describe = (value) => {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'string') return { type: 'string', length: value.length };
  if (value instanceof Uint8Array) return { type: value.constructor.name, length: value.length };
  if (typeof value === 'object') return { type: value.constructor && value.constructor.name || 'object', keys: Object.keys(value).slice(0, 15) };
  return { type: typeof value };
};

/** How the promise from `call` settles within `ms`: resolved, rejected (also a synchronous throw), or still pending. */
async function within(call, ms) {
  const start = Date.now();
  let timer;
  const pending = new Promise((resolve) => { timer = setTimeout(() => resolve({ outcome: 'pending' }), ms); });
  const settled = new Promise((resolve) => resolve(call())).then(
    (value) => ({ outcome: 'resolved', value }),
    (error) => ({ outcome: 'rejected', error }),
  );
  const result = await Promise.race([settled, pending]);
  clearTimeout(timer);
  return { ...result, afterMs: Date.now() - start };
}

const report = (result) => ({
  outcome: result.outcome,
  afterMs: result.afterMs,
  ...(result.outcome === 'resolved' ? { value: describe(result.value) } : {}),
  ...(result.outcome === 'rejected' ? { error: errorInfo(result.error) } : {}),
});

/** test.getSettings(): field names, the timeout and its type, the URL scheme (not the URL). */
function settingsFacts() {
  let settings;
  try {
    settings = test.getSettings();
  } catch (err) {
    fact('settings', { error: errorInfo(err) });
    return '';
  }
  const url = String(settings && settings.url || '');
  fact('settings', {
    keys: Object.keys(settings || {}),
    timeout: settings && settings.timeout,
    timeoutType: typeof (settings && settings.timeout),
    interval: settings && settings.interval,
    proxy: describe(settings && settings.proxy),
    urlScheme: (/^([a-z][a-z0-9+.-]*):/i.exec(url) || [])[1] || null,
  });
  return url;
}

/** markers.start() on a stopped marker, and markers.stop() on one never started. */
function markerFacts() {
  const attempt = (fn) => {
    try {
      fn();
      return { threw: false };
    } catch (err) {
      return { threw: true, error: errorInfo(err) };
    }
  };
  const start = attempt(() => markers.start('rt-marker'));
  const stop = attempt(() => markers.stop('rt-marker'));
  const restart = attempt(() => markers.start('rt-marker'));
  if (!restart.threw) attempt(() => markers.stop('rt-marker'));
  const stopNeverStarted = attempt(() => markers.stop('rt-never-started'));
  fact('markers', { start, stop, restartAfterStop: restart, stopNeverStarted });
}

function parseTarget(url) {
  const match = /^(ldaps?):\/\/(\[[^\]]+\]|[^:/?#]+)(?::(\d+))?/i.exec(url);
  if (!match) return null;
  const tls = match[1].toLowerCase() === 'ldaps';
  const host = match[2].replace(/^\[|\]$/g, '');
  return { tls, host, port: match[3] ? Number(match[3]) : (tls ? 636 : 389) };
}

async function connect(target, label) {
  const { tls, host, port } = target;
  const options = { rejectUnauthorized: false };
  if (!/^[\d.]+$/.test(host) && !host.includes(':')) options.servername = host;
  const result = await within(() => (tls ? net.connectTls(port, host, options) : net.connect(port, host)), CONNECT_WAIT_MS);
  if (result.outcome !== 'resolved') {
    fact(`${label}-connect`, report(result));
    return null;
  }
  return result.value;
}

/** Unbind and close; failures here say nothing about the runtime, so they are not reported. */
async function close(sock, { unbind = true } = {}) {
  if (unbind) await within(() => sock.writeAll(Buffer.from(UNBIND_REQUEST)), CLEANUP_WAIT_MS);
  await within(() => sock.end(), CLEANUP_WAIT_MS);
}

/** Which socket methods exist, and what the TLS ones return. */
function socketFacts(sock, tls) {
  const names = ['read', 'write', 'writeAll', 'end', 'setTimeout', 'getPeerCertificate', 'getCipher', 'destroy', 'on'];
  const types = Object.fromEntries(names.map((name) => [name, typeof sock[name]]));
  fact('socket', { tls, methods: types, ownKeys: Object.keys(sock).slice(0, 30) });
  for (const name of ['getPeerCertificate', 'getCipher']) {
    if (typeof sock[name] !== 'function') continue;
    try {
      const value = sock[name]();
      fact(name, { value: describe(value), hasSubject: Boolean(value && value.subject), hasName: Boolean(value && value.name) });
    } catch (err) {
      fact(name, { error: errorInfo(err) });
    }
  }
}

/** read() after the server closed the connection (it does after an UnbindRequest, RFC 4511 4.3). */
async function readAtEndFacts(target) {
  const sock = await connect(target, 'read-at-end');
  if (!sock) return;
  socketFacts(sock, target.tls);
  const write = await within(() => sock.writeAll(Buffer.from(UNBIND_REQUEST)), CLEANUP_WAIT_MS);
  const reads = [];
  for (let i = 0; i < MAX_READS_AT_END; i++) {
    const result = await within(() => sock.read(), READ_WAIT_MS);
    reads.push(report(result));
    // Keep reading after data or an empty chunk: either may come before the end-of-stream value.
    if (result.outcome !== 'resolved' || result.value === null || result.value === undefined) break;
  }
  fact('read-at-end', { unbindWrite: report(write), reads });
  await close(sock, { unbind: false });
}

/** Whether sock.setTimeout() ends a read on an idle connection (an LDAP server sends nothing unasked). */
async function setTimeoutFacts(target) {
  const sock = await connect(target, 'set-timeout');
  if (!sock) return;
  if (typeof sock.setTimeout !== 'function') {
    fact('setTimeout', { present: false });
    await close(sock);
    return;
  }
  let returned;
  try {
    returned = describe(sock.setTimeout(IDLE_TIMEOUT_MS));
  } catch (err) {
    fact('setTimeout', { present: true, threw: errorInfo(err) });
    await close(sock);
    return;
  }
  const read = await within(() => sock.read(), READ_WAIT_MS);
  fact('setTimeout', { present: true, idleTimeoutMs: IDLE_TIMEOUT_MS, returned, read: report(read) });
  await close(sock);
}

async function runtimeFacts() {
  const start = Date.now();
  markerFacts();
  const url = settingsFacts();
  const target = parseTarget(url);
  fact('target', target ? { parsed: true, tls: target.tls, port: target.port } : { parsed: false });
  if (target) {
    await readAtEndFacts(target);
    await setTimeoutFacts(target);
  }
  fact('done', { elapsedMs: Date.now() - start });
}

runtimeFacts().catch((err) => {
  console.error('Test failed:', err && err.message || 'Unknown error');
  throw err;
});
