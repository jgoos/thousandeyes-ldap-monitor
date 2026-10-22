/**
 * Local stand-in for the ThousandEyes `thousandeyes` runtime module.
 *
 * Mirrors documented behaviour where ThousandEyes documents it:
 *   - test.getSettings() returns { interval, timeout, url, proxy }; timeout is in seconds
 *     (inferred from the vendor sample `settings.timeout / 2 * 1000`).
 *   - markers.start() throws for a marker that was already started; markers.stop() throws for
 *     a marker that was never started or is already stopped.
 *   - credentials.get() only returns credentials associated with the test.
 *   https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests/transaction-scripting-reference
 *
 * Assumptions where ThousandEyes is silent (keep in sync with README "Testing"):
 *   - socket.read() resolves with the next received chunk, or null once the peer has closed.
 *   - credentials.get() throws for a credential not associated with the test.
 *   - socket.setTimeout() is recorded but not enforced unless `enforceSocketTimeout` is set,
 *     in which case it behaves like Node's idle timeout and rejects the pending read().
 *   - A TLS socket has getCipher() and getPeerCertificate() as in Node's tls module. Neither is
 *     documented for ThousandEyes, so `peerCertificate` can take getPeerCertificate() away.
 *
 * Configured through the TE_STUB_CONFIG environment variable (JSON):
 *   { credentials, settings, routes, enforceSocketTimeout, stallCleanup, peerCertificate, failWrite }
 * `routes` maps "host:port" as the script sees it to "127.0.0.1:port" on the test machine,
 * or to "hang" for a connect that never completes. Unrouted targets are refused.
 * `stallCleanup` makes writing an UnbindRequest and end() never complete.
 * `peerCertificate` changes getPeerCertificate() on TLS sockets: 'absent' leaves it out,
 * 'throws' makes it throw, and an object is returned in place of the real certificate.
 * `failWrite` ('bind' or 'search') makes writeAll() reject that request with EPIPE.
 * Every observable call is appended as a JSON line to the file named by TE_STUB_TRACE.
 */
import { appendFileSync } from 'node:fs';
import nodeNet from 'node:net';
import nodeTls from 'node:tls';

const config = JSON.parse(process.env.TE_STUB_CONFIG || '{}');
const tracePath = process.env.TE_STUB_TRACE;

const trace = (event) => {
  if (tracePath) appendFileSync(tracePath, `${JSON.stringify({ t: Date.now(), ...event })}\n`);
};

const resolveRoute = (host, port) => {
  const route = (config.routes || {})[`${host}:${port}`];
  if (route === 'hang') return { hang: true };
  if (!route) return { refused: true };
  const [routeHost, routePort] = route.split(':');
  return { host: routeHost, port: Number(routePort) };
};

// A promise that never settles; the interval keeps the process alive, as a live runtime would.
const stall = () => new Promise(() => { setInterval(() => {}, 60_000); });

// LDAPMessage whose protocolOp is UnbindRequest ([APPLICATION 2] NULL): ends in 0x42 0x00.
const isUnbindRequest = (buf) => buf.length >= 2 && buf[buf.length - 2] === 0x42 && buf[buf.length - 1] === 0x00;

// protocolOp tag of an LDAPMessage: skip the SEQUENCE header, then the messageID INTEGER.
const opTagOf = (buf) => {
  let pos = 1 + (buf[1] & 0x80 ? 1 + (buf[1] & 0x7f) : 1);
  pos += 2 + buf[pos + 1];
  return buf[pos];
};
const FAIL_WRITE_TAGS = { bind: 0x60, search: 0x63 };

const refusedError = (host, port) =>
  Object.assign(new Error(`connect ECONNREFUSED ${host}:${port}`), { code: 'ECONNREFUSED' });

function wrapSocket(sock) {
  const chunks = [];
  const readers = [];
  let closed = false;
  let failure = null;

  const settle = () => {
    while (readers.length && (chunks.length || closed || failure)) {
      const reader = readers.shift();
      if (chunks.length) reader.resolve(chunks.shift());
      else if (failure) reader.reject(failure);
      else reader.resolve(null);
    }
  };

  sock.on('data', (data) => {
    trace({ type: 'rx', hex: data.toString('hex') });
    chunks.push(data);
    settle();
  });
  sock.on('end', () => { closed = true; settle(); });
  sock.on('close', () => { closed = true; settle(); });
  sock.on('error', (err) => { failure = err; settle(); });
  sock.on('timeout', () => {
    trace({ type: 'socket-timeout' });
    failure = Object.assign(new Error('Socket timed out'), { code: 'ETIMEDOUT' });
    settle();
    sock.destroy();
  });

  const api = {
    setTimeout(ms) {
      trace({ type: 'setTimeout', value: ms });
      if (config.enforceSocketTimeout) sock.setTimeout(ms);
    },
    writeAll(buf) {
      trace({ type: 'tx', hex: Buffer.from(buf).toString('hex') });
      if (config.stallCleanup && isUnbindRequest(buf)) return stall();
      if (config.failWrite && opTagOf(Buffer.from(buf)) === FAIL_WRITE_TAGS[config.failWrite]) {
        return Promise.reject(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }));
      }
      return new Promise((resolve, reject) => sock.write(buf, (err) => (err ? reject(err) : resolve())));
    },
    read() {
      return new Promise((resolve, reject) => { readers.push({ resolve, reject }); settle(); });
    },
    end() {
      trace({ type: 'end' });
      if (config.stallCleanup) return stall();
      return new Promise((resolve) => {
        if (sock.destroyed) return resolve();
        sock.end(() => resolve());
      });
    },
  };
  if (typeof sock.getCipher === 'function') {
    api.getCipher = () => sock.getCipher();
    const { peerCertificate } = config;
    if (peerCertificate === 'throws') {
      api.getPeerCertificate = () => { throw new Error('getPeerCertificate is not available'); };
    } else if (peerCertificate && typeof peerCertificate === 'object') {
      api.getPeerCertificate = () => peerCertificate;
    } else if (peerCertificate !== 'absent') {
      api.getPeerCertificate = () => sock.getPeerCertificate();
    }
  }
  return api;
}

export const net = {
  connect: (port, host) => connectPlain(port, host),
  connectTls: (port, host, options = {}) => connectTls(port, host, options),
};

function connectPlain(port, host) {
  trace({ type: 'connect', host, port });
  const route = resolveRoute(host, port);
  if (route.hang) return new Promise(() => { setInterval(() => {}, 60_000); });
  if (route.refused) return Promise.reject(refusedError(host, port));
  return new Promise((resolve, reject) => {
    const sock = nodeNet.connect(route.port, route.host, () => resolve(wrapSocket(sock)));
    sock.once('error', reject);
  });
}

function connectTls(port, host, options) {
  trace({ type: 'connectTls', host, port, options: { ...options, ca: options.ca ? `${[].concat(options.ca).length} cert(s)` : undefined } });
  const route = resolveRoute(host, port);
  if (route.hang) return new Promise(() => { setInterval(() => {}, 60_000); });
  if (route.refused) return Promise.reject(refusedError(host, port));
  return new Promise((resolve, reject) => {
    // Node's tls.connect verifies the certificate against `servername` when it is set, or against
    // `host` otherwise; pass the name the script asked for so hostname checks behave as on an agent.
    const identity = options.servername || host;
    const sock = nodeTls.connect(
      {
        ...options,
        host: route.host,
        port: route.port,
        checkServerIdentity: (_name, cert) => nodeTls.checkServerIdentity(identity, cert),
      },
      () => resolve(wrapSocket(sock)),
    );
    sock.once('error', reject);
  });
}

export const credentials = {
  get(name) {
    const store = config.credentials || {};
    trace({ type: 'credentials.get', name, found: name in store });
    if (!(name in store)) throw new Error(`Credential "${name}" is not associated with this test`);
    return store[name];
  },
};

const markerState = new Map();
const markerError = (name, message) => {
  trace({ type: 'marker.error', name, message });
  return new Error(message);
};
export const markers = {
  start(name) {
    trace({ type: 'marker.start', name });
    if (markerState.has(name)) throw markerError(name, `Marker "${name}" was already started`);
    markerState.set(name, 'started');
  },
  stop(name) {
    trace({ type: 'marker.stop', name });
    if (markerState.get(name) !== 'started') throw markerError(name, `Marker "${name}" is not running`);
    markerState.set(name, 'stopped');
  },
};

export const test = {
  getSettings() {
    return { interval: 300, timeout: 30, url: '', proxy: null, ...(config.settings || {}) };
  },
};
