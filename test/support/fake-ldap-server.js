// Scripted LDAP responder. Each scenario hook returns the steps to play back for one request:
//   Buffer              write these bytes
//   { waitMs: n }       pause before the next step
//   { close: true }     end the connection
import nodeNet from 'node:net';
import nodeTls from 'node:tls';
import { TAG, decodeRequest, splitMessages } from './ber.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {object} scenario
 * @param {(req: object) => Array} [scenario.bind]    steps for a BindRequest
 * @param {(req: object) => Array} [scenario.search]  steps for a SearchRequest
 * @param {{ key: string, cert: string }} [scenario.tls]  serve LDAPS with this key/cert
 * @returns {Promise<{ port: number, requests: object[], close: () => Promise<void> }>}
 */
export async function startFakeLdap({ bind, search, tls } = {}) {
  const requests = [];
  const sockets = new Set();

  const onConnection = (sock) => {
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
    sock.on('error', () => {});
    let pending = Buffer.alloc(0);
    let queue = Promise.resolve();

    sock.on('data', (data) => {
      const { pdus, rest } = splitMessages(Buffer.concat([pending, data]));
      pending = Buffer.from(rest);
      for (const pdu of pdus) {
        const request = decodeRequest(pdu);
        requests.push(request);
        let steps = [];
        if (request.opTag === TAG.bindRequest && bind) steps = bind(request);
        else if (request.opTag === TAG.searchRequest && search) steps = search(request);
        else if (request.opTag === TAG.unbindRequest) steps = [{ close: true }];
        queue = queue.then(() => play(sock, steps));
      }
    });
  };

  const server = tls
    ? nodeTls.createServer({ key: tls.key, cert: tls.cert }, onConnection)
    : nodeNet.createServer(onConnection);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  return {
    port: server.address().port,
    requests,
    close: () => new Promise((resolve) => {
      for (const sock of sockets) sock.destroy();
      server.close(() => resolve());
    }),
  };
}

async function play(sock, steps) {
  for (const step of steps) {
    if (sock.destroyed) return;
    if (Buffer.isBuffer(step)) sock.write(step);
    else if (step.waitMs) await sleep(step.waitMs);
    else if (step.close) sock.end();
  }
}
