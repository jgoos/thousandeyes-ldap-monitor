// Throwaway CA and server certificate for LDAPS tests, generated with the openssl CLI.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

/**
 * @param {string[]} subjectAltNames  e.g. ['DNS:ldap.test', 'IP:127.0.0.1']
 * @returns {{ caPem: string, key: string, cert: string } | null}  null when openssl is unavailable
 */
export function createTlsFixture(subjectAltNames) {
  const dir = mkdtempSync(path.join(tmpdir(), 'ldap-monitor-tls-'));
  const file = (name) => path.join(dir, name);
  const openssl = (...args) => execFileSync('openssl', args, { stdio: 'pipe' });
  try {
    const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
    openssl('req', '-x509', ...ec, '-keyout', file('ca.key'), '-out', file('ca.pem'), '-days', '2',
      '-subj', '/CN=ldap-monitor test CA',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
    openssl('req', ...ec, '-keyout', file('server.key'), '-out', file('server.csr'), '-subj', '/CN=ldap.test');
    writeFileSync(file('ext.cnf'), `subjectAltName=${subjectAltNames.join(',')}\nextendedKeyUsage=serverAuth\n`);
    openssl('x509', '-req', '-in', file('server.csr'), '-CA', file('ca.pem'), '-CAkey', file('ca.key'),
      '-CAcreateserial', '-out', file('server.pem'), '-days', '2', '-extfile', file('ext.cnf'));
    return {
      caPem: readFileSync(file('ca.pem'), 'utf8'),
      key: readFileSync(file('server.key'), 'utf8'),
      cert: readFileSync(file('server.pem'), 'utf8'),
    };
  } catch {
    return null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
