/**
 * ThousandEyes Transaction — LDAP health probe
 *
 * • Authenticated LDAPv3 simple bind
 * • Fast base-scope search against Root DSE
 * • Fails (throws) on error or if either round-trip exceeds `slowMs`
 *
 * Secure Credentials required:
 *   ldapMonUser  →  full bind DN   (e.g. "cn=monitor,ou=svc,dc=example,dc=com")
 *   ldapMonPass  →  password
 */

import { net, credentials } from 'thousandeyes';

// Configuration object so values can be easily customized
const cfg = {
  host: 'ldap.example.com',  // FQDN or IP
  port: 636,                 // 389 = LDAP, 636 = LDAPS
  timeoutMs: 5000,           // socket timeout
  slowMs: 300,               // alert threshold in ms
  baseDN: '',                // '' = Root DSE  (fastest search)
  filterAttr: 'objectClass', // attribute for present filter
  retryDelayMs: 100,         // delay between retries
  maxRetries: 2,             // max retry attempts for transient failures
  tlsMinVersion: 'TLSv1.2'   // minimum TLS version (supports 1.2, 1.3)
};

async function runTest() {

  /* ─────────── user-tunable settings ─────────── */
  const {
    host,
    port,
    timeoutMs,
    slowMs,
    baseDN,
    filterAttr,
    retryDelayMs,
    maxRetries,
    tlsMinVersion
  } = cfg;
  /* ───────────────────────────────────────────── */

  /* Secure secrets        (Settings ▸ Secure Credentials) */
  const bindDN  = credentials.get('ldapMonUser');
  const bindPwd = credentials.get('ldapMonPass');

  /* Input validation */
  if (!bindDN || !bindPwd) {
    throw new Error('Missing credentials: Ensure ldapMonUser and ldapMonPass are configured');
  }

  if (port !== 389 && port !== 636) {
    throw new Error(`Invalid port ${port}: Must be 389 (LDAP) or 636 (LDAPS)`);
  }

  if (slowMs <= 0) {
    throw new Error('Invalid slowMs threshold: must be greater than 0');
  }

  /* ---------- tiny BER helpers so we don't hard-code hex ---------- */
  /**
   * Generic Tag-Length-Value builder for BER encoding
   * @param {number} tag - BER tag byte
   * @param {Buffer} payload - Value to encode
   * @returns {Buffer} TLV-encoded buffer
   */
  // Encode BER length (supports multi-byte lengths)
  const berLen = (len) => {
    if (len < 0x80) return Buffer.from([len]);
    const bytes = [];
    while (len > 0) {
      bytes.unshift(len & 0xff);
      len >>= 8;
    }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  };

  const tlv  = (tag, payload) =>
    Buffer.concat([Buffer.from([tag]), berLen(payload.length), payload]);
  
  /** Encode INTEGER */
  const int  = n   => tlv(0x02, Buffer.from([n]));
  
  /** Encode OCTET STRING */
  const str  = (s) => tlv(0x04, Buffer.from(s, 'utf8'));
  
  /** Context-specific tag 0 for simple authentication */
  const ctx0 = (b) => Buffer.concat([Buffer.from([0x80]), berLen(b.length), b]);
  /* ---------------------------------------------------------------- */

  /* Performance metrics collector */
  const metrics = {
    connectionStart: null,
    connectionEnd: null,
    bindStart: null,
    bindEnd: null,
    searchStart: null,
    searchEnd: null
  };

  let sock;
  let attempt = 0;

  /* Retry loop for transient failures */
  while (attempt <= maxRetries) {
    try {
      /* 1 ▸ open socket (TLS if port 636) */
      metrics.connectionStart = Date.now();
      const connectPromise = (port === 636)
          ? net.connectTls(port, host, {
              minVersion: tlsMinVersion,
              rejectUnauthorized: true,
              servername: host
            })
          : net.connect(port, host);

      sock = await Promise.race([
        connectPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Connection timeout')), timeoutMs))
      ]);
      sock.setTimeout(timeoutMs);
      metrics.connectionEnd = Date.now();
      
      const connectionTime = metrics.connectionEnd - metrics.connectionStart;
      console.log(`Connection established in ${connectionTime} ms`);
      
      break; // Success, exit retry loop
    } catch (err) {
      attempt++;
      if (attempt > maxRetries) {
        throw new Error(`Connection failed after ${maxRetries + 1} attempts: ${err.message}`);
      }
      console.log(`Connection attempt ${attempt} failed, retrying in ${retryDelayMs}ms...`);
      await new Promise(resolve => setTimeout(resolve, retryDelayMs));
    }
  }

  try {
    /* 2 ▸ LDAPv3 simple-bind  (messageID = 1) */
    const bindReq = tlv(
      0x30,                                   // outer SEQUENCE
      Buffer.concat([
        int(1),                               // messageID
        tlv(0x60,                             // [APPLICATION 0] BindRequest
          Buffer.concat([
            int(3),                           // version 3
            str(bindDN),                      // bind DN
            ctx0(Buffer.from(bindPwd, 'utf8')) // password
          ])
        )
      ])
    );

    metrics.bindStart = Date.now();
    await sock.writeAll(bindReq);
    const bindRsp = await sock.read();
    metrics.bindEnd = Date.now();
    
    const bindRTT = metrics.bindEnd - metrics.bindStart;
    console.log(`Bind RTT: ${bindRTT} ms`);

    /* Enhanced bind response validation */
    if (!bindRsp?.length) {
      throw new Error('Bind failed: No response received from server');
    }
    
    if (bindRsp[8] !== 0x61) {
      throw new Error(`Bind failed: Unexpected response type 0x${bindRsp[8].toString(16)} (expected 0x61)`);
    }
    
    // Check result code (should be at position 12 for success = 0)
    if (bindRsp.length > 12 && bindRsp[12] !== 0x00) {
      const resultCode = bindRsp[12];
      const errorMessages = {
        0x01: 'operationsError',
        0x07: 'authMethodNotSupported', 
        0x08: 'strongerAuthRequired',
        0x31: 'invalidCredentials',
        0x32: 'insufficientAccessRights'
      };
      const errorMsg = errorMessages[resultCode] || `code 0x${resultCode.toString(16)}`;
      throw new Error(`Bind failed: ${errorMsg}`);
    }
    
    if (bindRTT > slowMs) {
      throw new Error(`Slow bind: ${bindRTT} ms (>${slowMs}ms threshold)`);
    }

    /* 3 ▸ base-scope search  (messageID = 2) */
    const searchReqBody = Buffer.concat([
      str(baseDN),         // baseObject
      int(0),              // scope           0 = base
      int(0),              // derefAliases    0 = never
      Buffer.from([0x02,0x02,0x03,0xE8]), // sizeLimit 1000
      Buffer.from([0x02,0x02,0x00,0x00]), // timeLimit 0
      Buffer.from([0x01,0x01,0x00]),      // typesOnly FALSE
      (() => {
        const attrBuf = Buffer.from(filterAttr, 'utf8');
        return Buffer.concat([Buffer.from([0x87]), berLen(attrBuf.length), attrBuf]);
      })(),
      Buffer.from([0x30,0x00])            // attributes = none
    ]);

    const searchReq = tlv(
      0x30,                                   // outer SEQUENCE
      Buffer.concat([
        int(2),                               // messageID
        tlv(0x63, searchReqBody)              // [APPLICATION 3] SearchRequest
      ])
    );

    metrics.searchStart = Date.now();
    await sock.writeAll(searchReq);

    const searchChunks = [];
    while (true) {
      const chunk = await sock.read();
      if (!chunk) {
        throw new Error('Search failed: connection closed before completion');
      }
      searchChunks.push(chunk);
      if (chunk.includes(0x65)) break; // SearchResultDone
    }
    metrics.searchEnd = Date.now();
    const searchRsp = Buffer.concat(searchChunks);
    
    const searchRTT = metrics.searchEnd - metrics.searchStart;
    console.log(`Search RTT: ${searchRTT} ms`);

    /* Enhanced search response validation */
    if (!searchRsp?.length) {
      throw new Error('Search failed: No response received from server');
    }
    
    if (searchRsp[8] !== 0x64) {
      throw new Error(`Search failed: Unexpected response type 0x${searchRsp[8].toString(16)} (expected 0x64 SearchResultEntry)`);
    }

    const doneIndex = searchRsp.lastIndexOf(0x65);
    if (doneIndex === -1 || doneIndex + 4 >= searchRsp.length) {
      throw new Error('Search failed: No SearchResultDone message');
    }
    const searchResultCode = searchRsp[doneIndex + 4];
    if (searchResultCode !== 0x00) {
      throw new Error(`Search failed: code 0x${searchResultCode.toString(16)}`);
    }
    
    if (searchRTT > slowMs) {
      throw new Error(`Slow search: ${searchRTT} ms (>${slowMs}ms threshold)`);
    }

    /* Total operation time */
    const totalTime = metrics.searchEnd - metrics.connectionStart;
    console.log(`Total operation time: ${totalTime} ms`);
    
    /* Performance summary */
    console.log('Performance breakdown:');
    console.log(`  - Connection: ${metrics.connectionEnd - metrics.connectionStart} ms`);
    console.log(`  - Bind: ${bindRTT} ms`); 
    console.log(`  - Search: ${searchRTT} ms`);

  } finally {
    /* Ensure socket is always closed */
    if (sock) {
      try {
        await sock.end();
      } catch (closeErr) {
        console.error(`Error closing socket: ${closeErr.message}`);
      }
    }
  }
}

// Execute the test with proper error handling
runTest().catch(err => {
  console.error('Test failed:', err.message);
  throw err;
});
