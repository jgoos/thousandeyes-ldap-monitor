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
 *   ldapCaPem    →  CA certificate in PEM format for LDAPS connections
 *
 * Optional Configuration Credentials (override defaults):
 *   ldapHost     →  LDAP server hostname
 *   ldapPort     →  LDAP server port (389 for LDAP, 636 for LDAPS)
 *   ldapBaseDN   →  Base DN for search (empty = Root DSE)
 */

import { net, credentials, test, markers } from 'thousandeyes';

/**
 * Get configuration from secure credentials with fallback defaults
 * Uses secure credentials for configuration since testVars are not available
 */
const getTestConfig = () => {
  // Get test timeout defensively for TypeScript compatibility
  let testTimeout = null;
  
  if (test && 'getSettings' in test) {
    try {
      const getSettingsMethod = test['getSettings'];
      if (typeof getSettingsMethod === 'function') {
        const settings = getSettingsMethod.call(test);
        if (settings) {
          testTimeout = settings.timeout;
        }
      }
    } catch (e) {
      // Ignore if getSettings fails
    }
  }

  // Try to get configuration from credentials (optional)
  // These would be additional credentials beyond the auth credentials
  let ldapHost = null;
  let ldapPort = null;
  let ldapBaseDN = null;
  
  try {
    // Optional configuration credentials (if available)
    ldapHost = credentials.get('ldapHost');
    ldapPort = credentials.get('ldapPort');
    ldapBaseDN = credentials.get('ldapBaseDN');
  } catch (e) {
    // Credentials may not exist, use defaults
  }

  // Configuration with secure credentials and sensible defaults
  return {
    host: ldapHost || 'ldap.example.com',                   // Override via ldapHost credential
    port: parseInt(ldapPort) || 636,                        // Override via ldapPort credential (389 = LDAP, 636 = LDAPS)
    timeoutMs: testTimeout || 5000,                         // socket timeout from test settings
    slowMs: 300,                                            // alert threshold in ms
    baseDN: ldapBaseDN || '',                               // Override via ldapBaseDN credential ('' = Root DSE)
    filterAttr: 'objectClass',                              // attribute for present filter
    retryDelayMs: 100,                                      // delay between retries
    maxRetries: 2,                                          // max retry attempts
    tlsMinVersion: 'TLSv1.2',                               // minimum TLS version
    serverName: ldapHost || 'LDAP Server'                   // For identification
  };
};

async function runTest() {
  // Get configuration from credentials and defaults
  const cfg = getTestConfig();

  /* ─────────── dynamic configuration loaded ─────────── */
  const {
    host,
    port,
    timeoutMs,
    slowMs,
    baseDN,
    filterAttr,
    retryDelayMs,
    maxRetries,
    tlsMinVersion,
    serverName
  } = cfg;
  
  // Log which server we're testing for clarity
  console.log(`Testing LDAP server: ${serverName} (${host}:${port})`);
  
  const effectiveTimeoutMs = timeoutMs;
  /* ───────────────────────────────────────────── */

  /* Secure secrets        (Settings ▸ Secure Credentials) */
  const bindDN  = credentials.get('ldapMonUser');
  const bindPwd = credentials.get('ldapMonPass');
  const caPem   = credentials.get('ldapCaPem');
  
  // Debug certificate information
  if (port === 636) {
    if (caPem) {
      console.log(`CA certificate provided - length: ${caPem.length} characters`);
      console.log(`CA certificate starts with: ${caPem.substring(0, 27)}...`);
    } else {
      console.log('No CA certificate provided - will use system certificates');
    }
  }

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
   * Encode BER length (supports multi-byte lengths)
   * @param {number} len - Length to encode
   * @returns {Buffer} BER-encoded length
   */
  const berLen = (len) => {
    if (len < 0x80) return Buffer.from([len]);
    const bytes = [];
    while (len > 0) {
      bytes.unshift(len & 0xff);
      len >>= 8;
    }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  };

  /**
   * Generic Tag-Length-Value builder for BER encoding
   * @param {number} tag - BER tag byte
   * @param {Buffer} payload - Value to encode
   * @returns {Buffer} TLV-encoded buffer
   */
  const tlv  = (tag, payload) =>
    Buffer.concat([Buffer.from([tag]), berLen(payload.length), payload]);
  
  /** Encode INTEGER */
  const int  = n   => tlv(0x02, Buffer.from([n]));
  
  /** Encode OCTET STRING */
  const str  = (s) => tlv(0x04, Buffer.from(s, 'utf8'));
  
  /** Context-specific tag 0 for simple authentication */
  const ctx0 = (b) => Buffer.concat([Buffer.from([0x80]), berLen(b.length), b]);
  /* ---------------------------------------------------------------- */

  /* --------- TLS information logging (defensive for TypeScript) --------- */
  /**
   * Log TLS connection information in a TypeScript-safe way
   * @param {object} socket - The socket object (may or may not have TLS methods)
   */
  const logTLSInfo = (socket) => {
    try {
      let cipher = null;
      let cert = null;
      let cn = null;
      
      // Safely attempt to get cipher information
      if (socket && 'getCipher' in socket) {
        try {
          const getCipherMethod = socket.getCipher;
          if (typeof getCipherMethod === 'function') {
            cipher = getCipherMethod.call(socket);
          }
        } catch (e) {
          // Ignore cipher access errors
        }
      }
      
      // Safely attempt to get certificate information
      if (socket && 'getPeerCertificate' in socket) {
        try {
          const getCertMethod = socket.getPeerCertificate;
          if (typeof getCertMethod === 'function') {
            cert = getCertMethod.call(socket);
            if (cert && cert.subject && cert.subject.CN) {
              cn = cert.subject.CN;
            }
          }
        } catch (e) {
          // Ignore certificate access errors
        }
      }
      
      const cipherName = cipher && cipher.name ? cipher.name : 'unknown';
      const commonName = cn || 'unknown';
      console.log(`TLS cipher: ${cipherName}; peer CN: ${commonName}`);
      
    } catch (error) {
      // If anything fails, just log basic TLS connection info
      console.log('TLS connection established');
    }
  };

  /**
   * Create a delay promise in a TypeScript-safe way
   * @param {number} delayMs - Delay in milliseconds
   * @returns {Promise} Promise that resolves after the delay
   */
  const createDelay = (delayMs) => {
    return new Promise(resolve => {
      try {
        // Try different timer approaches for maximum compatibility
        if (globalThis && 'setTimeout' in globalThis) {
          const setTimeoutMethod = globalThis.setTimeout;
          if (typeof setTimeoutMethod === 'function') {
            setTimeoutMethod(resolve, delayMs);
            return;
          }
        }
        
        // Fallback to global setTimeout if available
        if (typeof setTimeout === 'function') {
          setTimeout(resolve, delayMs);
          return;
        }
        
        // Try setImmediate for faster retry if setTimeout unavailable
        if (globalThis && 'setImmediate' in globalThis) {
          const setImmediateMethod = globalThis.setImmediate;
          if (typeof setImmediateMethod === 'function') {
            setImmediateMethod(resolve);
            return;
          }
        }
        
        // Last resort: immediate resolution
        resolve();
        
      } catch (error) {
        // If any timer approach fails, resolve immediately
        resolve();
      }
    });
  };

  /**
   * Safely check if a chunk contains the SearchResultDone marker (0x65)
   * @param {any} chunk - The chunk to check (may or may not be a Buffer)
   * @returns {boolean} True if chunk contains 0x65, false otherwise
   */
  const chunkContainsSearchDone = (chunk) => {
    try {
      if (!chunk) return false;
      
      // Check if it has an includes method and use it
      if ('includes' in chunk && typeof chunk.includes === 'function') {
        return chunk.includes(0x65);
      }
      
      // Fallback: check if it's array-like and iterate
      if (chunk.length && typeof chunk.length === 'number') {
        for (let i = 0; i < chunk.length; i++) {
          if (chunk[i] === 0x65) return true;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  };

  /**
   * Safely concatenate buffer chunks in a TypeScript-compatible way
   * @param {Array} chunks - Array of chunks to concatenate
   * @returns {Buffer|null} Concatenated buffer or null if failed
   */
  const safeBufferConcat = (chunks) => {
    try {
      if (!Array.isArray(chunks) || chunks.length === 0) {
        return null;
      }
      
      // Ensure all chunks are valid before concatenating
      const validChunks = chunks.filter(chunk => 
        chunk && (Buffer.isBuffer(chunk) || chunk.length !== undefined)
      );
      
      if (validChunks.length === 0) return null;
      
      return Buffer.concat(validChunks);
    } catch (error) {
      return null;
    }
  };

  /**
   * Safely find the last index of SearchResultDone marker (0x65)
   * @param {any} response - The response buffer to search
   * @returns {number} Index of last 0x65 or -1 if not found
   */
  const findSearchDoneIndex = (response) => {
    try {
      if (!response) return -1;
      
      // Try using lastIndexOf if available
      if ('lastIndexOf' in response && typeof response.lastIndexOf === 'function') {
        return response.lastIndexOf(0x65);
      }
      
      // Fallback: manual search from end
      if (response.length && typeof response.length === 'number') {
        for (let i = response.length - 1; i >= 0; i--) {
          if (response[i] === 0x65) return i;
        }
      }
      
      return -1;
    } catch (error) {
      return -1;
    }
  };
  /* --------------------------------------------------------------------- */

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
    const connectMarkerName = `connect-${attempt}`;
    markers.start(`retry-${attempt}`);
    let connectMarkerStarted = false;
    try {
      /* 1 ▸ open socket (TLS if port 636) */
      metrics.connectionStart = Date.now();
      markers.start(connectMarkerName);
      connectMarkerStarted = true;
      
      if (port === 636) {
        console.log(`Establishing LDAPS connection with ${caPem ? 'custom CA certificate' : 'system CA certificates'}`);
      }
      
      let connectPromise;
      if (port === 636) {
        const tlsOptions = {
          minVersion: tlsMinVersion,
          rejectUnauthorized: true,
          servername: host
        };
        
        // Add CA certificate if provided
        if (caPem) {
          try {
            // Ensure the CA certificate is properly formatted
            const caCert = caPem.trim();
            if (!caCert.includes('-----BEGIN CERTIFICATE-----')) {
              throw new Error('CA certificate must be in PEM format (missing -----BEGIN CERTIFICATE-----)');
            }
            tlsOptions.ca = [Buffer.from(caCert, 'utf8')];
            console.log('Using custom CA certificate for LDAPS connection');
          } catch (caError) {
            throw new Error(`Invalid CA certificate format: ${caError.message}`);
          }
        } else {
          console.log('Warning: Using system CA certificates - may fail with self-signed certificates');
        }
        
        connectPromise = net.connectTls(port, host, tlsOptions);
      } else {
        connectPromise = net.connect(port, host);
      }

      // Create connection with timeout
      const socketResult = await connectPromise;
      
      // Ensure socket has required methods
      if (!socketResult || typeof socketResult.setTimeout !== 'function') {
        throw new Error('Invalid socket object received');
      }
      
      sock = socketResult;
      sock.setTimeout(effectiveTimeoutMs);
      metrics.connectionEnd = Date.now();
      markers.stop(connectMarkerName);
      connectMarkerStarted = false;

      // Log TLS information if available (defensive handling for TypeScript compatibility)
      if (port === 636) {
        logTLSInfo(sock);
      }

      const connectionTime = metrics.connectionEnd - metrics.connectionStart;
      console.log(`Connection established in ${connectionTime} ms`);
      markers.stop(`retry-${attempt}`);
      break; // Success, exit retry loop
    } catch (err) {
      if (connectMarkerStarted) {
        markers.stop(connectMarkerName);
      }
      markers.stop(`retry-${attempt}`);
      
      // Enhanced error logging for certificate issues
      const errorMsg = err && err.message || 'Unknown error';
      if (errorMsg.includes('certificate') || errorMsg.includes('CERT_') || errorMsg.includes('SSL') || errorMsg.includes('TLS')) {
        console.log(`Certificate/TLS error on attempt ${attempt + 1}: ${errorMsg}`);
        if (!caPem && port === 636) {
          console.log('Hint: Consider providing ldapCaPem credential for self-signed certificates');
        }
      } else {
        console.log(`Connection attempt ${attempt + 1} failed: ${errorMsg}`);
      }
      
      attempt++;
      if (attempt > maxRetries) {
        // Provide more specific error message for certificate issues
        if (errorMsg.includes('certificate') || errorMsg.includes('CERT_') || errorMsg.includes('SSL') || errorMsg.includes('TLS')) {
          throw new Error(`TLS/Certificate validation failed after ${maxRetries + 1} attempts: ${errorMsg}. ${!caPem && port === 636 ? 'Consider providing ldapCaPem credential for self-signed certificates.' : ''}`);
        }
        throw new Error(`Connection failed after ${maxRetries + 1} attempts: ${errorMsg}`);
      }
      
      // Use defensive delay mechanism
      await createDelay(retryDelayMs);
    }
  }

  // Set test variable defensively for TypeScript compatibility
  if (test && 'setVariable' in test) {
    try {
      const setVariableMethod = test['setVariable']; // Use bracket notation for TypeScript compatibility
      if (typeof setVariableMethod === 'function') {
        setVariableMethod.call(test, 'retries', attempt);
      }
    } catch (e) {
      // Ignore if setVariable fails
    }
  }

  // Ensure socket is available for LDAP operations
  if (!sock) {
    throw new Error('Socket not available after connection attempts');
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

    let bindRTT;
    metrics.bindStart = Date.now();
    markers.start('bind');
    try {
      // Defensive check for socket methods
      if (!sock || typeof sock.writeAll !== 'function' || typeof sock.read !== 'function') {
        throw new Error('Socket does not have required writeAll/read methods');
      }
      
      await sock.writeAll(bindReq);
      const bindRsp = await sock.read();
      metrics.bindEnd = Date.now();

      bindRTT = metrics.bindEnd - metrics.bindStart;
      console.log(`Bind RTT: ${bindRTT} ms`);

      /* Enhanced bind response validation */
      if (!bindRsp || !bindRsp.length) {
        throw new Error('Bind failed: No response received from server');
      }

      if (bindRsp.length > 8 && bindRsp[8] !== 0x61) {
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
    } finally {
      markers.stop('bind');
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
    markers.start('search');
    let searchRsp;
    try {
      await sock.writeAll(searchReq);

      const searchChunks = [];
      while (true) {
        const chunk = await sock.read();
        if (!chunk) {
          throw new Error('Search failed: connection closed before completion');
        }
        searchChunks.push(chunk);
        if (chunkContainsSearchDone(chunk)) break; // SearchResultDone
      }
      metrics.searchEnd = Date.now();
      searchRsp = safeBufferConcat(searchChunks);
    } finally {
      markers.stop('search');
    }

    const searchRTT = metrics.searchEnd - metrics.searchStart;
    console.log(`Search RTT: ${searchRTT} ms`);

    /* Enhanced search response validation */
    if (!searchRsp || !searchRsp.length) {
      throw new Error('Search failed: No response received from server');
    }
    
    if (searchRsp.length > 8 && searchRsp[8] !== 0x64) {
      throw new Error(`Search failed: Unexpected response type 0x${searchRsp[8].toString(16)} (expected 0x64 SearchResultEntry)`);
    }

    const doneIndex = findSearchDoneIndex(searchRsp);
    const searchRspLength = searchRsp && searchRsp.length ? searchRsp.length : 0;
    if (doneIndex === -1 || doneIndex + 4 >= searchRspLength) {
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
    if (sock && typeof sock.end === 'function') {
      try {
        await sock.end();
      } catch (closeErr) {
        console.error(`Error closing socket: ${closeErr && closeErr.message || 'Unknown error'}`);
      }
    }
  }
}

// Execute the test with proper error handling
runTest().catch(err => {
  console.error('Test failed:', err && err.message || 'Unknown error');
  throw err;
});
