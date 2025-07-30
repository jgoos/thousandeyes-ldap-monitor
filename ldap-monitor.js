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
 *   ldapCaBase64 →  CA certificate(s) in base64-encoded format for LDAPS connections
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

  // Read credentials directly here where they're used
  let ldapHost = null;
  let ldapPort = null;
  let ldapBaseDN = null;
  
  // Detailed credential debugging - make it visible in console and accessible globally
  let debugInfo = [];
  debugInfo.push('CRED_DEBUG:');
  debugInfo.push(`obj=${typeof credentials}`);
  debugInfo.push(`get=${typeof credentials.get}`);
  
  try {
    // Test each credential individually
    ldapHost = credentials.get('ldapHost');
    const hostStatus = ldapHost ? `'${ldapHost}'` : 'NULL';
    debugInfo.push(`host=${hostStatus}`);
    
    ldapPort = credentials.get('ldapPort');
    const portStatus = ldapPort ? `'${ldapPort}'` : 'NULL';
    debugInfo.push(`port=${portStatus}`);
    
    ldapBaseDN = credentials.get('ldapBaseDN');
    const baseDnStatus = ldapBaseDN ? `'${ldapBaseDN}'` : 'NULL';
    debugInfo.push(`baseDN=${baseDnStatus}`);
    
    // Test auth credentials for comparison
    try {
      const testUser = credentials.get('ldapMonUser');
      const testPass = credentials.get('ldapMonPass');
      debugInfo.push(`user=${testUser ? 'OK' : 'NULL'}`);
      debugInfo.push(`pass=${testPass ? 'OK' : 'NULL'}`);
    } catch (authErr) {
      debugInfo.push(`auth_err=${authErr.message}`);
    }
    
  } catch (e) {
    debugInfo.push(`ERROR=${e.message}`);
    console.log(`CREDENTIAL ERROR: ${e.message}`);
  }
  
  // Log for console visibility
  console.log('=== CREDENTIAL DEBUG ===');
  console.log(debugInfo.join(' | '));
  console.log('=== END DEBUG ===');
  
  // Debug info is available in console logs and will be reconstructed in error messages

  // Configuration with secure credentials and sensible defaults
  return {
    host: ldapHost || 'ldap.example.com',                   // Override via ldapHost credential
    port: parseInt(ldapPort) || 636,                        // Override via ldapPort credential (389 = LDAP, 636 = LDAPS)
    timeoutMs: testTimeout || 5000,                         // socket timeout from test settings
    slowMs: 300,                                            // alert threshold in ms
    baseDN: ldapBaseDN || '',                               // Override via ldapBaseDN credential ('' = Root DSE - may not work on all servers)
    fallbackSearch: !ldapBaseDN,                            // Use fallback search strategy if no base DN provided
    filterAttr: !ldapBaseDN ? 'objectClass' : 'uid',        // use objectClass for Root DSE, uid for specific DNs
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
    serverName,
    fallbackSearch
  } = cfg;
  
  // Log which server we're testing for clarity
  console.log(`Testing LDAP server: ${serverName} (${host}:${port})`);
  
  const effectiveTimeoutMs = timeoutMs;
  /* ───────────────────────────────────────────── */

  /* Secure secrets        (Settings ▸ Secure Credentials) */
  const bindDN  = credentials.get('ldapMonUser');
  const bindPwd = credentials.get('ldapMonPass');
  const caBase64 = credentials.get('ldapCaBase64');
  
  // Debug certificate information
  if (port === 636) {
    if (caBase64) {
      console.log(`Base64-encoded CA certificate provided - length: ${caBase64.length} characters`);
      console.log(`Base64 data starts with: ${caBase64.substring(0, 40)}...`);
    } else {
      console.log('No CA certificate provided - will use system certificates');
    }
  }
  
  // Enhanced base DN debugging - make visible in GUI
  let baseDnInfo = [];
  baseDnInfo.push(`final_baseDN='${baseDN}'(len:${baseDN.length})`);
  baseDnInfo.push(`bindDN='${bindDN}'`);
  
  if (baseDN === '') {
    baseDnInfo.push('STATUS=EMPTY_BASE_DN!');
    baseDnInfo.push('expected=ou=People,o=company');
    baseDnInfo.push('issue=ldapBaseDN_not_read');
    console.log('BASE DN STATUS: FAILED - Empty base DN, credential not read');
  } else {
    baseDnInfo.push(`STATUS=OK`);
    console.log(`BASE DN STATUS: OK - Using ${baseDN}`);
    
    // Check compatibility
    if (bindDN && bindDN.includes(baseDN)) {
      baseDnInfo.push('compat=YES');
    } else if (bindDN && baseDN !== '') {
      baseDnInfo.push('compat=MAYBE');
    }
  }
  
  console.log('=== BASE DN CHECK ===');
  console.log(baseDnInfo.join(' | '));
  console.log('=== END BASE DN CHECK ===');

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
        console.log(`Establishing LDAPS connection with ${caBase64 ? 'custom CA certificate' : 'system CA certificates'}`);
      }
      
      let connectPromise;
      if (port === 636) {
        const tlsOptions = {
          minVersion: tlsMinVersion,
          rejectUnauthorized: true,
          servername: host
        };
        
        // Add CA certificate if provided
        if (caBase64) {
          try {
            // Decode base64 to PEM format
            console.log('Decoding base64 CA certificate...');
            const pemCertificate = Buffer.from(caBase64.trim(), 'base64').toString('utf8');
            console.log(`Decoded certificate length: ${pemCertificate.length} characters`);
            
            // Normalize line endings and validate PEM format
            const normalizedPem = pemCertificate.replace(/\r\n/g, '\n').trim();
            
            if (!normalizedPem.includes('-----BEGIN CERTIFICATE-----')) {
              throw new Error('Decoded certificate is not in valid PEM format (missing -----BEGIN CERTIFICATE-----)');
            }
            
            // Extract all certificates from the PEM data (handles certificate chains)
            const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
            const certificates = normalizedPem.match(certRegex);
            
            if (!certificates || certificates.length === 0) {
              throw new Error('No valid certificates found in decoded PEM data');
            }
            
            console.log(`Found ${certificates.length} certificate(s) in decoded data`);
            
            // Convert each certificate to Buffer
            const caBuffers = certificates.map((cert, index) => {
              const trimmedCert = cert.trim();
              console.log(`Certificate ${index + 1}: ${trimmedCert.length} chars`);
              return Buffer.from(trimmedCert, 'utf8');
            });
            
            tlsOptions.ca = caBuffers;
            console.log(`Using ${caBuffers.length} custom CA certificate(s) for LDAPS connection`);
            
          } catch (caError) {
            throw new Error(`CA certificate processing failed: ${caError.message}`);
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
        if (!caBase64 && port === 636) {
          console.log('Hint: Consider providing ldapCaBase64 credential for self-signed certificates');
        }
      } else {
        console.log(`Connection attempt ${attempt + 1} failed: ${errorMsg}`);
      }
      
      attempt++;
      if (attempt > maxRetries) {
        // Provide more specific error message for certificate issues
        if (errorMsg.includes('certificate') || errorMsg.includes('CERT_') || errorMsg.includes('SSL') || errorMsg.includes('TLS')) {
          throw new Error(`TLS/Certificate validation failed after ${maxRetries + 1} attempts: ${errorMsg}. ${!caBase64 && port === 636 ? 'Consider providing ldapCaBase64 credential (base64-encoded) for self-signed certificates.' : ''}`);
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
      
      console.log(`Sending LDAP bind request (${bindReq.length} bytes) for user: ${bindDN}`);
      const maxReqBytes = bindReq.length < 32 ? bindReq.length : 32;
      console.log(`Bind request hex (first 32 bytes): ${bindReq.slice(0, maxReqBytes).toString('hex')}`);
      await sock.writeAll(bindReq);
      const bindRsp = await sock.read();
      metrics.bindEnd = Date.now();

      bindRTT = metrics.bindEnd - metrics.bindStart;
      console.log(`Bind RTT: ${bindRTT} ms`);

      /* Enhanced bind response validation with detailed debugging */
      if (!bindRsp || !bindRsp.length) {
        throw new Error('Bind failed: No response received from server');
      }

      console.log(`Received bind response: ${bindRsp.length} bytes`);
      const maxBytes = bindRsp.length < 32 ? bindRsp.length : 32;
      console.log(`Response hex (first 32 bytes): ${bindRsp.slice(0, maxBytes).toString('hex')}`);
      
      // Helper function for hex formatting (compatible with older JS)
      const toHex = (num) => {
        const hex = num.toString(16);
        return hex.length === 1 ? '0' + hex : hex;
      };
      
      // Debug the response structure
      if (bindRsp.length > 0) {
        console.log(`Response byte analysis:`);
        console.log(`  [0] = 0x${toHex(bindRsp[0])} (${bindRsp[0]})`);
        if (bindRsp.length > 1) console.log(`  [1] = 0x${toHex(bindRsp[1])} (${bindRsp[1]})`);
        if (bindRsp.length > 2) console.log(`  [2] = 0x${toHex(bindRsp[2])} (${bindRsp[2]})`);
        if (bindRsp.length > 8) console.log(`  [8] = 0x${toHex(bindRsp[8])} (${bindRsp[8]}) - Response type`);
        if (bindRsp.length > 12) console.log(`  [12] = 0x${toHex(bindRsp[12])} (${bindRsp[12]}) - Result code`);
      }

      // Check for LDAP message structure: 0x30 (SEQUENCE) at start
      if (bindRsp.length > 0 && bindRsp[0] !== 0x30) {
        throw new Error(`Bind failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${bindRsp[0].toString(16)}`);
      }

      // Look for BindResponse (0x61) - might be at different position depending on message structure
      let bindResponsePosition = -1;
      const maxSearchLen = (bindRsp.length - 1) < 20 ? (bindRsp.length - 1) : 20;
      for (let i = 0; i < maxSearchLen; i++) {
        if (bindRsp[i] === 0x61) {
          bindResponsePosition = i;
          break;
        }
      }
      
      if (bindResponsePosition === -1) {
        // Look for any response type indicators
        const responseTypes = [];
        const maxScanLen = bindRsp.length < 20 ? bindRsp.length : 20;
        for (let i = 0; i < maxScanLen; i++) {
          if (bindRsp[i] >= 0x60 && bindRsp[i] <= 0x78) { // LDAP response range
            responseTypes.push(`0x${bindRsp[i].toString(16)} at position ${i}`);
          }
        }
        throw new Error(`Bind failed: No BindResponse (0x61) found in response. Found response types: ${responseTypes.length > 0 ? responseTypes.join(', ') : 'none'}`);
      }
      
      console.log(`Found BindResponse (0x61) at position ${bindResponsePosition}`);
      
      // Check for the traditional position first (position 8)
      if (bindRsp.length > 8 && bindRsp[8] !== 0x61) {
        if (bindResponsePosition !== 8) {
          console.log(`Warning: BindResponse found at position ${bindResponsePosition}, not the expected position 8`);
        } else {
          throw new Error(`Bind failed: Unexpected response type 0x${bindRsp[8].toString(16)} (expected 0x61)`);
        }
      }

      // Check result code - adjust position based on where BindResponse was found
      const resultCodePosition = bindResponsePosition + 4; // Result code typically 4 bytes after BindResponse
      if (bindRsp.length > resultCodePosition) {
        const resultCode = bindRsp[resultCodePosition];
        const resultHex = resultCode.toString(16);
        const paddedHex = resultHex.length === 1 ? '0' + resultHex : resultHex;
        console.log(`Result code at position ${resultCodePosition}: 0x${paddedHex} (${resultCode})`);
        
        if (resultCode !== 0x00) {
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
        
        console.log('Bind successful - result code 0x00');
      } else {
        console.log('Warning: Could not determine result code from response');
      }

      if (bindRTT > slowMs) {
        throw new Error(`Slow bind: ${bindRTT} ms (>${slowMs}ms threshold)`);
      }
      
      console.log('LDAP bind completed successfully');
    } finally {
      markers.stop('bind');
    }
    

    /* 3 ▸ flexible search  (messageID = 2) */
    // Use subtree scope (2) for organizational DN searches, base scope (0) for Root DSE
    // Subtree scope searches beneath the DN, which works for organizational units
    const searchScope = baseDN === '' ? 0 : 2; // Subtree scope for specific DNs like ou=People
    console.log(`Using search scope: ${searchScope} (0=base, 1=one-level, 2=subtree)`);
    console.log(`Search filter: (${filterAttr}=*) - checking for presence of ${filterAttr} attribute`);
    if (baseDN === '') {
      console.log(`Note: Using objectClass filter for Root DSE search (standard approach)`);
    } else {
      console.log(`Note: Using uid filter for organizational DN search`);
    }
    console.log(`Search target: base DN '${baseDN}' with ${searchScope === 0 ? 'base scope (0) - searching only the exact DN object' : 'subtree scope (2) - searching beneath the DN'}`);
    
    // For debugging: log what we expect to find
    if (baseDN.includes('ou=People') && searchScope === 2) {
      console.log(`Info: Subtree scope search on organizational unit should find user objects beneath it.`);
    }
    
    const searchReqBody = Buffer.concat([
      str(baseDN),         // baseObject
      int(searchScope),    // scope           0 = base, 2 = subtree
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
      console.log(`Sending LDAP search request (${searchReq.length} bytes) - baseDN: '${baseDN}' ${baseDN === '' ? '(Root DSE - may require ldapBaseDN credential)' : ''}, filterAttr: '${filterAttr}'`);
      const maxSearchReqBytes = searchReq.length < 32 ? searchReq.length : 32;
      console.log(`Search request hex (first 32 bytes): ${searchReq.slice(0, maxSearchReqBytes).toString('hex')}`);
      
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

    /* Enhanced search response validation with detailed debugging */
    if (!searchRsp || !searchRsp.length) {
      throw new Error('Search failed: No response received from server');
    }
    
    console.log(`Received search response: ${searchRsp.length} bytes`);
    const maxSearchBytes = searchRsp.length < 32 ? searchRsp.length : 32;
    console.log(`Search response hex (first 32 bytes): ${searchRsp.slice(0, maxSearchBytes).toString('hex')}`);
    
    // Helper function for hex formatting (reuse from bind)
    const toHexSearch = (num) => {
      const hex = num.toString(16);
      return hex.length === 1 ? '0' + hex : hex;
    };
    
    // Debug the search response structure
    if (searchRsp.length > 0) {
      console.log(`Search response byte analysis:`);
      console.log(`  [0] = 0x${toHexSearch(searchRsp[0])} (${searchRsp[0]}) - Should be SEQUENCE (0x30)`);
      if (searchRsp.length > 1) console.log(`  [1] = 0x${toHexSearch(searchRsp[1])} (${searchRsp[1]}) - Length`);
      if (searchRsp.length > 2) console.log(`  [2] = 0x${toHexSearch(searchRsp[2])} (${searchRsp[2]})`);
      if (searchRsp.length > 8) console.log(`  [8] = 0x${toHexSearch(searchRsp[8])} (${searchRsp[8]}) - Response type`);
      if (searchRsp.length > 12) console.log(`  [12] = 0x${toHexSearch(searchRsp[12])} (${searchRsp[12]})`);
    }
    
    // Check for LDAP message structure: 0x30 (SEQUENCE) at start
    if (searchRsp.length > 0 && searchRsp[0] !== 0x30) {
      throw new Error(`Search failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${toHexSearch(searchRsp[0])}`);
    }
    
    // Look for different types of search responses
    let searchEntryPosition = -1;
    let searchDonePosition = -1;
    let searchRefPosition = -1;
    
    const maxScanSearchLen = searchRsp.length < 50 ? searchRsp.length : 50;
    for (let i = 0; i < maxScanSearchLen; i++) {
      if (searchRsp[i] === 0x64) searchEntryPosition = i; // SearchResultEntry
      if (searchRsp[i] === 0x65) searchDonePosition = i;  // SearchResultDone
      if (searchRsp[i] === 0x73) searchRefPosition = i;   // SearchResultReference
    }
    
    console.log(`Search response types found:`);
    console.log(`  SearchResultEntry (0x64): ${searchEntryPosition >= 0 ? 'position ' + searchEntryPosition : 'not found'}`);
    console.log(`  SearchResultDone (0x65): ${searchDonePosition >= 0 ? 'position ' + searchDonePosition : 'not found'}`);
    console.log(`  SearchResultReference (0x73): ${searchRefPosition >= 0 ? 'position ' + searchRefPosition : 'not found'}`);
    
    // Check what's actually at position 8
    if (searchRsp.length > 8) {
      const responseType = searchRsp[8];
      console.log(`Response type at position 8: 0x${toHexSearch(responseType)} (${responseType})`);
      
      // Handle different response types more flexibly
      if (responseType === 0x65) {
        console.log('Received SearchResultDone - this may indicate an empty result set or immediate completion');
        // Continue processing - this might be valid
      } else if (responseType === 0x64) {
        console.log('Received SearchResultEntry - search found results');
      } else {
        // Look for the actual response type in the message
        const responseTypes = [];
        for (let i = 0; i < maxScanSearchLen; i++) {
          if (searchRsp[i] >= 0x60 && searchRsp[i] <= 0x78) { // LDAP response range
            responseTypes.push(`0x${toHexSearch(searchRsp[i])} at position ${i}`);
          }
        }
        console.log(`Found LDAP response types: ${responseTypes.length > 0 ? responseTypes.join(', ') : 'none'}`);
        const baseDnHint = baseDN === '' ? ' Consider setting ldapBaseDN credential with a valid base DN (e.g., dc=company,dc=com) instead of using Root DSE.' : '';
        
        // If this is a fallback search and we get 0xbe, provide specific guidance
        if (responseType === 0xbe) {
          // Reconstruct debug info for error message
          const credentialInfo = `host=${host}|port=${port}|baseDN=${baseDN || 'NULL'}|user=${bindDN ? 'OK' : 'NULL'}`;
          const baseDnInfo = `final_baseDN='${baseDN}'|bindDN='${bindDN}'|status=${baseDN === '' ? 'EMPTY' : 'OK'}`;
          
          const errorDetails = `LDAP Search Failed: Response type 0xbe (Invalid DN Syntax/Insufficient Access Rights)`;
          let debugSection = `\n\nDEBUG INFORMATION:`;
          debugSection += `\n- Credential Status: ${credentialInfo}`;
          debugSection += `\n- Base DN Status: ${baseDnInfo}`;
          
          let solution;
          if (baseDN === '') {
            solution = '\n\nSOLUTION:';
            solution += '\nThe ldapBaseDN credential was not read successfully.';
            solution += '\nAdd ldapBaseDN credential with your organization\'s base DN (e.g., ou=People,o=company)';
          } else {
            solution = `\n\nPOSSIBLE SOLUTIONS for base DN '${baseDN}':`;
            solution += `\n1. Verify your user has search permissions on '${baseDN}'`;
            solution += `\n2. Try with empty base DN (Root DSE) by removing ldapBaseDN credential`;
            solution += `\n3. Try with exact bind DN as base DN`;
            solution += `\n4. Verify the base DN exists and is searchable with LDAP tools`;
          }
          throw new Error(`${errorDetails}${debugSection}${solution}`);
        }
        
        // Handle specific response types with detailed explanations
        if (responseType === 0x01) {
          // Reconstruct debug info for error message
          const credentialInfo = `host=${host}|port=${port}|baseDN=${baseDN || 'NULL'}|user=${bindDN ? 'OK' : 'NULL'}`;
          const baseDnInfo = `final_baseDN='${baseDN}'|bindDN='${bindDN}'|status=${baseDN === '' ? 'EMPTY' : 'OK'}`;
          
          const errorDetails = `LDAP Search Failed: Response type 0x01 (Operations Error)`;
          let debugSection = `\n\nDEBUG INFORMATION:`;
          debugSection += `\n- Credential Status: ${credentialInfo}`;
          debugSection += `\n- Base DN Status: ${baseDnInfo}`;
          
          let suggestion = '';
          if (baseDN === '') {
            suggestion = `\n\nSOLUTION:`;
            suggestion += `\nThe ldapBaseDN credential was not read successfully.`;
            suggestion += `\nAdd ldapBaseDN with your organization's base DN (e.g., ou=People,o=company)`;
          } else if (baseDN.includes('ou=People')) {
            suggestion = `\n\nSOLUTION:`;
            suggestion += `\nTry your exact bind DN as base DN: 'uid=your-monitor-user,${baseDN}'`;
            suggestion += `\nOR remove ldapBaseDN for Root DSE search`;
          } else {
            suggestion = `\n\nSOLUTION:`;
            suggestion += `\nTry your organization's base DN (e.g., ou=People,o=company)`;
            suggestion += `\nOR use your exact bind DN`;
          }
          throw new Error(`${errorDetails}${debugSection}${suggestion}`);
        } else if (responseType === 0x78) {
          throw new Error(`Search failed: Response type 0x78 indicates an Extended Response. This may be an unsupported operation or protocol mismatch.`);
        } else {
          throw new Error(`Search failed: Unexpected response type 0x${toHexSearch(responseType)} at position 8. Expected 0x64 (SearchResultEntry) or 0x65 (SearchResultDone).${baseDnHint}`);
        }
      }
    }

    const doneIndex = findSearchDoneIndex(searchRsp);
    const searchRspLength = searchRsp && searchRsp.length ? searchRsp.length : 0;
    
    console.log(`SearchResultDone analysis:`);
    console.log(`  Search response length: ${searchRspLength}`);
    console.log(`  SearchResultDone index: ${doneIndex}`);
    
    if (doneIndex === -1) {
      // If we didn't find SearchResultDone, but we got SearchResultDone at position 8, handle it
      if (searchRsp.length > 8 && searchRsp[8] === 0x65) {
        console.log('SearchResultDone found at position 8 - likely immediate completion');
        const resultCodePos = 12; // Typical position for result code in SearchResultDone
        if (searchRsp.length > resultCodePos) {
          const directResultCode = searchRsp[resultCodePos];
          console.log(`Direct result code at position ${resultCodePos}: 0x${toHexSearch(directResultCode)} (${directResultCode})`);
          if (directResultCode !== 0x00) {
            throw new Error(`Search failed: code 0x${toHexSearch(directResultCode)}`);
          }
          console.log('Search completed successfully with empty result set');
        } else {
          console.log('Warning: Could not determine result code from SearchResultDone');
        }
      } else {
        throw new Error('Search failed: No SearchResultDone message found');
      }
    } else {
      if (doneIndex + 4 >= searchRspLength) {
        throw new Error('Search failed: SearchResultDone message truncated');
      }
      const searchResultCode = searchRsp[doneIndex + 4];
      console.log(`Search result code at position ${doneIndex + 4}: 0x${toHexSearch(searchResultCode)} (${searchResultCode})`);
      if (searchResultCode !== 0x00) {
        throw new Error(`Search failed: code 0x${toHexSearch(searchResultCode)}`);
      }
      console.log('Search completed successfully');
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
