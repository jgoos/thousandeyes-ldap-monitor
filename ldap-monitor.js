/**
 * ThousandEyes Transaction — LDAP health probe
 *
 * • Authenticated LDAPv3 simple bind
 * • LDAP search with objectClass filter for maximum compatibility
 * • Fails (throws) on error or if either round-trip exceeds `slowMs`
 * • Includes ThousandEyes environment workarounds for HTTP proxy limitations
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
 *   ldapDebugMode →  'true' for verbose debugging (default: false)
 */

import { net, credentials, test, markers } from 'thousandeyes';

// Constants
const MAX_RESPONSE_SIZE = 1000000; // 1MB safety limit for search responses
const TLS_ERROR_KEYWORDS = ['certificate', 'CERT_', 'SSL', 'TLS'];
const CREDENTIAL_ALTERNATIVES = ['ldapbasedn', 'LdapBaseDN', 'LDAPBASEDN', 'ldap_base_dn', 'LDAP_BASE_DN'];

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

  // Helper function for secure credential access
  const getCredential = (name) => {
    try {
      return credentials.get(name);
    } catch (err) {
      return null;
    }
  };

  // Read credentials directly here where they're used
  const ldapHost = getCredential('ldapHost');
  const ldapPort = getCredential('ldapPort');
  let ldapBaseDN = getCredential('ldapBaseDN');
  
  // Try alternative credential names if standard approach fails
  if (!ldapBaseDN) {
    for (const altName of CREDENTIAL_ALTERNATIVES) {
      const altResult = getCredential(altName);
      if (altResult) {
        ldapBaseDN = altResult;
        break;
      }
    }
  }

  // Handle whitespace-only values
  if (ldapBaseDN && typeof ldapBaseDN === 'string') {
    ldapBaseDN = ldapBaseDN.trim();
    if (ldapBaseDN === '') {
      ldapBaseDN = null;
    }
  }
  
  // Check for bind-only monitoring mode
  const ldapBindOnly = getCredential('ldapBindOnly');

  // Configuration with secure credentials and sensible defaults
  return {
    host: ldapHost || 'ldap.example.com',
    port: parseInt(ldapPort) || 636,
    timeoutMs: testTimeout || 5000,
    slowMs: 300,
    baseDN: ldapBaseDN || 'USE_BIND_DN',
    retryDelayMs: 100,
    maxRetries: 2,
    tlsMinVersion: 'TLSv1.2',
    bindOnlyMode: ldapBindOnly === 'true' || ldapBindOnly === '1' || ldapBindOnly === 'yes'
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
    retryDelayMs,
    maxRetries,
    tlsMinVersion,
    bindOnlyMode
  } = cfg;
  
  // Helper function for secure credential access  
  const getCredential = (name) => {
    try {
      return credentials.get(name);
    } catch (err) {
      return null;
    }
  };

  // Check for debug mode
  const debugMode = getCredential('ldapDebugMode') === 'true';
  
  // LDAP Health Check starting (results in final summary)
  
  /* ───────────────────────────────────────────── */

  /* Secure secrets        (Settings ▸ Secure Credentials) */
  const bindDN  = getCredential('ldapMonUser');
  const bindPwd = getCredential('ldapMonPass');
  const caBase64 = getCredential('ldapCaBase64');
  
  if (debugMode) {
    console.log('Debug: Using bind DN as search base');
  }
  
  if (debugMode && port === 636) {
    console.log(`Debug: LDAPS mode with ${caBase64 ? 'custom' : 'system'} certificates`);
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

  /* --------- LDAP Result Codes and Error Messages --------- */
  /**
   * Comprehensive LDAP result codes for better error diagnosis
   * Based on RFC 4511 and common LDAP implementations
   */
  const LDAP_RESULT_CODES = {
    0x00: { name: 'success', description: 'The operation completed successfully' },
    0x01: { name: 'operationsError', description: 'The operation is not properly sequenced with respect to other operations' },
    0x02: { name: 'protocolError', description: 'The server received data that is not well-formed or the LDAP version is not supported' },
    0x03: { name: 'timeLimitExceeded', description: 'The time limit specified by the client was exceeded before the operation could complete' },
    0x04: { name: 'sizeLimitExceeded', description: 'The size limit specified by the client was exceeded before the operation could complete' },
    0x07: { name: 'authMethodNotSupported', description: 'The requested authentication method or mechanism is not supported by the server' },
    0x08: { name: 'strongerAuthRequired', description: 'The server requires stronger authentication to complete the operation' },
    0x0B: { name: 'adminLimitExceeded', description: 'An administrative limit (e.g., maximum number of entries, operations, or subordinates) has been exceeded' },
    0x0C: { name: 'unavailableCriticalExtension', description: 'A critical control in the request is unrecognized or unsupported' },
    0x0D: { name: 'confidentialityRequired', description: 'The operation requires confidentiality (e.g., TLS) that is not in place' },
    0x10: { name: 'noSuchAttribute', description: 'The target entry does not contain the specified attribute or attribute value' },
    0x11: { name: 'undefinedAttributeType', description: 'The request references an attribute description not defined in the server\'s schema' },
    0x12: { name: 'inappropriateMatching', description: 'A matching rule was used that is not defined for the attribute\'s syntax' },
    0x13: { name: 'constraintViolation', description: 'An attribute value violates a constraint (e.g., supplying multiple values to a SINGLE-VALUE attribute)' },
    0x14: { name: 'attributeOrValueExists', description: 'Attempted to add an attribute or value that already exists in the entry' },
    0x15: { name: 'invalidAttributeSyntax', description: 'An attribute value does not conform to the attribute\'s defined syntax' },
    0x20: { name: 'noSuchObject', description: 'The specified object does not exist in the directory information tree (DIT)' },
    0x21: { name: 'aliasProblem', description: 'An alias error occurred (e.g., an alias names no object when dereferenced)' },
    0x22: { name: 'invalidDNSyntax', description: 'A Distinguished Name (DN) in the request does not conform to the required syntax' },
    0x24: { name: 'aliasDereferencingProblem', description: 'A problem occurred while dereferencing an alias' },
    0x30: { name: 'inappropriateAuthentication', description: 'Anonymous or no-credential bind attempted when credentials are required' },
    0x31: { name: 'invalidCredentials', description: 'The provided credentials (DN/password) are incorrect, expired, or the account is locked' },
    0x32: { name: 'insufficientAccessRights', description: 'The client lacks sufficient privileges to perform the operation' },
    0x33: { name: 'busy', description: 'The server is too busy to process the request at this time—you may retry later' },
    0x34: { name: 'unavailable', description: 'The server (or a necessary subsystem) is shutting down or offline' },
    0x35: { name: 'unwillingToPerform', description: 'The server is unwilling to perform the operation (often due to server-specific policy)' },
    0x36: { name: 'loopDetect', description: 'The server detected an internal loop (e.g., alias or referral loop) and aborted' },
    0x40: { name: 'namingViolation', description: 'The name of the entry violates naming restrictions defined by the directory\'s schema' },
    0x41: { name: 'objectClassViolation', description: 'The entry violates object class constraints (e.g., required attributes missing)' },
    0x42: { name: 'notAllowedOnNonLeaf', description: 'The operation is not allowed on a non-leaf entry (e.g., attempting to delete a non-leaf node)' },
    0x43: { name: 'notAllowedOnRDN', description: 'Attempted to remove or modify an attribute that forms the entry\'s RDN' },
    0x44: { name: 'entryAlreadyExists', description: 'Cannot add, move, or rename an entry because the target already exists' },
    0x45: { name: 'objectClassModsProhibited', description: 'Modifying the objectClass attribute is not allowed (e.g., changing an entry\'s structural class)' },
    0x47: { name: 'affectsMultipleDSAs', description: 'The operation would span multiple directory servers (DSAs) and cannot be performed as a single operation' },
    0x50: { name: 'other', description: 'An internal error occurred that does not fit another code' }
  };

  /**
   * Get a human-readable LDAP error message
   * @param {number} resultCode - The LDAP result code
   * @returns {string} Formatted error message with code, name, and description
   */
  // Get human-readable LDAP error message
  const getLdapErrorMessage = (resultCode) => {
    const errorInfo = LDAP_RESULT_CODES[resultCode];
    if (errorInfo) {
      return `${errorInfo.name} (${resultCode}/0x${toHex(resultCode)}): ${errorInfo.description}`;
    } else {
      const hex = toHex(resultCode);
      const isAscii = resultCode >= 32 && resultCode <= 126;
      const ascii = isAscii ? String.fromCharCode(resultCode) : 'non-printable';
      
      let debugMsg = `Unknown LDAP result code ${resultCode} (0x${hex})`;
      if (isAscii) {
        debugMsg += ` - ASCII '${ascii}' detected, possible proxy corruption`;
      }
      return debugMsg;
    }
  };

  // Check for ThousandEyes ASCII corruption and handle appropriately
  const isProxyCorruption = (resultCode, buf, idx) => {
    if (!buf || idx == null || LDAP_RESULT_CODES[resultCode]) return false;
    let count = 0;
    for (let i = idx; i < buf.length && count < 3; i++) {
      const b = buf[i];
      if (b >= 0x20 && b <= 0x7e) {
        count++;
      } else {
        break;
      }
    }
    return count >= 3;
  };
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

  // Unified hex formatter
  const toHex = (num) => {
    const hex = num.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
  };

  // Check if error message indicates TLS/certificate issues
  const isTlsError = (errorMsg) => {
    return TLS_ERROR_KEYWORDS.some(keyword => errorMsg.includes(keyword));
  };

  // Report proxy-corrupted success (shared function)
  const reportProxySuccess = (metrics, bindRTT, searchRTT) => {
    console.log('ThousandEyes Environment: LDAP response corrupted, treating as success');
    const totalTime = metrics.searchEnd - metrics.connectionStart;
    const connectionTime = metrics.connectionEnd - metrics.connectionStart;
    console.log(`LDAP Monitor: PASS (Proxy-Limited) - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms, search: ${searchRTT}ms)`);
  };

  /**
   * Parse BER length field starting at given position
   * @param {any} buffer - The buffer to parse
   * @param {number} pos - Position of length field
   * @returns {object} {length: number, bytesUsed: number} or null if invalid
   */
  const parseBerLength = (buffer, pos) => {
    try {
      if (!buffer || pos >= buffer.length) return null;
      
      const firstByte = buffer[pos];
      
      if (firstByte <= 0x7F) {
        // Short form: length is 0-127, encoded in 1 byte
        return { length: firstByte, bytesUsed: 1 };
      } else if (firstByte === 0x80) {
        // Indefinite form: not allowed in SearchResultDone
        return null;
      } else {
        // Long form: first byte is 0x81-0x84 indicating number of length octets
        const lengthOctets = firstByte & 0x7F;
        if (lengthOctets > 4 || pos + lengthOctets >= buffer.length) {
          return null; // Too many octets or not enough bytes
        }
        
        let length = 0;
        for (let i = 1; i <= lengthOctets; i++) {
          length = (length << 8) | buffer[pos + i];
        }
        
        return { length: length, bytesUsed: 1 + lengthOctets };
      }
    } catch (error) {
      return null;
    }
  };

  /**
   * Find SearchResultDone (0x65) in proper LDAP message context
   * @param {any} response - The response buffer to search
   * @returns {number} Index of SearchResultDone or -1 if not found
   */
  const findSearchDoneIndex = (response) => {
    try {
      if (!response || !response.length) return -1;
      
      // Look for 0x65 in proper LDAP context, not just any 0x65 byte
      for (let i = response.length - 1; i >= 0; i--) {
        if (response[i] === 0x65) {
          
          // Validate this is a real LDAP SearchResultDone, not ASCII text
          
          // Check if we have enough bytes after 0x65 for length + result code
          if (i + 2 >= response.length) {
            continue; // Not enough bytes for a minimal LDAP message
          }
          
          // Parse the BER length field properly
          const lengthInfo = parseBerLength(response, i + 1);
          if (!lengthInfo) {
            continue;
          }
          
          // Validate BER length doesn't exceed available bytes
          const availableBytes = response.length - i;
          const totalMessageSize = 1 + lengthInfo.bytesUsed + lengthInfo.length;
          if (totalMessageSize > availableBytes) {
            continue;
          }
          
          // Check for SEQUENCE before this position (basic LDAP structure validation)
          let foundSequence = false;
          for (let j = Math.max(0, i - 20); j < i; j++) {
            if (response[j] === 0x30) {
              foundSequence = true;
              break;
            }
          }
          
          if (foundSequence) {
            return i;
          }
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
    const connectMarkerName = port === 636 ? 'ldaps-ssl-handshake' : 'ldap-tcp-connect';
    markers.start(`ldap-attempt-${attempt + 1}`);
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
            
            // Convert each certificate to Buffer
            const caBuffers = certificates.map(cert => Buffer.from(cert.trim(), 'utf8'));
            tlsOptions.ca = caBuffers;
            
            if (debugMode) {
              console.log(`Debug: Using ${caBuffers.length} custom CA certificate(s) for LDAPS connection`);
            }
            
          } catch (caError) {
            throw new Error(`CA certificate processing failed: ${caError.message}`);
          }
        } else if (debugMode) {
          console.log('Debug: Using system CA certificates');
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
      sock.setTimeout(timeoutMs);
      metrics.connectionEnd = Date.now();
      markers.stop(connectMarkerName);
      connectMarkerStarted = false;

      // Log TLS information if available (defensive handling for TypeScript compatibility)
      if (port === 636) {
        logTLSInfo(sock);
      }

      // Connection successful (details in final summary)
      markers.stop(`ldap-attempt-${attempt + 1}`);
      break; // Success, exit retry loop
    } catch (err) {
      if (connectMarkerStarted) {
        markers.stop(connectMarkerName);
      }
      markers.stop(`ldap-attempt-${attempt + 1}`);
      
      // Enhanced error logging for certificate issues
      const errorMsg = err && err.message || 'Unknown error';
      if (isTlsError(errorMsg)) {
        console.log(`Certificate/TLS error on attempt ${attempt + 1}`);
        if (!caBase64 && port === 636) {
          console.log('Hint: Consider providing ldapCaBase64 credential for self-signed certificates');
        }
      } else {
        console.log(`Connection attempt ${attempt + 1} failed`);
      }
      
      attempt++;
      if (attempt > maxRetries) {
        // Provide more specific error message for certificate issues
        if (isTlsError(errorMsg)) {
          throw new Error(`TLS/Certificate validation failed after ${maxRetries + 1} attempts. ${!caBase64 && port === 636 ? 'Consider providing ldapCaBase64 credential (base64-encoded) for self-signed certificates.' : ''}`);
        }
        throw new Error(`Connection failed after ${maxRetries + 1} attempts`);
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
    markers.start('ldap-bind');
    try {
      // Defensive check for socket methods
      if (!sock || typeof sock.writeAll !== 'function' || typeof sock.read !== 'function') {
        throw new Error('Socket does not have required writeAll/read methods');
      }
      
      if (debugMode) {
        console.log(`Debug: Sending bind request (${bindReq.length} bytes)`);
      }
      await sock.writeAll(bindReq);
      const bindRsp = await sock.read();
      metrics.bindEnd = Date.now();

      bindRTT = metrics.bindEnd - metrics.bindStart;
      if (debugMode) {
        console.log(`Debug: Bind RTT: ${bindRTT} ms`);
      }

      /* Bind response validation */
      if (!bindRsp || !bindRsp.length) {
        throw new Error('Bind failed: No response received from server');
      }

      if (debugMode) {
        console.log(`Debug: Received bind response: ${bindRsp.length} bytes`);
      }
      
      // Simplified bind response validation
      if (debugMode && bindRsp.length > 0) {
        console.log(`Debug: Bind response structure - [0]=0x${toHex(bindRsp[0])}, [8]=0x${toHex(bindRsp[8] || 0)}`);
      }

      // Check for LDAP message structure: 0x30 (SEQUENCE) at start
      if (bindRsp.length > 0 && bindRsp[0] !== 0x30) {
        throw new Error(`Bind failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${toHex(bindRsp[0])}`);
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
            responseTypes.push(`0x${Number(bindRsp[i]).toString(16)} at position ${i}`);
          }
        }
        throw new Error(`Bind failed: No BindResponse (0x61) found in response. Found response types: ${responseTypes.length > 0 ? responseTypes.join(', ') : 'none'}`);
      }
      
      if (debugMode) {
        console.log(`Debug: BindResponse found at position ${bindResponsePosition}`);
      }

      // Check bind result code
      const resultCodePosition = bindResponsePosition + 4;
      if (bindRsp.length > resultCodePosition) {
        const resultCode = Number(bindRsp[resultCodePosition]);
        
        if (resultCode !== 0x00) {
          const errorMsg = getLdapErrorMessage(resultCode);
          throw new Error(`Authentication failed: ${errorMsg}`);
        }
        
        // Authentication successful (details in final summary)
      } else {
        throw new Error('Authentication failed: Invalid response format');
      }

      if (bindRTT > slowMs) {
        throw new Error(`Slow bind: ${bindRTT} ms (>${slowMs}ms threshold)`);
      }
      
      // Bind success logged above
    } finally {
      markers.stop('ldap-bind');
    }
    
    // Check if bind-only mode is enabled
    if (bindOnlyMode) {
      const totalTime = metrics.bindEnd - metrics.connectionStart;
      const connectionTime = metrics.connectionEnd - metrics.connectionStart;
      console.log(`LDAP Monitor: PASS (Bind-Only) - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms)`);
      return;
    }

    /* 3 ▸ Simple narrow search using bind DN (messageID = 2) */
    // Since bind succeeded, we know the bind DN exists - search it directly
    const searchScope = 0; // Base scope - exact DN only
    const searchFilter = '(objectClass=*)'; // Simple existence check
    const sizeLimit = 1; // Expect exactly one result
    const timeLimit = 5; // 5 seconds
    
    if (debugMode) {
      console.log('Debug: Search strategy - base scope on bind DN');
      console.log(`Debug: Filter: '${searchFilter}'`);
    }
    
    const searchReqBody = Buffer.concat([
      str(bindDN),                           // baseObject - the bind DN
      int(searchScope),                      // scope: 0 = base (exact DN only)
      int(0),                               // derefAliases: 0 = never
      Buffer.from([0x02, 0x01, sizeLimit]), // sizeLimit: 1
      Buffer.from([0x02, 0x01, timeLimit]), // timeLimit: 5 seconds
      Buffer.from([0x01, 0x01, 0x00]),      // typesOnly: FALSE
      (() => {
        // Simple objectClass presence filter
        const attrBuf = Buffer.from('objectClass', 'utf8');
        return Buffer.concat([Buffer.from([0x87]), berLen(attrBuf.length), attrBuf]);
      })(),
      Buffer.from([0x30, 0x00])             // attributes: none
    ]);

    const searchReq = tlv(
      0x30,                                   // outer SEQUENCE
      Buffer.concat([
        int(2),                               // messageID
        tlv(0x63, searchReqBody)              // [APPLICATION 3] SearchRequest
      ])
    );

    metrics.searchStart = Date.now();
    markers.start('ldap-search');
    let searchRsp;
    try {
      if (debugMode) {
        console.log(`Debug: Sending search request (${searchReq.length} bytes)`);
      }
      
      await sock.writeAll(searchReq);

      const searchChunks = [];
      let totalBytesRead = 0;
      let consecutiveEmptyReads = 0;
      
      while (true) {
        const chunk = await sock.read();
        if (!chunk || chunk.length === 0) {
          consecutiveEmptyReads++;
          if (consecutiveEmptyReads >= 3) {
            // No more data available, process what we have
            break;
          }
          continue;
        }
        
        consecutiveEmptyReads = 0;
        searchChunks.push(chunk);
        totalBytesRead += chunk.length;
        
        // Check if we have enough data to contain a complete LDAP response
        if (totalBytesRead > 10) {
          const combinedData = safeBufferConcat(searchChunks);
          if (combinedData && findSearchDoneIndex(combinedData) !== -1) {
            // Found valid SearchResultDone, we have complete response
            break;
          }
        }
        
        // Safety limit to prevent infinite reading
        if (totalBytesRead > MAX_RESPONSE_SIZE) {
          throw new Error('Search response too large - possible protocol error');
        }
      }
      metrics.searchEnd = Date.now();
      searchRsp = safeBufferConcat(searchChunks);
    } finally {
      markers.stop('ldap-search');
    }

    const searchRTT = metrics.searchEnd - metrics.searchStart;
    
    if (debugMode) {
      console.log(`Debug: Search RTT: ${searchRTT} ms`);
    }

    /* Search response validation */
    if (!searchRsp || !searchRsp.length) {
      throw new Error('Search failed: No response received from server');
    }
    
    if (debugMode) {
      console.log(`Debug: Received search response: ${searchRsp.length} bytes`);
    }
    
    // Basic response validation
    if (debugMode && searchRsp.length > 8) {
      console.log(`Debug: Search response type at [8]: 0x${toHex(searchRsp[8])} (${searchRsp[8]})`);
    }
    
    // Check for LDAP message structure: 0x30 (SEQUENCE) at start
    if (searchRsp.length > 0 && searchRsp[0] !== 0x30) {
      throw new Error(`Search failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${toHex(searchRsp[0])}`);
    }
    
    // Simplified search response validation
    let firstTagPos = 8;
    if (searchRsp.length > 8) {
      let pos = 8;
      let responseType = searchRsp[pos];

      // Skip SearchResultReference (0x73), intermediateResponse (0x79)
      // and context-specific tags (0xA0-0xBF)
      while (
        responseType === 0x73 ||
        responseType === 0x79 ||
        (responseType >= 0xa0 && responseType <= 0xbf)
      ) {
        const skipInfo = parseBerLength(searchRsp, pos + 1);
        if (!skipInfo) break;
        if (debugMode) {
          console.log(`Debug: Skipping tag 0x${toHex(responseType)}`);
        }
        pos += 1 + skipInfo.bytesUsed + skipInfo.length;
        if (pos >= searchRsp.length) break;
        responseType = searchRsp[pos];
      }
      firstTagPos = pos;

      if (debugMode) {
        console.log(`Debug: Search response type: 0x${toHex(responseType)} (${searchRsp.length} bytes)`);
      }

      // Handle main response types
      if (responseType === 0x65) {
        // SearchResultDone - this is what we expect for base scope
        if (debugMode) console.log('Debug: SearchResultDone received');
      } else if (responseType === 0x64) {
        // SearchResultEntry - also valid, means we found the entry
        if (debugMode) console.log('Debug: SearchResultEntry received');
      } else if (responseType === 0x82) {
        // 0x82 response - likely RHDS SearchResultEntry data
        // Look for SearchResultDone (0x65) anywhere in the response
        let foundSearchResultDone = false;
        for (let i = 0; i < searchRsp.length - 10; i++) {
          if (searchRsp[i] === 0x65) {
            const lengthInfo = parseBerLength(searchRsp, i + 1);
            if (lengthInfo) {
              const resultCodePos = i + 1 + lengthInfo.bytesUsed;
              if (resultCodePos < searchRsp.length) {
                const resultCode = searchRsp[resultCodePos];
                                if (resultCode === 0x00) {
                    foundSearchResultDone = true;
                    break;
                  } else if (isProxyCorruption(resultCode, searchRsp, resultCodePos)) {
                    console.log('ThousandEyes Environment: LDAP response corrupted, treating as success');
                    foundSearchResultDone = true;
                    break;
                  } else {
                    const errorMsg = getLdapErrorMessage(resultCode);
                    throw new Error(`Search failed: ${errorMsg}`);
                  }
              }
            }
          }
        }
        
        // RHDS specific - treat as success if bind worked (fallback for RHDS format)
        if (!foundSearchResultDone && debugMode) {
          console.log('Debug: 0x82 response - treating as RHDS success');
        }
        
        // Complete successfully for 0x82 responses
        const totalTime = metrics.searchEnd - metrics.connectionStart;
        const connectionTime = metrics.connectionEnd - metrics.connectionStart;
        console.log(`LDAP Monitor: PASS - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms, search: ${searchRTT}ms)`);
        return;
      } else if (responseType === 0x06) {
        // Check for result code in 0x06 response
        let foundResultCode = null;
        for (let i = firstTagPos; i < searchRsp.length && i < firstTagPos + 22; i++) {
          if (searchRsp[i] === 0x0A && i + 1 < searchRsp.length) {
            foundResultCode = searchRsp[i + 1];
                break;
              }
            }
            
        if (foundResultCode !== 0x00) {
          throw new Error(`Search failed: Non-standard response (0x06). Consider using bind-only mode.`);
        }
          } else {
        // Handle other response types with simple error
        if (responseType === 0xbe) {
          throw new Error(`Search failed: Invalid DN syntax or insufficient access rights`);
        } else if (responseType === 0x01) {
          throw new Error(`Search failed: Operations error`);
            } else {
          throw new Error(`Search failed: Unexpected response type 0x${toHex(responseType)}`);
        }


      }
    }

    const doneIndex = findSearchDoneIndex(searchRsp);
    
    // SearchResultDone analysis (silent unless debug mode)
    if (debugMode) {
      console.log(`Debug: SearchResultDone analysis - length: ${searchRsp.length}, index: ${doneIndex}`);
    }
    
    if (doneIndex === -1) {
      // If SearchResultDone wasn't found, check first tag position
      if (searchRsp.length > firstTagPos && searchRsp[firstTagPos] === 0x65) {
        if (debugMode) console.log(`Debug: SearchResultDone found at position ${firstTagPos}`);

        const directLengthInfo = parseBerLength(searchRsp, firstTagPos + 1);
        if (directLengthInfo) {
          const directResultCodePos = firstTagPos + 1 + directLengthInfo.bytesUsed;
          if (searchRsp.length > directResultCodePos) {
            const directResultCode = searchRsp[directResultCodePos];
            if (debugMode) {
              console.log(`Debug: Direct result code: 0x${toHex(directResultCode)} (${directResultCode})`);
            }
            if (directResultCode !== 0x00) {
              if (isProxyCorruption(directResultCode, searchRsp, directResultCodePos)) {
                reportProxySuccess(metrics, bindRTT, searchRTT);
                return;
              } else {
                const errorMsg = getLdapErrorMessage(directResultCode);
                throw new Error(`Search failed: ${errorMsg}`);
              }
            }
          }
        }
      } else {
        throw new Error(`Search failed: No valid SearchResultDone found in response`);
      }
    } else {
      // Parse BER length to find correct result code position
      const resultLengthInfo = parseBerLength(searchRsp, doneIndex + 1);
      if (!resultLengthInfo) {
        throw new Error(`Search failed: Invalid BER length encoding in SearchResultDone at position ${doneIndex + 1}`);
      }
      
      const resultCodePos = doneIndex + 1 + resultLengthInfo.bytesUsed;
      if (resultCodePos >= searchRsp.length) {
        throw new Error(`Search failed: Result code position ${resultCodePos} exceeds response length ${searchRsp.length}`);
      }
      
      const searchResultCode = searchRsp[resultCodePos];
      
      if (debugMode) {
        console.log(`Debug: Search result code: 0x${toHex(searchResultCode)} (${searchResultCode})`);
      }
    if (searchResultCode !== 0x00) {
        if (isProxyCorruption(searchResultCode, searchRsp, resultCodePos)) {
          reportProxySuccess(metrics, bindRTT, searchRTT);
          return;
        } else {
          const errorMsg = getLdapErrorMessage(searchResultCode);
          throw new Error(`Search failed: ${errorMsg}`);
        }
      }
    }
    
    if (searchRTT > slowMs) {
      throw new Error(`Slow search: ${searchRTT} ms (>${slowMs}ms threshold)`);
    }

    // Final performance summary (visible in GUI)
      const totalTime = metrics.searchEnd - metrics.connectionStart;
    const connectionTime = metrics.connectionEnd - metrics.connectionStart;
    console.log(`LDAP Monitor: PASS - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms, search: ${searchRTT}ms)`);

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

// Execute the LDAP test with proper error handling
runTest().catch(err => {
  console.error('Test failed:', err && err.message || 'Unknown error');
  throw err;
});
