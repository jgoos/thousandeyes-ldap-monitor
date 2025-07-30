/**
 * ThousandEyes Transaction — LDAP health probe
 *
 * • Authenticated LDAPv3 simple bind
 * • LDAP search with objectClass filter for maximum compatibility
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
    // Test each credential individually with detailed analysis
    console.log('Testing ldapHost credential...');
    try {
      ldapHost = credentials.get('ldapHost');
      console.log(`ldapHost raw result:`, ldapHost);
      console.log(`ldapHost type: ${typeof ldapHost}`);
      console.log(`ldapHost length: ${ldapHost ? ldapHost.length : 'N/A'}`);
      const hostStatus = ldapHost ? `'${ldapHost}'` : 'NULL';
      debugInfo.push(`host=${hostStatus}`);
    } catch (hostErr) {
      console.log(`ldapHost error: ${hostErr.message}`);
      debugInfo.push(`host=ERROR:${hostErr.message}`);
    }
    
    console.log('Testing ldapPort credential...');
    try {
      ldapPort = credentials.get('ldapPort');
      console.log(`ldapPort raw result:`, ldapPort);
      console.log(`ldapPort type: ${typeof ldapPort}`);
      console.log(`ldapPort length: ${ldapPort ? ldapPort.length : 'N/A'}`);
      const portStatus = ldapPort ? `'${ldapPort}'` : 'NULL';
      debugInfo.push(`port=${portStatus}`);
    } catch (portErr) {
      console.log(`ldapPort error: ${portErr.message}`);
      debugInfo.push(`port=ERROR:${portErr.message}`);
    }
    
    console.log('Testing ldapBaseDN credential...');
    try {
      ldapBaseDN = credentials.get('ldapBaseDN');
      console.log(`ldapBaseDN raw result:`, ldapBaseDN);
      console.log(`ldapBaseDN type: ${typeof ldapBaseDN}`);
      console.log(`ldapBaseDN length: ${ldapBaseDN ? ldapBaseDN.length : 'N/A'}`);
      console.log(`ldapBaseDN === null: ${ldapBaseDN === null}`);
      console.log(`ldapBaseDN === undefined: ${ldapBaseDN === undefined}`);
      console.log(`ldapBaseDN === '': ${ldapBaseDN === ''}`);
      
      // Check for whitespace-only values
      if (ldapBaseDN && typeof ldapBaseDN === 'string') {
        console.log(`ldapBaseDN trimmed: '${ldapBaseDN.trim()}'`);
        console.log(`ldapBaseDN trimmed length: ${ldapBaseDN.trim().length}`);
      }
      
      const baseDnStatus = ldapBaseDN ? `'${ldapBaseDN}'` : 'NULL';
      debugInfo.push(`baseDN=${baseDnStatus}`);
    } catch (baseDnErr) {
      console.log(`ldapBaseDN error: ${baseDnErr.message}`);
      debugInfo.push(`baseDN=ERROR:${baseDnErr.message}`);
    }
    
    // Test auth credentials for comparison
    console.log('Testing auth credentials for comparison...');
    try {
      const testUser = credentials.get('ldapMonUser');
      const testPass = credentials.get('ldapMonPass');
      console.log(`ldapMonUser type: ${typeof testUser}`);
      console.log(`ldapMonPass type: ${typeof testPass}`);
      debugInfo.push(`user=${testUser ? 'OK' : 'NULL'}`);
      debugInfo.push(`pass=${testPass ? 'OK' : 'NULL'}`);
    } catch (authErr) {
      console.log(`Auth credential error: ${authErr.message}`);
      debugInfo.push(`auth_err=${authErr.message}`);
    }
    
    // Try alternative credential access methods if standard approach fails
    if (!ldapBaseDN) {
      console.log('Trying alternative credential access methods...');
      
      // Try with different casing
      const alternatives = ['ldapbasedn', 'LdapBaseDN', 'LDAPBASEDN', 'ldap_base_dn', 'LDAP_BASE_DN'];
      for (const altName of alternatives) {
        try {
          console.log(`Trying credential name: ${altName}`);
          const altResult = credentials.get(altName);
          if (altResult) {
            console.log(`SUCCESS with ${altName}: '${altResult}'`);
            ldapBaseDN = altResult;
            debugInfo.push(`baseDN_alt=${altName}:'${altResult}'`);
            break;
          }
        } catch (altErr) {
          console.log(`${altName} failed: ${altErr.message}`);
        }
      }
    }
    
  } catch (e) {
    debugInfo.push(`ERROR=${e.message}`);
    console.log(`CREDENTIAL ERROR: ${e.message}`);
    console.log(`Error stack: ${e.stack}`);
  }
  
  // Log for console visibility
  console.log('=== CREDENTIAL DEBUG ===');
  console.log(debugInfo.join(' | '));
  console.log('=== END DEBUG ===');
  
  // Debug info is available in console logs and will be reconstructed in error messages

  // Handle whitespace-only values
  if (ldapBaseDN && typeof ldapBaseDN === 'string') {
    ldapBaseDN = ldapBaseDN.trim();
    if (ldapBaseDN === '') {
      console.log('ldapBaseDN contained only whitespace, treating as null');
      ldapBaseDN = null;
    }
  }
  
  console.log(`Final credential values before config creation:`);
  console.log(`- ldapHost: ${ldapHost ? `'${ldapHost}'` : 'null'}`);
  console.log(`- ldapPort: ${ldapPort ? `'${ldapPort}'` : 'null'}`);
  console.log(`- ldapBaseDN: ${ldapBaseDN ? `'${ldapBaseDN}'` : 'null'}`);
  
  // Configuration with secure credentials and sensible defaults
  return {
    host: ldapHost || 'ldap.example.com',                   // Override via ldapHost credential
    port: parseInt(ldapPort) || 636,                        // Override via ldapPort credential (389 = LDAP, 636 = LDAPS)
    timeoutMs: testTimeout || 5000,                         // socket timeout from test settings
    slowMs: 300,                                            // alert threshold in ms
    baseDN: ldapBaseDN || '',                               // Override via ldapBaseDN credential ('' = Root DSE - may not work on all servers)
    fallbackSearch: !ldapBaseDN,                            // Use fallback search strategy if no base DN provided
    filterAttr: 'objectClass',                               // use objectClass for better compatibility across LDAP servers
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
  const getLdapErrorMessage = (resultCode) => {
    const errorInfo = LDAP_RESULT_CODES[resultCode];
    if (errorInfo) {
      return `${errorInfo.name} (${resultCode}/0x${resultCode.toString(16)}): ${errorInfo.description}`;
    } else {
      // Enhanced debugging for unknown result codes
      const hex = resultCode.toString(16);
      const ascii = (resultCode >= 32 && resultCode <= 126) ? String.fromCharCode(resultCode) : 'non-printable';
      const isAscii = resultCode >= 32 && resultCode <= 126;
      
      let debugMsg = `Unknown LDAP result code ${resultCode} (0x${hex})`;
      
      if (isAscii) {
        debugMsg += `\n\nDEBUG ANALYSIS:\n`;
        debugMsg += `- This byte (0x${hex}) represents ASCII character '${ascii}'\n`;
        debugMsg += `- This suggests we may be reading text data instead of LDAP protocol bytes\n`;
        debugMsg += `- The SearchResultDone detection or BER length parsing may have errors\n`;
        debugMsg += `- Check the hex dump above to verify the actual LDAP message structure\n`;
        debugMsg += `\nPOSSIBLE CAUSES:\n`;
        debugMsg += `1. False positive SearchResultDone detection (reading ASCII 'e' as 0x65)\n`;
        debugMsg += `2. Incorrect BER length parsing leading to wrong result code position\n`;
        debugMsg += `3. Server response contains mixed LDAP protocol and text data\n`;
        debugMsg += `4. Response truncation or corruption during transmission\n`;
        debugMsg += `\nSOLUTIONS:\n`;
        debugMsg += `1. Review the hex dump for proper LDAP message structure\n`;
        debugMsg += `2. Verify BER length calculation matches actual message format\n`;
        debugMsg += `3. Check if server uses non-standard LDAP response encoding\n`;
        debugMsg += `4. Try base scope (0) instead of subtree scope (2) for simpler responses`;
      } else {
        debugMsg += `\n\nThis is not a standard LDAP result code (valid range: 0-80/0x00-0x50)`;
      }
      
      return debugMsg;
    }
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
   * Helper function for hex formatting (compatible with older JS)
   * @param {number} num - Number to format as hex
   * @returns {string} Two-digit hex string
   */
  const toHexSearch = (num) => {
    const hex = num.toString(16);
    return hex.length === 1 ? '0' + hex : hex;
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
   * Intelligently find SearchResultDone (0x65) in proper LDAP message context
   * @param {any} response - The response buffer to search
   * @returns {number} Index of valid SearchResultDone or -1 if not found
   */
  const findSearchDoneIndex = (response) => {
    try {
      if (!response || !response.length) return -1;
      
      // Look for 0x65 in proper LDAP context, not just any 0x65 byte
      // SearchResultDone should be followed by proper LDAP length encoding
      for (let i = response.length - 1; i >= 0; i--) {
        if (response[i] === 0x65) {
          // Validate this is a real LDAP SearchResultDone, not ASCII text
          
          // Check if we have enough bytes after 0x65 for length + result code
          if (i + 2 >= response.length) {
            console.log(`Found 0x65 at position ${i} but insufficient bytes for LDAP message (need ${i + 2}, have ${response.length})`);
            continue; // Not enough bytes for a minimal LDAP message
          }
          
          // Parse the BER length field properly
          const lengthInfo = parseBerLength(response, i + 1);
          if (!lengthInfo) {
            console.log(`Found 0x65 at position ${i} but invalid BER length encoding`);
            continue; // Not a valid BER length, likely ASCII text
          }
          
          // Critical: Validate BER length doesn't exceed available bytes
          const availableBytes = response.length - i;
          const totalMessageSize = 1 + lengthInfo.bytesUsed + lengthInfo.length; // tag + length field + content
          if (totalMessageSize > availableBytes) {
            console.log(`Found 0x65 at position ${i} but BER length ${lengthInfo.length} exceeds available bytes (need ${totalMessageSize}, have ${availableBytes}) - likely ASCII text`);
            continue; // BER length is impossible, definitely ASCII text
          }
          
          // Check if we have enough bytes for the result code
          const resultCodePos = i + 1 + lengthInfo.bytesUsed;
          if (resultCodePos >= response.length) {
            console.log(`Found 0x65 at position ${i} but insufficient bytes for result code (need ${resultCodePos + 1}, have ${response.length})`);
            continue; // Not enough bytes for result code
          }
          
          // Additional validation: check if this 0x65 is preceded by reasonable LDAP structure
          // Look for SEQUENCE (0x30) somewhere before this position
          let foundSequenceBefore = false;
          for (let j = Math.max(0, i - 20); j < i; j++) {
            if (response[j] === 0x30) {
              foundSequenceBefore = true;
              break;
            }
          }
          
          if (!foundSequenceBefore) {
            console.log(`Found 0x65 at position ${i} but no SEQUENCE (0x30) found in preceding 20 bytes - likely ASCII text`);
            continue; // No LDAP message structure found before this 0x65
          }
          
          console.log(`Found valid SearchResultDone (0x65) at position ${i} with proper LDAP context`);
          console.log(`  BER length: ${lengthInfo.length} bytes (${lengthInfo.bytesUsed} octets used)`);
          console.log(`  Result code position: ${resultCodePos}`);
          
          // Show context around this SearchResultDone for verification
          const contextStart = Math.max(0, i - 10);
          const contextEnd = Math.min(response.length, resultCodePos + 5);
          console.log(`  Context hex dump (positions ${contextStart}-${contextEnd-1}):`);
          for (let j = contextStart; j < contextEnd; j++) {
            const byte = response[j];
            const ascii = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            let marker = '';
            if (j === i) marker = ' <-- SearchResultDone';
            else if (j === i + 1) marker = ' <-- BER length';
            else if (j === resultCodePos) marker = ' <-- Result code';
            console.log(`    [${j}] = 0x${toHexSearch(byte)} (${byte}) '${ascii}'${marker}`);
          }
          
          return i; // This looks like a real LDAP SearchResultDone
        }
      }
      
      console.log('No valid SearchResultDone found in LDAP message context');
      return -1;
    } catch (error) {
      console.log(`Error in findSearchDoneIndex: ${error.message}`);
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
        throw new Error(`Bind failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${Number(bindRsp[0]).toString(16)}`);
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
      
      console.log(`Found BindResponse (0x61) at position ${bindResponsePosition}`);
      
      // Check for the traditional position first (position 8)
      if (bindRsp.length > 8 && bindRsp[8] !== 0x61) {
        if (bindResponsePosition !== 8) {
          console.log(`Warning: BindResponse found at position ${bindResponsePosition}, not the expected position 8`);
        } else {
          throw new Error(`Bind failed: Unexpected response type 0x${Number(bindRsp[8]).toString(16)} (expected 0x61)`);
        }
      }

      // Check result code - adjust position based on where BindResponse was found
      const resultCodePosition = bindResponsePosition + 4; // Result code typically 4 bytes after BindResponse
      if (bindRsp.length > resultCodePosition) {
        const resultCode = Number(bindRsp[resultCodePosition]);
        const resultHex = resultCode.toString(16);
        const paddedHex = resultHex.length === 1 ? '0' + resultHex : resultHex;
        console.log(`Result code at position ${resultCodePosition}: 0x${paddedHex} (${resultCode})`);
        
        if (resultCode !== 0x00) {
          const errorMsg = getLdapErrorMessage(resultCode);
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
    console.log(`Note: Using objectClass filter for maximum LDAP server compatibility`);
    if (baseDN === '') {
      console.log(`Search type: Root DSE search (base DN is empty)`);
    } else {
      console.log(`Search type: Organizational DN search on '${baseDN}'`);
    }
    console.log(`Search target: base DN '${baseDN}' with ${searchScope === 0 ? 'base scope (0) - searching only the exact DN object' : 'subtree scope (2) - searching beneath the DN'}`);
    
    // For debugging: log what we expect to find
    if (baseDN.includes('ou=People') && searchScope === 2) {
      console.log(`Info: Subtree scope search on organizational unit should find objects beneath it.`);
      console.log(`Using objectClass filter for broad compatibility across different LDAP implementations`);
    } else if (baseDN === '') {
      console.log(`Info: Root DSE search should return server information and available naming contexts`);
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
      } else if (responseType === 0x82) {
        // Handle 0x82 separately before the general error handling
        console.log('Received response type 0x82 - checking for valid LDAP response...');
        
        // Enhanced debugging for 0x82 response
        console.log('Full response analysis for 0x82:');
        for (let i = 0; i < (searchRsp.length < 20 ? searchRsp.length : 20); i++) {
          console.log(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})`);
        }
        
        // Check if this might be a SearchResultDone with context-specific encoding
        let foundResultCode = null;
        for (let i = 8; i < searchRsp.length && i < 30; i++) {
          if (searchRsp[i] === 0x0A) { // ENUMERATED result code
            if (i + 1 < searchRsp.length) {
              foundResultCode = searchRsp[i + 1];
              console.log(`Found potential result code at position ${i + 1}: 0x${toHexSearch(foundResultCode)} (${foundResultCode})`);
              break;
            }
          }
        }
        
        if (foundResultCode === 0x00) {
          console.log('Response type 0x82 contains success result code (0x00) - treating as successful search completion');
          console.log('Continuing with search completion processing...');
          // Continue to the SearchResultDone analysis below
        } else {
          // Handle error case for 0x82
          const errorDetails = `LDAP Search Failed: Response type 0x82 with result code 0x${foundResultCode ? toHexSearch(foundResultCode) : 'unknown'}`;
          let debugSection = `\n\nDEBUG INFORMATION:`;
          debugSection += `\n- Response type 0x82 may indicate a context-specific LDAP message encoding`;
                        debugSection += `\n- Search was: base='${baseDN}', scope=2, filter='(objectClass=*)'`;
          debugSection += `\n- This suggests the search reached the server but returned an error`;
          
          let solution = `\n\nPOSSIBLE SOLUTIONS:`;
          solution += `\n1. Try using your exact bind DN as the base DN instead of '${baseDN}'`;
          solution += `\n2. Try removing the ldapBaseDN credential to use Root DSE search`;
          solution += `\n3. Try base scope (0) instead of subtree scope (2) for more limited search`;
          solution += `\n4. Check if the user has proper search permissions on '${baseDN}'`;
          solution += `\n5. The server may use non-standard LDAP response encoding`;
          
          throw new Error(`${errorDetails}${debugSection}${solution}`);
        }
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
        } else if (responseType === 0x10) {
          // 0x10 is a SEQUENCE tag - this might indicate the message structure is different
          console.log('Received response type 0x10 (SEQUENCE) - analyzing message structure...');
          
          // Enhanced debugging for 0x10 response
          console.log('Full response analysis for 0x10:');
          for (let i = 0; i < (searchRsp.length < 30 ? searchRsp.length : 30); i++) {
            console.log(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})`);
          }
          
          // Look for SearchResultEntry (0x64) or SearchResultDone (0x65) at different positions
          console.log('Scanning for LDAP response types throughout the message...');
          let foundEntries = [];
          let foundDone = [];
          
          for (let i = 0; i < searchRsp.length; i++) {
            if (searchRsp[i] === 0x64) {
              foundEntries.push(i);
              console.log(`Found SearchResultEntry (0x64) at position ${i}`);
            }
            if (searchRsp[i] === 0x65) {
              foundDone.push(i);
              console.log(`Found SearchResultDone (0x65) at position ${i}`);
            }
          }
          
          if (foundDone.length > 0) {
            console.log(`Response contains SearchResultDone at position(s): ${foundDone.join(', ')}`);
            console.log('This appears to be a valid LDAP response with different message structure');
            
            // Try to find the result code near the SearchResultDone
            const donePos = foundDone[foundDone.length - 1]; // Use last SearchResultDone
            let resultCode = null;
            
            // Look for result code in the next few bytes after SearchResultDone
            for (let i = donePos + 1; i < searchRsp.length && i < donePos + 10; i++) {
              if (searchRsp[i - 1] === 0x0A && searchRsp[i] >= 0x00 && searchRsp[i] <= 0x50) {
                resultCode = searchRsp[i];
                console.log(`Found result code ${resultCode} (0x${toHexSearch(resultCode)}) at position ${i}`);
                break;
              }
            }
            
            if (resultCode === 0x00) {
              console.log('Search completed successfully (result code 0x00) - different message structure but valid response');
              // Continue with normal processing
            } else if (resultCode !== null) {
              const errorMsg = getLdapErrorMessage(resultCode);
              throw new Error(`Search failed: ${errorMsg}`);
            } else {
              console.log('SearchResultDone found but could not determine result code - assuming success');
              // Continue with normal processing
            }
          } else if (foundEntries.length > 0) {
            console.log(`Response contains SearchResultEntry at position(s): ${foundEntries.join(', ')}`);
            console.log('This indicates search results were found - continuing processing');
            // Continue with normal processing
          } else {
            // No clear LDAP response types found - enhanced debugging
            const debugInfo = [];
            debugInfo.push(`0x10 SEQUENCE RESPONSE DEBUG:`);
            debugInfo.push(`- Response type 0x10 (SEQUENCE) found at position 8`);
            debugInfo.push(`- No SearchResultEntry (0x64) or SearchResultDone (0x65) found`);
            debugInfo.push(`- Search parameters: base='${baseDN}', scope=2, filter='(objectClass=*)'`);
            debugInfo.push(`- Total message length: ${searchRsp.length} bytes`);
            
            // Enhanced hex dump analysis
            debugInfo.push(`- Full message hex dump (first 50 bytes):`);
            const dumpLen = Math.min(50, searchRsp.length);
            for (let i = 0; i < dumpLen; i++) {
              const marker = i === 8 ? ' <-- Response type' : '';
              debugInfo.push(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})${marker}`);
            }
            
            // Look for any potential LDAP response patterns
            const potentialResponses = [];
            for (let i = 0; i < searchRsp.length; i++) {
              if (searchRsp[i] >= 0x60 && searchRsp[i] <= 0x78) {
                potentialResponses.push(`0x${toHexSearch(searchRsp[i])} at position ${i}`);
              }
            }
            
            if (potentialResponses.length > 0) {
              debugInfo.push(`- Potential LDAP response bytes found: ${potentialResponses.join(', ')}`);
            } else {
              debugInfo.push(`- No LDAP response bytes (0x60-0x78) found in entire message`);
            }
            
            // Look for common LDAP message patterns
            const sequence30Positions = [];
            for (let i = 0; i < searchRsp.length; i++) {
              if (searchRsp[i] === 0x30) {
                sequence30Positions.push(i);
              }
            }
            debugInfo.push(`- SEQUENCE (0x30) tags found at positions: ${sequence30Positions.join(', ')}`);
            
            debugInfo.push(`DIAGNOSTIC SUGGESTIONS:`);
            debugInfo.push(`1. This appears to be a valid LDAP message but with unexpected structure`);
            debugInfo.push(`2. The server may use non-standard response encoding`);
            debugInfo.push(`3. Try base scope (0) instead of subtree scope (2) for simpler response`);
            debugInfo.push(`4. Try using your exact bind DN as the base DN`);
            debugInfo.push(`5. Try removing ldapBaseDN credential to use Root DSE search`);
            debugInfo.push(`6. Consider that the search may have succeeded but response format is non-standard`);
            
            throw new Error(`LDAP Search Failed: Response type 0x10 (SEQUENCE) - no standard LDAP response types found\n\n${debugInfo.join('\n')}`);
          }
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
        
        // Parse BER length to find correct result code position
        const directLengthInfo = parseBerLength(searchRsp, 9);
        if (directLengthInfo) {
          const directResultCodePos = 9 + directLengthInfo.bytesUsed;
          if (searchRsp.length > directResultCodePos) {
            const directResultCode = searchRsp[directResultCodePos];
            console.log(`Direct result code at position ${directResultCodePos}: 0x${toHexSearch(directResultCode)} (${directResultCode})`);
            console.log(`  Direct SearchResultDone structure: tag=0x65 at 8, length=${directLengthInfo.length} (${directLengthInfo.bytesUsed} bytes), result=0x${toHexSearch(directResultCode)}`);
            if (directResultCode !== 0x00) {
              const errorMsg = getLdapErrorMessage(directResultCode);
              throw new Error(`Search failed: ${errorMsg}`);
            }
            console.log('Search completed successfully with empty result set');
          } else {
            console.log(`Warning: Could not determine result code - need position ${directResultCodePos} but only have ${searchRsp.length} bytes`);
          }
        } else {
          console.log('Warning: Could not parse BER length in direct SearchResultDone');
        }
      } else {
        // Enhanced debugging for missing SearchResultDone
        const debugInfo = [];
        debugInfo.push(`NO SEARCHRESULTDONE DEBUG:`);
        debugInfo.push(`- Total response length: ${searchRspLength} bytes`);
        debugInfo.push(`- SearchResultDone index: ${doneIndex} (not found)`);
        debugInfo.push(`- Search completed but no valid SearchResultDone marker found`);
        
        // Show response type analysis
        if (searchRsp.length > 8) {
          debugInfo.push(`- Response type at position 8: 0x${toHexSearch(searchRsp[8])} (${searchRsp[8]})`);
          
          // Scan for any 0x65 bytes in the response
          const found65Positions = [];
          for (let i = 0; i < searchRsp.length; i++) {
            if (searchRsp[i] === 0x65) {
              found65Positions.push(i);
            }
          }
          
          if (found65Positions.length > 0) {
            debugInfo.push(`- Found 0x65 bytes at positions: ${found65Positions.join(', ')}`);
            debugInfo.push(`- But none were recognized as valid SearchResultDone by findSearchDoneIndex()`);
          } else {
            debugInfo.push(`- No 0x65 (SearchResultDone) bytes found anywhere in response`);
          }
        }
        
        // Show hex dump of first and last parts of response
        const firstBytes = Math.min(20, searchRsp.length);
        const lastBytes = Math.min(20, searchRsp.length);
        
        debugInfo.push(`- First ${firstBytes} bytes of response:`);
        for (let i = 0; i < firstBytes; i++) {
          debugInfo.push(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})`);
        }
        
        if (searchRsp.length > 20) {
          debugInfo.push(`- Last ${lastBytes} bytes of response:`);
          for (let i = Math.max(0, searchRsp.length - lastBytes); i < searchRsp.length; i++) {
            debugInfo.push(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})`);
          }
        }
        
        debugInfo.push(`POSSIBLE CAUSES:`);
        debugInfo.push(`1. Server returned non-standard LDAP response format`);
        debugInfo.push(`2. Response is valid but uses different message structure`);
        debugInfo.push(`3. Message chunking issue - incomplete response received`);
        debugInfo.push(`4. Server sent error response in unexpected format`);
        
        throw new Error(`Search failed: No SearchResultDone message found\n\n${debugInfo.join('\n')}`);
      }
    } else {
      // Parse BER length to determine minimum required bytes
      const truncationLengthInfo = parseBerLength(searchRsp, doneIndex + 1);
      const minRequiredPos = truncationLengthInfo ? (doneIndex + 1 + truncationLengthInfo.bytesUsed) : (doneIndex + 4);
      
      if (minRequiredPos >= searchRspLength) {
        // Enhanced debugging for truncated SearchResultDone
        const debugInfo = [];
        debugInfo.push(`TRUNCATED SEARCHRESULTDONE DEBUG:`);
        debugInfo.push(`- SearchResultDone found at index: ${doneIndex}`);
        debugInfo.push(`- Total response length: ${searchRspLength} bytes`);
        if (truncationLengthInfo) {
          debugInfo.push(`- BER length: ${truncationLengthInfo.length} bytes (${truncationLengthInfo.bytesUsed} octets used)`);
          debugInfo.push(`- Need to read result code at position: ${minRequiredPos}`);
        } else {
          debugInfo.push(`- Could not parse BER length, assuming position: ${minRequiredPos}`);
        }
        debugInfo.push(`- Available bytes after SearchResultDone: ${searchRspLength - doneIndex}`);
        debugInfo.push(`- Missing bytes: ${minRequiredPos - searchRspLength + 1}`);
        
        // Show hex dump around the SearchResultDone position
        const start = Math.max(0, doneIndex - 5);
        const end = Math.min(searchRspLength, doneIndex + 10);
        debugInfo.push(`- Hex dump around SearchResultDone (positions ${start}-${end-1}):`);
        for (let i = start; i < end; i++) {
          const marker = i === doneIndex ? ' <-- SearchResultDone' : '';
          debugInfo.push(`  [${i}] = 0x${toHexSearch(searchRsp[i])} (${searchRsp[i]})${marker}`);
        }
        
        // Provide solutions
        debugInfo.push(`POSSIBLE CAUSES:`);
        debugInfo.push(`1. Server sent incomplete LDAP message (network issue)`);
        debugInfo.push(`2. Message chunking issue - response split across multiple reads`);
        debugInfo.push(`3. Non-standard LDAP message format from server`);
        debugInfo.push(`4. SearchResultDone detected incorrectly (false positive)`);
        
        throw new Error(`Search failed: SearchResultDone message truncated\n\n${debugInfo.join('\n')}`);
      }
      // Parse BER length to find correct result code position
      const resultLengthInfo = parseBerLength(searchRsp, doneIndex + 1);
      if (!resultLengthInfo) {
        throw new Error(`Search failed: Invalid BER length encoding in SearchResultDone at position ${doneIndex + 1}`);
      }
      
      const resultCodePos = doneIndex + 1 + resultLengthInfo.bytesUsed;
      if (resultCodePos >= searchRspLength) {
        throw new Error(`Search failed: Result code position ${resultCodePos} exceeds response length ${searchRspLength}`);
      }
      
      const searchResultCode = searchRsp[resultCodePos];
      console.log(`Search result code at position ${resultCodePos}: 0x${toHexSearch(searchResultCode)} (${searchResultCode})`);
      console.log(`  SearchResultDone structure: tag=0x65 at ${doneIndex}, length=${resultLengthInfo.length} (${resultLengthInfo.bytesUsed} bytes), result=0x${toHexSearch(searchResultCode)}`);
      
      // Enhanced debugging for result code validation
      console.log(`ENHANCED RESULT CODE DEBUG:`);
      console.log(`  doneIndex: ${doneIndex}`);
      console.log(`  BER length value: ${resultLengthInfo.length}`);
      console.log(`  BER length bytes used: ${resultLengthInfo.bytesUsed}`);
      console.log(`  Calculated result code position: ${resultCodePos}`);
      console.log(`  Response length: ${searchRspLength}`);
      
      // Show detailed hex dump around result code position
      const debugStart = Math.max(0, doneIndex - 5);
      const debugEnd = Math.min(searchRspLength, resultCodePos + 10);
      console.log(`  Hex dump (positions ${debugStart}-${debugEnd-1}):`);
      for (let i = debugStart; i < debugEnd; i++) {
        const byte = searchRsp[i];
        const ascii = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        let marker = '';
        if (i === doneIndex) marker = ' <-- SearchResultDone tag';
        else if (i === doneIndex + 1) marker = ' <-- BER length start';
        else if (i === resultCodePos) marker = ' <-- Result code position';
        console.log(`    [${i}] = 0x${toHexSearch(byte)} (${byte}) '${ascii}'${marker}`);
      }
      
      // Validate if this looks like a real LDAP result code
      const isValidLdapResultCode = searchResultCode >= 0 && searchResultCode <= 0x50;
      console.log(`  Is valid LDAP result code (0-80): ${isValidLdapResultCode}`);
      if (!isValidLdapResultCode) {
        console.log(`  WARNING: 0x${toHexSearch(searchResultCode)} (${searchResultCode}) is not a standard LDAP result code!`);
        console.log(`  This suggests we may be reading ASCII text instead of LDAP protocol data.`);
      }
      if (searchResultCode !== 0x00) {
        // Compact hex dump for GUI visibility (permissions-friendly)
        const hexDumpLines = [];
        hexDumpLines.push(`\nDEBUG: doneIndex=${doneIndex}, BER len=${resultLengthInfo.length}(${resultLengthInfo.bytesUsed}b), resultPos=${resultCodePos}, respLen=${searchRspLength}`);
        
        // Show only critical bytes around the issue
        const compactStart = Math.max(0, doneIndex - 2);
        const compactEnd = Math.min(searchRspLength, resultCodePos + 3);
        const compactBytes = [];
        for (let i = compactStart; i < compactEnd; i++) {
          const byte = searchRsp[i];
          const ascii = (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
          let marker = '';
          if (i === doneIndex) marker = '(SRD)';
          else if (i === doneIndex + 1) marker = '(LEN)';
          else if (i === resultCodePos) marker = '(RC!)';
          compactBytes.push(`[${i}]=0x${toHexSearch(byte)}/${ascii}${marker}`);
        }
        hexDumpLines.push(`Key bytes: ${compactBytes.join(' ')}`);
        
        // Check if we're reading "People" text
        const surroundingText = [];
        for (let i = Math.max(0, resultCodePos - 3); i < Math.min(searchRspLength, resultCodePos + 4); i++) {
          const byte = searchRsp[i];
          if (byte >= 32 && byte <= 126) {
            surroundingText.push(String.fromCharCode(byte));
          }
        }
        if (surroundingText.length > 0) {
          hexDumpLines.push(`ASCII context: "${surroundingText.join('')}"`);
        }
        
        const errorMsg = getLdapErrorMessage(searchResultCode);
        throw new Error(`Search failed: ${errorMsg}${hexDumpLines.join('\n')}`);
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
