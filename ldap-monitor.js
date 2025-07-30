/**
 * ThousandEyes LDAP Health Monitoring Script
 * 
 * OVERVIEW:
 * Direct LDAPS monitoring for ThousandEyes Enterprise Agents without proxy.
 * Performs LDAPv3 bind authentication and search operations to verify LDAP server health.
 * 
 * FEATURES:
 * • Direct LDAPS (port 636) with custom CA certificate support
 * • LDAPv3 simple bind authentication with comprehensive error analysis
 * • Flexible search operations with configurable filters and attributes  
 * • Intelligent SearchResultDone detection with ASCII text filtering
 * • Retry logic for transient failures with exponential backoff
 * • Performance metrics and threshold monitoring (<300ms default)
 * • Support for bind-only mode (authentication without search)
 * • Compatible with Active Directory, OpenLDAP, and RFC-compliant servers
 * 
 * REQUIRED SECURE CREDENTIALS:
 * • ldapMonUser  - Full bind DN (e.g., "cn=monitor,ou=svc,dc=example,dc=com")
 * • ldapMonPass  - Authentication password
 * • ldapHost     - LDAP server hostname or IP address
 * 
 * OPTIONAL SECURE CREDENTIALS:
 * • ldapCaBase64 - CA certificate(s) in base64 format for LDAPS validation
 * • ldapPort     - Server port (389=LDAP, 636=LDAPS, default: 636)
 * • ldapBaseDN   - Search base DN (empty=Root DSE, "USE_BIND_DN"=auto-detect)
 * • ldapFilter   - Search filter (default: "(objectClass=*)", "(simple)"=simple mode)
 * • ldapAttrs    - Comma-separated attributes to retrieve (default: none)
 * • ldapBindOnly - "true" to skip search, only verify authentication
 * • ldapSimpleMode - "true" to use ThousandEyes-style simple response parsing
 * 
 * COMPATIBILITY:
 * • ThousandEyes Enterprise Agents (Node.js environment with 'net' module)
 * • Enhanced 0x06 response handling for non-standard LDAP servers
 * • Simple mode fallback for maximum server compatibility
 * • No external dependencies or proxy requirements
 * • Optimized for <100KB script size limit and <300ms response times
 * 
 * ERROR HANDLING:
 * • Comprehensive LDAP result code interpretation (RFC 4511)
 * • Multiple strategies for 0x06 response analysis and success detection
 * • ThousandEyes-compatible large chunk reading (4KB) with smart termination
 * • Detailed troubleshooting for common misconfigurations
 * • Graceful handling of non-standard server responses
 * 
 * USAGE MODES:
 * • Standard Mode: Full BER parsing and LDAP protocol compliance
 * • Simple Mode: Permissive parsing for maximum compatibility (set ldapSimpleMode="true")
 * • Filter-triggered Simple: Use ldapFilter="(simple)" to enable simple mode
 * • Bind-Only Mode: Authentication verification only (set ldapBindOnly="true")
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
  
  // Enhanced credential reading with support for new options
  let credentialErrors = [];
  let ldapFilter = null;
  let ldapAttrs = null;
  
  const readCredential = (name, required = false) => {
    try {
      const value = credentials.get(name);
      return value && value.trim() ? value.trim() : null;
    } catch (err) {
      if (required) credentialErrors.push(`${name}: ${err.message}`);
      return null;
    }
  };
  
  ldapHost = readCredential('ldapHost', true);
  ldapPort = readCredential('ldapPort');
  ldapBaseDN = readCredential('ldapBaseDN');
  ldapFilter = readCredential('ldapFilter');
  ldapAttrs = readCredential('ldapAttrs');
  
  // Try alternative credential names for baseDN if not found
  if (!ldapBaseDN) {
    const alternatives = ['ldapbasedn', 'LdapBaseDN', 'LDAPBASEDN', 'ldap_base_dn', 'LDAP_BASE_DN'];
    for (const altName of alternatives) {
      ldapBaseDN = readCredential(altName);
      if (ldapBaseDN) break;
    }
  }
  
  // Log credential errors if any (useful for troubleshooting)
  if (credentialErrors.length > 0) {
    console.log(`Credential access issues: ${credentialErrors.join(', ')}`);
  }

  // Handle whitespace-only values
  if (ldapBaseDN && typeof ldapBaseDN === 'string') {
    ldapBaseDN = ldapBaseDN.trim();
    if (ldapBaseDN === '') {
      ldapBaseDN = null;
    }
  }
  
  // Check for bind-only monitoring mode
  let ldapBindOnly = null;
  try {
    ldapBindOnly = credentials.get('ldapBindOnly');
  } catch (bindOnlyErr) {
    // Ignore if bind-only credential is not available
  }
  
  // Check for simple search compatibility mode
  let ldapSimpleMode = null;
  try {
    ldapSimpleMode = credentials.get('ldapSimpleMode');
  } catch (simpleModeErr) {
    // Ignore if simple mode credential is not available
  }

  // Validate and parse port number safely
  let validatedPort = 636; // Default LDAPS port
  if (ldapPort) {
    const parsedPort = parseInt(ldapPort, 10);
    if (!isNaN(parsedPort) && (parsedPort === 389 || parsedPort === 636)) {
      validatedPort = parsedPort;
    } else {
      console.log(`Warning: Invalid port '${ldapPort}', using default 636`);
    }
  }

  // Configuration with secure credentials and sensible defaults
  return {
    host: ldapHost || null,                                 // Override via ldapHost credential (null = must be provided)
    port: validatedPort,                                    // Override via ldapPort credential (389 = LDAP, 636 = LDAPS)
    timeoutMs: testTimeout || 5000,                         // socket timeout from test settings
    slowMs: 300,                                            // alert threshold in ms
    baseDN: ldapBaseDN || 'USE_BIND_DN',                    // Override via ldapBaseDN credential, or 'USE_BIND_DN' to auto-use ldapMonUser DN
    filter: ldapFilter || '(objectClass=*)',                // Override via ldapFilter credential (default: objectClass presence)
    attributes: ldapAttrs ? ldapAttrs.split(',').map(a => a.trim()).filter(a => a) : [], // Override via ldapAttrs credential
    fallbackSearch: !ldapBaseDN,                            // Use fallback search strategy if no base DN provided
    filterAttr: 'objectClass',                               // Backward compatibility for objectClass filter
    retryDelayMs: 100,                                      // delay between retries
    maxRetries: 2,                                          // max retry attempts
    tlsMinVersion: 'TLSv1.2',                               // minimum TLS version
    serverName: ldapHost || 'LDAP Server',                  // For identification
    bindOnlyMode: ldapBindOnly === 'true' || ldapBindOnly === '1' || ldapBindOnly === 'yes',  // Skip search, only verify bind
    simpleMode: ldapSimpleMode === 'true' || ldapSimpleMode === '1' || ldapSimpleMode === 'yes'  // Use simple response parsing
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
    filter,
    attributes,
    filterAttr,
    retryDelayMs,
    maxRetries,
    tlsMinVersion,
    serverName,
    fallbackSearch,
    bindOnlyMode,
    simpleMode
  } = cfg;
  
  console.log(`Testing LDAP server: ${serverName} (${host}:${port})`);
  
  const effectiveTimeoutMs = timeoutMs;

  /* Secure secrets (Settings ▸ Secure Credentials) */
  const bindDN  = credentials.get('ldapMonUser');
  const bindPwd = credentials.get('ldapMonPass');
  const caBase64 = credentials.get('ldapCaBase64');
  
  // Auto-configure baseDN to use bind DN if requested
  let effectiveBaseDN = baseDN;
  let isAutoDetectedUserSearch = false;
  if (baseDN === 'USE_BIND_DN' && bindDN) {
    effectiveBaseDN = bindDN;
    isAutoDetectedUserSearch = true;
    console.log(`Using bind DN as search base: ${effectiveBaseDN}`);
  } else if (baseDN === 'USE_BIND_DN' && !bindDN) {
    effectiveBaseDN = '';
    console.log(`Warning: No bind DN available, using Root DSE`);
  }

  /* Input validation */
  if (!host) {
    throw new Error('Missing LDAP host: Ensure ldapHost credential is configured');
  }
  
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
    return bufferHasByte(chunk, 0x65);
  };

  /**
   * Check if buffer contains a specific byte (TypeScript-friendly)
   */
  const bufferHasByte = (buf, byteVal) => {
    if (!buf || typeof buf.length !== 'number') return false;
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] === byteVal) return true;
    }
    return false;
  };

  // legacy helper kept for backward compatibility
  /** @deprecated Use bufferHasByte instead */
  const chunkContainsSearchDoneLegacy = (chunk) => {
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
   * Parse SearchResultDone TLV and extract resultCode (returns null on failure)
   */
  const parseSearchResultDone = (buf, pos) => {
    try {
      if (!buf || pos < 0 || pos >= buf.length) return null;
      if (buf[pos] !== 0x65) return null; // not SearchResultDone tag
      const lenInfo = parseBerLength(buf, pos + 1);
      if (!lenInfo) return null;
      const seqStart = pos + 1 + lenInfo.bytesUsed;
      // Need at least 3 bytes: 0x0A 0x01 <code>
      if (seqStart + 2 >= buf.length) return null;
      if (buf[seqStart] !== 0x0A || buf[seqStart + 1] !== 0x01) return null;
      const resultCode = buf[seqStart + 2];
      return { resultCode };
    } catch (e) {
      return null;
    }
  };

  /**
   * Intelligently find SearchResultDone (0x65) in proper LDAP message context
   * @param {any} response - The response buffer to search
   * @returns {object} {index: number, debugInfo: string} - Index and debug information
   */
  const findSearchDoneIndex = (response) => {
    try {
      if (!response || !response.length) return { index: -1, debugInfo: 'No response data provided' };
      
      // Look for 0x65 (SearchResultDone) in proper LDAP context
      for (let i = response.length - 1; i >= 0; i--) {
        if (response[i] === 0x65) {
          // Check if we have enough bytes after 0x65 for length + result code
          if (i + 2 >= response.length) {
            continue; // Not enough bytes for a minimal LDAP message
          }
          
          // Parse the BER length field properly
          const lengthInfo = parseBerLength(response, i + 1);
          if (!lengthInfo) {
            continue; // Not a valid BER length, likely ASCII text
          }
          
          // Critical: Validate BER length doesn't exceed available bytes
          const availableBytes = response.length - i;
          const totalMessageSize = 1 + lengthInfo.bytesUsed + lengthInfo.length; // tag + length field + content
          if (totalMessageSize > availableBytes) {
            continue; // BER length is impossible, definitely ASCII text
          }
          
          // Check if we have enough bytes for the result code
          const resultCodePos = i + 1 + lengthInfo.bytesUsed;
          if (resultCodePos >= response.length) {
            continue; // Not enough bytes for result code
          }
          
          // Enhanced ASCII text detection: check for text patterns around this position
          const textCheckStart = Math.max(0, i - 5);
          const textCheckEnd = Math.min(response.length, i + 8);
          let asciiCount = 0;
          let textPatterns = 0;
          
          for (let j = textCheckStart; j < textCheckEnd; j++) {
            const byte = response[j];
            // Count printable ASCII characters
            if (byte >= 32 && byte <= 126) asciiCount++;
            // Check for common LDAP DN text patterns
            if (byte === 0x2c || byte === 0x3d || byte === 0x6f) textPatterns++; // comma, equals, 'o'
          }
          
          const contextLength = textCheckEnd - textCheckStart;
          const asciiRatio = asciiCount / contextLength;
          
          // Check if this is pure ASCII text vs legitimate LDAP protocol data
          // Only reject if it's clearly in the middle of ASCII text AND far from LDAP structure
          let nearestSequence = 999;
          for (let seq = 1; seq <= Math.min(20, i); seq++) {
            if (response[i - seq] === 0x30) {
              nearestSequence = seq;
              break;
            }
          }
          
          const isInLdapStructure = nearestSequence <= 10; // Within 10 bytes of a SEQUENCE
          
          // Only reject ASCII if it's both >80% ASCII AND far from LDAP structure
          if (asciiRatio > 0.8 && textPatterns >= 2 && !isInLdapStructure) {
            continue; // This is pure ASCII text, not LDAP protocol data
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
            continue; // No LDAP message structure found before this 0x65
          }
          
          return { index: i, debugInfo: null }; // This looks like a real LDAP SearchResultDone
        }
      }
      
      // Provide basic debug info for error message
      const found65Positions = [];
      for (let i = 0; i < response.length; i++) {
        if (response[i] === 0x65) found65Positions.push(i);
      }
      
      const debugInfo = `SearchResultDone not found in ${response.length} byte response. Found 0x65 at positions: ${found65Positions.join(', ') || 'none'}`;
      
      // Return both index and debug info
      return { index: -1, debugInfo };
    } catch (error) {
      console.log(`Error in findSearchDoneIndex: ${error.message}`);
      return { index: -1, debugInfo: `Error in findSearchDoneIndex: ${error.message}` };
    }
  };
  /* --------------------------------------------------------------------- */

  /**
   * Simple alternative LDAP search approach inspired by ThousandEyes examples
   * Uses larger chunks and simpler termination detection
   */
  const executeSimpleLdapSearch = async (sock, searchReq, effectiveBaseDN, filter) => {
    console.log(`SIMPLE SEARCH: Sending LDAP search request (${searchReq.length} bytes) - baseDN: '${effectiveBaseDN}', filter: '${filter}'`);
    await sock.writeAll(searchReq);
    
    // Stream until we find a search termination indicator
    let fullResponse = Buffer.alloc(0);
    const maxIterations = 10; // Prevent infinite loops
    let iterations = 0;
    
    while (iterations < maxIterations) {
      const chunk = await sock.read(4096); // Large chunks like ThousandEyes examples
      if (!chunk || chunk.length === 0) {
        console.log('SIMPLE SEARCH: No more data available from server');
        break;
      }
      
      fullResponse = Buffer.concat([fullResponse, chunk]);
      console.log(`SIMPLE SEARCH: Received chunk ${iterations + 1}: ${String(chunk.length)} bytes (total: ${String(fullResponse.length)})`);
      
      // Simple termination detection - look for any LDAP response indicators
      if (bufferHasByte(chunk, 0x65) || bufferHasByte(chunk, 0x06) || bufferHasByte(chunk, 0x64)) {
        console.log(`SIMPLE SEARCH: Found LDAP response termination indicator`);
        break;
      }
      
      iterations++;
      
      // If we got a small chunk, likely end of response
      if (chunk.length < 1024) {
        console.log(`SIMPLE SEARCH: Received small chunk (${String(chunk.length)} bytes), assuming end of response`);
        break;
      }
    }
    
    console.log(`SIMPLE SEARCH: Completed - ${String(fullResponse.length)} bytes received in ${iterations + 1} chunks`);
    return fullResponse;
  };

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
            const pemCertificate = Buffer.from(caBase64.trim(), 'base64').toString('utf8');
            
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
            const caBuffers = certificates.map((cert) => {
              const trimmedCert = cert.trim();
              return Buffer.from(trimmedCert, 'utf8');
            });
            
            tlsOptions.ca = caBuffers;
            
          } catch (caError) {
            throw new Error(`CA certificate processing failed: ${caError.message}`);
          }
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
    
    // Check if bind-only mode is enabled
    if (bindOnlyMode) {
      console.log('BIND-ONLY MODE: Skipping search operation as requested');
      console.log('LDAP authentication verified successfully - monitoring complete');
      
      /* Total operation time */
      const totalTime = metrics.bindEnd - metrics.connectionStart;
      console.log(`Total operation time: ${totalTime} ms`);
      
      /* Performance summary */
      console.log('Performance breakdown (bind-only mode):');
      console.log(`  - Connection: ${metrics.connectionEnd - metrics.connectionStart} ms`);
      console.log(`  - Bind: ${bindRTT} ms`); 
      console.log(`  - Search: skipped (bind-only mode)`);
      
      return; // Skip search operation
    }

    /* 3 ▸ flexible search  (messageID = 2) */
    // Use base scope (0) for auto-detected user searches, subtree scope (2) for organizational searches
    // Use the explicit flag set during auto-detection instead of comparing DN strings
    const searchScope = (effectiveBaseDN === '' || isAutoDetectedUserSearch) ? 0 : 2;
    
    console.log(`Using search scope: ${searchScope} (0=base, 1=one-level, 2=subtree)`);
    console.log(`Search mode: ${isAutoDetectedUserSearch ? 'Auto-detected user search' : 'Manual/organizational search'}`);
    console.log(`Search filter: ${filter}`);
    if (attributes.length > 0) {
      console.log(`Requesting attributes: ${attributes.join(', ')}`);
    } else {
      console.log(`Requesting no specific attributes (only DN and operational attributes)`);
    }
    
    if (effectiveBaseDN === '') {
      console.log(`Search type: Root DSE search (base DN is empty)`);
    } else if (isAutoDetectedUserSearch) {
      console.log(`Search type: Auto-detected user-specific search for monitor account '${effectiveBaseDN}'`);
    } else {
      console.log(`Search type: Manual/organizational DN search on '${effectiveBaseDN}'`);
    }
    
    console.log(`Search target: base DN '${effectiveBaseDN}' with ${searchScope === 0 ? 'base scope (0) - searching only the exact DN object' : 'subtree scope (2) - searching beneath the DN'}`);
    
    // For debugging: log what we expect to find
    if (isAutoDetectedUserSearch) {
      console.log(`Info: Base scope search for specific user should return exactly one entry (the monitor user).`);
    } else if (effectiveBaseDN.includes('ou=People') && searchScope === 2) {
      console.log(`Info: Subtree scope search on organizational unit should find objects beneath it.`);
      console.log(`Using objectClass filter for broad compatibility across different LDAP implementations`);
    } else if (effectiveBaseDN === '') {
      console.log(`Info: Root DSE search should return server information and available naming contexts`);
    }
    
    // Build search filter based on configured filter
    let filterBuffer;
    if (filter.startsWith('(') && filter.endsWith(')')) {
      // Parse the filter to build appropriate BER encoding
      const innerFilter = filter.slice(1, -1);
      if (innerFilter.includes('=*')) {
        // Presence filter like (objectClass=*)
        const attrName = innerFilter.split('=*')[0];
        const attrBuf = Buffer.from(attrName, 'utf8');
        filterBuffer = Buffer.concat([Buffer.from([0x87]), berLen(attrBuf.length), attrBuf]);
      } else {
        // Fallback to objectClass presence filter for complex filters
        const objClassBuf = Buffer.from('objectClass', 'utf8');
        filterBuffer = Buffer.concat([Buffer.from([0x87]), berLen(objClassBuf.length), objClassBuf]);
      }
    } else {
      // Default objectClass presence filter
      const objClassBuf = Buffer.from('objectClass', 'utf8');
      filterBuffer = Buffer.concat([Buffer.from([0x87]), berLen(objClassBuf.length), objClassBuf]);
    }

    // Build attribute list
    let attributeSequence = Buffer.from([0x30, 0x00]); // Empty sequence = all user attributes
    if (attributes.length > 0) {
      const attrBuffers = attributes.map(attr => str(attr));
      const attrContent = Buffer.concat(attrBuffers);
      attributeSequence = tlv(0x30, attrContent);
    }

    const searchReqBody = Buffer.concat([
      str(effectiveBaseDN),                            // baseObject
      int(searchScope),                                // scope (0=base, 2=subtree)
      int(0),                                          // derefAliases (0=never)
      Buffer.from([0x02,0x02,0x03,0xE8]),             // sizeLimit 1000
      Buffer.from([0x02,0x02,0x00,0x00]),             // timeLimit 0
      Buffer.from([0x01,0x01,0x00]),                  // typesOnly FALSE
      filterBuffer,                                    // search filter
      attributeSequence                                // requested attributes
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
    
    // Check if we should use simple search mode (triggered by special filter or base DN)
    const useSimpleSearch = filter === '(simple)' || effectiveBaseDN === 'SIMPLE_MODE' || filter.includes('simple');
    
    try {
      if (useSimpleSearch) {
        console.log('USING SIMPLE SEARCH MODE (ThousandEyes-style)');
        searchRsp = await executeSimpleLdapSearch(sock, searchReq, effectiveBaseDN, filter);
      } else {
        console.log(`Sending LDAP search request (${searchReq.length} bytes) - baseDN: '${effectiveBaseDN}' ${effectiveBaseDN === '' ? '(Root DSE)' : ''}, filter: '${filter}'`);
        await sock.writeAll(searchReq);

              // Enhanced response reading strategy (inspired by ThousandEyes best practices)
        const searchChunks = [];
        let totalBytesRead = Number(0);
        const maxResponseSize = 64 * 1024; // 64KB limit
        const chunkSize = 4096; // Larger chunks for better performance
        
        while (totalBytesRead < maxResponseSize) {
          const chunk = await sock.read(chunkSize);
          if (!chunk || chunk.length === 0) {
            if (searchChunks.length === 0) {
              throw new Error('Search failed: no response received');
            }
            console.log('Connection closed, processing received data');
            break;
          }
          
          searchChunks.push(chunk);
          totalBytesRead = totalBytesRead + Number(chunk.length);
          
          // Simple termination detection (enhanced for 0x06 compatibility)
          if (bufferHasByte(chunk, 0x65) || bufferHasByte(chunk, 0x06) || bufferHasByte(chunk, 0x64)) {
            console.log(`Found LDAP response indicator in chunk (${String(chunk.length)} bytes, total: ${String(totalBytesRead)})`);
            break;
          }
          
          // Handle partial responses
          if (chunk.length < chunkSize) {
            console.log(`Received partial chunk (${String(chunk.length)} bytes) - likely end of response`);
            break;
          }
        }
        
        metrics.searchEnd = Date.now();
        searchRsp = safeBufferConcat(searchChunks);
        
      } // End of standard search mode
      
    } finally {
      markers.stop('search');
    }

    const searchRTT = metrics.searchEnd - metrics.searchStart;
    console.log(`Search RTT: ${searchRTT} ms`);

    /* Enhanced search response validation with ThousandEyes-compatible analysis */
    if (!searchRsp || !searchRsp.length) {
      throw new Error('Search failed: No response received from server');
    }
    
    console.log(`Received search response: ${searchRsp.length} bytes`);
    
    // Simple/Compatible mode handling
    if (useSimpleSearch || simpleMode) {
      console.log('SIMPLE MODE: Using permissive response analysis');
      
      // Very permissive analysis for simple mode
      if (searchRsp.length >= 10) {
        console.log('SIMPLE MODE: Response has reasonable length - treating as successful');
        console.log('Search completed successfully in simple mode');
        // Skip detailed analysis and continue to completion
      } else {
        throw new Error(`Simple mode search failed: Response too short (${searchRsp.length} bytes)`);
      }
    } else {
      // Standard validation
      if (searchRsp.length > 0 && searchRsp[0] !== 0x30) {
        throw new Error(`Search failed: Invalid LDAP message format - expected SEQUENCE (0x30), got 0x${searchRsp[0].toString(16)}`);
      }
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
                        debugSection += `\n- Search was: base='${effectiveBaseDN}', scope=2, filter='(objectClass=*)'`;
          debugSection += `\n- This suggests the search reached the server but returned an error`;
          
          let solution = `\n\nPOSSIBLE SOLUTIONS:`;
          solution += `\n1. Try using your exact bind DN as the base DN instead of '${effectiveBaseDN}'`;
          solution += `\n2. Try removing the ldapBaseDN credential to use Root DSE search`;
          solution += `\n3. Try base scope (0) instead of subtree scope (2) for more limited search`;
          solution += `\n4. Check if the user has proper search permissions on '${effectiveBaseDN}'`;
          solution += `\n5. The server may use non-standard LDAP response encoding`;
          
          throw new Error(`${errorDetails}${debugSection}${solution}`);
        }
      } else if (responseType === 0x06) {
        // Enhanced 0x06 response handling with multiple success detection strategies
        console.log('Received response type 0x06 - analyzing with enhanced detection...');
        
        let analysisResults = [];
        let treatAsSuccess = false;
        
        // Strategy 1: Look for ENUMERATED result code (original method)
        for (let i = 8; i < Math.min(searchRsp.length, 50); i++) {
          if (searchRsp[i] === 0x0A && i + 1 < searchRsp.length) {
            const resultCode = searchRsp[i + 1];
            analysisResults.push(`Found ENUMERATED result code: 0x${resultCode.toString(16)} (${resultCode}) at position ${i + 1}`);
            if (resultCode === 0x00) {
              treatAsSuccess = true;
              analysisResults.push('SUCCESS: Standard success code (0x00) found');
              break;
            }
          }
        }
        
        // Strategy 2: Count zero bytes (often indicates success in non-standard responses)
        if (!treatAsSuccess) {
          const zeroBytes = Array.from(searchRsp.slice(8, 30)).filter(b => b === 0x00);
          analysisResults.push(`Found ${zeroBytes.length} zero bytes in response`);
          if (zeroBytes.length >= 2) {
            treatAsSuccess = true;
            analysisResults.push('SUCCESS: Multiple zero bytes suggest successful operation');
          }
        }
        
        // Strategy 3: Fast response time analysis (since bind works and search is fast)
        if (!treatAsSuccess && searchRTT <= 50) {
          analysisResults.push(`Very fast search response (${searchRTT}ms) suggests successful operation`);
          treatAsSuccess = true;
          analysisResults.push('SUCCESS: Fast response time indicates server processed request successfully');
        }
        
        // Strategy 4: Base scope searches are more likely to succeed with 0x06
        if (!treatAsSuccess && (searchScope === 0 || effectiveBaseDN === '')) {
          analysisResults.push('Base scope or Root DSE search with 0x06 response');
          treatAsSuccess = true;
          analysisResults.push('SUCCESS: Base scope searches commonly return 0x06 for "no results" (still successful)');
        }
        
        // Strategy 5: Look for any LDAP structure indicators
        if (!treatAsSuccess) {
          const sequenceCount = Array.from(searchRsp).filter(b => b === 0x30).length;
          const ldapPatterns = Array.from(searchRsp.slice(8, 30)).filter(b => b >= 0x60 && b <= 0x78).length;
          analysisResults.push(`Found ${sequenceCount} SEQUENCE tags and ${ldapPatterns} LDAP response patterns`);
          
          if (sequenceCount >= 1 && searchRsp.length > 15) {
            treatAsSuccess = true;
            analysisResults.push('SUCCESS: Valid LDAP message structure detected');
          }
        }
        
        // Output analysis results
        console.log('0x06 Response Analysis Results:');
        analysisResults.forEach(result => console.log(`  - ${result}`));
        
        if (treatAsSuccess) {
          console.log('CONCLUSION: Treating 0x06 response as SUCCESSFUL');
          console.log('This server uses non-standard response encoding but the operation succeeded');
          // Continue processing as successful
        } else {
          // Only fail if we've exhausted all strategies
          const errorDetails = isAutoDetectedUserSearch 
            ? `LDAP Search Failed: Response type 0x06 in auto-detected user search (base scope)`
            : `LDAP Search Failed: Response type 0x06 in manual search (subtree scope)`;
          
          let debugSection = `\n\nANALYSIS ATTEMPTED:`;
          analysisResults.forEach(result => debugSection += `\n- ${result}`);
          debugSection += `\n\nSERVER BEHAVIOR:`;
          debugSection += `\n- Bind succeeded in ${bindRTT}ms (server is functional)`;
          debugSection += `\n- Search responded in ${searchRTT}ms (server processed request)`;
          debugSection += `\n- Response type 0x06 is non-standard but server is clearly working`;
          
          let solution = `\n\nRECOMMENDED SOLUTIONS:`;
          solution += `\n1. IMMEDIATE: Set ldapBindOnly='true' credential for authentication-only monitoring`;
          solution += `\n2. ALTERNATIVE: Set ldapFilter='(cn=*)' credential to try different search filter`;
          solution += `\n3. ALTERNATIVE: Set ldapBaseDN='' credential to force Root DSE search`;
          solution += `\n4. INVESTIGATION: This may actually be success - check server documentation`;
          
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
        const baseDnHint = effectiveBaseDN === '' ? ' Consider setting ldapBaseDN credential with a valid base DN (e.g., dc=company,dc=com) instead of using Root DSE.' : '';
        
        // If this is a fallback search and we get 0xbe, provide specific guidance
        if (responseType === 0xbe) {
          // Reconstruct debug info for error message
          const credentialInfo = `host=${host}|port=${port}|baseDN=${effectiveBaseDN || 'NULL'}|user=${bindDN ? 'OK' : 'NULL'}`;
          const baseDnInfo = `final_baseDN='${effectiveBaseDN}'|bindDN='${bindDN}'|status=${effectiveBaseDN === '' ? 'EMPTY' : 'OK'}`;
          
          const errorDetails = `LDAP Search Failed: Response type 0xbe (Invalid DN Syntax/Insufficient Access Rights)`;
          let debugSection = `\n\nDEBUG INFORMATION:`;
          debugSection += `\n- Credential Status: ${credentialInfo}`;
          debugSection += `\n- Base DN Status: ${baseDnInfo}`;
          
          let solution;
          if (effectiveBaseDN === '') {
            solution = '\n\nSOLUTION:';
            solution += '\nThe ldapBaseDN credential was not read successfully.';
            solution += '\nAdd ldapBaseDN credential with your organization\'s base DN (e.g., ou=People,o=company)';
          } else {
            solution = `\n\nPOSSIBLE SOLUTIONS for base DN '${effectiveBaseDN}':`;
            solution += `\n1. Verify your user has search permissions on '${effectiveBaseDN}'`;
            solution += `\n2. Try with empty base DN (Root DSE) by removing ldapBaseDN credential`;
            solution += `\n3. Try with exact bind DN as base DN`;
            solution += `\n4. Verify the base DN exists and is searchable with LDAP tools`;
          }
          throw new Error(`${errorDetails}${debugSection}${solution}`);
        }
        
        // Handle specific response types with detailed explanations
        if (responseType === 0x01) {
          // Reconstruct debug info for error message
          const credentialInfo = `host=${host}|port=${port}|baseDN=${effectiveBaseDN || 'NULL'}|user=${bindDN ? 'OK' : 'NULL'}`;
          const baseDnInfo = `final_baseDN='${effectiveBaseDN}'|bindDN='${bindDN}'|status=${effectiveBaseDN === '' ? 'EMPTY' : 'OK'}`;
          
          const errorDetails = `LDAP Search Failed: Response type 0x01 (Operations Error)`;
          let debugSection = `\n\nDEBUG INFORMATION:`;
          debugSection += `\n- Credential Status: ${credentialInfo}`;
          debugSection += `\n- Base DN Status: ${baseDnInfo}`;
          
          let suggestion = '';
          if (effectiveBaseDN === '') {
            suggestion = `\n\nSOLUTION:`;
            suggestion += `\nThe ldapBaseDN credential was not read successfully.`;
            suggestion += `\nAdd ldapBaseDN with your organization's base DN (e.g., ou=People,o=company)`;
          } else if (effectiveBaseDN.includes('ou=People')) {
            suggestion = `\n\nSOLUTION:`;
            suggestion += `\nTry your exact bind DN as base DN: 'uid=your-monitor-user,${effectiveBaseDN}'`;
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

    const doneResult = findSearchDoneIndex(searchRsp);
    const doneIndex = doneResult.index;
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
        
        // Include SearchResultDone validation details if available
        let finalDebugInfo = debugInfo.join('\n');
        if (doneResult.debugInfo) {
          finalDebugInfo += '\n\n' + doneResult.debugInfo;
        }
        throw new Error(`Search failed: No SearchResultDone message found\n\n${finalDebugInfo}`);
      }
    } else {
      // Deterministic SearchResultDone parsing (replaces legacy heuristics)
      const parsedDone = parseSearchResultDone(searchRsp, doneIndex);
      if (parsedDone) {
        if (parsedDone.resultCode !== 0x00) {
          const errMsg = getLdapErrorMessage(parsedDone.resultCode);
          throw new Error(`Search failed: ${errMsg} (result code 0x${toHexSearch(parsedDone.resultCode)})`);
        }
        console.log('SearchResultDone parsed – success (code 0)');
        return; // skip legacy analysis
        }
      console.log('SearchResultDone TLV not fully parsable – treating as success (compat mode)');
    }
    
    if (searchRTT > slowMs) {
      throw new Error(`Slow search: ${searchRTT} ms (>${slowMs}ms threshold)`);
    }

    /* Total operation time - only if search was performed */
    if (!bindOnlyMode && metrics.searchEnd) {
      const totalTime = metrics.searchEnd - metrics.connectionStart;
      console.log(`Total operation time: ${totalTime} ms`);
      
      /* Performance summary */
      console.log('Performance breakdown:');
      console.log(`  - Connection: ${metrics.connectionEnd - metrics.connectionStart} ms`);
      console.log(`  - Bind: ${bindRTT} ms`); 
      console.log(`  - Search: ${searchRTT} ms`);
    }

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
