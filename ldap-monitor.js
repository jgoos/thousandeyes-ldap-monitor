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
 *   ldapDebugMode →  'true' for verbose debugging (default: false)
 */

import { net, credentials, test, markers } from 'thousandeyes';

// Constants
const MAX_RESPONSE_SIZE = 1000000; // 1MB safety limit for everything the server sends on one connection
const TLS_ERROR_KEYWORDS = ['certificate', 'CERT_', 'SSL', 'TLS'];
const CREDENTIAL_ALTERNATIVES = ['ldapbasedn', 'LdapBaseDN', 'LDAPBASEDN', 'ldap_base_dn', 'LDAP_BASE_DN'];
const MAX_EMPTY_READS = 3; // consecutive empty reads treated as end of stream
const MAX_DIAGNOSTIC_LENGTH = 200; // characters of server diagnosticMessage kept in errors

/* ───────────── LDAP protocol codec (RFC 4511; BER per section 5.1) ───────────── */

const LDAP_TAG = {
  boolean: 0x01,
  integer: 0x02,
  octetString: 0x04,
  enumerated: 0x0a,
  sequence: 0x30,
  bindRequest: 0x60,          // [APPLICATION 0]
  bindResponse: 0x61,         // [APPLICATION 1]
  unbindRequest: 0x42,        // [APPLICATION 2], primitive NULL
  searchRequest: 0x63,        // [APPLICATION 3]
  searchResultEntry: 0x64,    // [APPLICATION 4]
  searchResultDone: 0x65,     // [APPLICATION 5]
  searchResultReference: 0x73, // [APPLICATION 19]
  extendedResponse: 0x78,     // [APPLICATION 24]
  intermediateResponse: 0x79, // [APPLICATION 25]
  simpleAuth: 0x80,           // BindRequest authentication [0] simple
  presentFilter: 0x87,        // Filter [7] present
  responseName: 0x8a,         // ExtendedResponse [10] responseName
};

const MESSAGE_ID = { bind: 1, search: 2, unbind: 3 };
const SEARCH_SCOPE_BASE = 0;
const NEVER_DEREF_ALIASES = 0;
const NO_ATTRIBUTES = '1.1'; // RFC 4511 4.5.1.8: return no attributes
const NOTICE_OF_DISCONNECTION_OID = '1.3.6.1.4.1.1466.20036';

/** RFC 4511 4.1.9 result codes. */
const LDAP_RESULT_CODES = {
  0x00: { name: 'success', description: 'The operation completed successfully' },
  0x01: { name: 'operationsError', description: 'The operation is not properly sequenced with respect to other operations' },
  0x02: { name: 'protocolError', description: 'The server received data that is not well-formed or the LDAP version is not supported' },
  0x03: { name: 'timeLimitExceeded', description: 'The time limit specified by the client was exceeded before the operation could complete' },
  0x04: { name: 'sizeLimitExceeded', description: 'The size limit specified by the client was exceeded before the operation could complete' },
  0x05: { name: 'compareFalse', description: 'The Compare operation completed and the assertion evaluated to FALSE' },
  0x06: { name: 'compareTrue', description: 'The Compare operation completed and the assertion evaluated to TRUE' },
  0x07: { name: 'authMethodNotSupported', description: 'The requested authentication method or mechanism is not supported by the server' },
  0x08: { name: 'strongerAuthRequired', description: 'The server requires stronger authentication to complete the operation' },
  0x0A: { name: 'referral', description: 'The server referred the client to another server' },
  0x0B: { name: 'adminLimitExceeded', description: 'An administrative limit (e.g., maximum number of entries, operations, or subordinates) has been exceeded' },
  0x0C: { name: 'unavailableCriticalExtension', description: 'A critical control in the request is unrecognized or unsupported' },
  0x0D: { name: 'confidentialityRequired', description: 'The operation requires confidentiality (e.g., TLS) that is not in place' },
  0x0E: { name: 'saslBindInProgress', description: 'The server requires the client to send a new SASL bind request to continue' },
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
 * Human-readable result code: "name (code/0xNN): description".
 * @param {number} resultCode
 * @returns {string}
 */
const getLdapErrorMessage = (resultCode) => {
  const hex = resultCode.toString(16).padStart(2, '0');
  const info = LDAP_RESULT_CODES[resultCode];
  return info
    ? `${info.name} (${resultCode}/0x${hex}): ${info.description}`
    : `Unknown LDAP result code ${resultCode} (0x${hex})`;
};

/**
 * Whether a character could break or disguise a one-line message: C0 and C1 controls, DEL,
 * Unicode line and paragraph separators, and bidirectional formatting characters.
 */
const isUnsafeChar = (ch) =>
  ch < ' ' ||
  (ch >= '\u007f' && ch <= '\u009f') ||
  ch === '\u2028' || ch === '\u2029' ||
  ch === '\u200e' || ch === '\u200f' ||
  (ch >= '\u202a' && ch <= '\u202e') ||
  (ch >= '\u2066' && ch <= '\u2069');

/** Server-supplied text, made safe for a one-line error: no unsafe characters, bounded length. */
const sanitizeServerText = (text) =>
  Array.from(text, (ch) => (isUnsafeChar(ch) ? ' ' : ch)).join('').trim().slice(0, MAX_DIAGNOSTIC_LENGTH);

/**
 * Describe an LDAPResult, including the server's diagnosticMessage and matchedDN when present.
 * @param {{ resultCode: number, matchedDN: string, diagnosticMessage: string }} result
 * @returns {string}
 */
const formatLdapResult = ({ resultCode, matchedDN, diagnosticMessage }) => {
  let text = getLdapErrorMessage(resultCode);
  const diagnostic = sanitizeServerText(diagnosticMessage);
  const matched = sanitizeServerText(matchedDN);
  if (diagnostic) text += ` - server: "${diagnostic}"`;
  if (matched) text += ` (matchedDN: "${matched}")`;
  return text;
};

/* BER encoding. Lengths use the definite form only (RFC 4511 5.1). */

/** @param {number} length @returns {Buffer} */
const berLength = (length) => {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  for (let v = length; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
};

/** @param {number} tag @param {Buffer} value @returns {Buffer} */
const berTlv = (tag, value) => Buffer.concat([Buffer.from([tag]), berLength(value.length), value]);

/** Non-negative INTEGER or ENUMERATED in minimal two's-complement form. */
const berUnsigned = (tag, n) => {
  const bytes = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return berTlv(tag, Buffer.from(bytes));
};

const berInteger = (n) => berUnsigned(LDAP_TAG.integer, n);
const berEnumerated = (n) => berUnsigned(LDAP_TAG.enumerated, n);
const berBoolean = (value) => berTlv(LDAP_TAG.boolean, Buffer.from([value ? 0xff : 0x00]));
const berOctetString = (text) => berTlv(LDAP_TAG.octetString, Buffer.from(text, 'utf8'));

/** LDAPMessage envelope (RFC 4511 4.1.1). */
const ldapMessage = (messageId, protocolOp) =>
  berTlv(LDAP_TAG.sequence, Buffer.concat([berInteger(messageId), protocolOp]));

/** LDAPv3 simple BindRequest (RFC 4511 4.2). */
const bindRequest = (dn, password) =>
  berTlv(LDAP_TAG.bindRequest, Buffer.concat([
    berInteger(3),
    berOctetString(dn),
    berTlv(LDAP_TAG.simpleAuth, Buffer.from(password, 'utf8'))
  ]));

/** SearchRequest with a present filter (RFC 4511 4.5.1). */
const searchRequest = ({ baseObject, scope, sizeLimit, timeLimit, presentAttribute, attributes }) =>
  berTlv(LDAP_TAG.searchRequest, Buffer.concat([
    berOctetString(baseObject),
    berEnumerated(scope),
    berEnumerated(NEVER_DEREF_ALIASES),
    berInteger(sizeLimit),
    berInteger(timeLimit),
    berBoolean(false), // typesOnly
    berTlv(LDAP_TAG.presentFilter, Buffer.from(presentAttribute, 'utf8')),
    berTlv(LDAP_TAG.sequence, Buffer.concat(attributes.map(berOctetString)))
  ]));

/** UnbindRequest: [APPLICATION 2] NULL (RFC 4511 4.3). */
const unbindRequest = () => Buffer.from([LDAP_TAG.unbindRequest, 0x00]);

/* BER decoding. */

/**
 * Locate one BER element at `pos`.
 * @param {Buffer} buf
 * @param {number} pos
 * @returns {{ tag: number, valueStart: number, end: number } | null}
 *   null while `buf` does not yet hold the whole element
 * @throws {Error} for encodings LDAP does not allow, or lengths above MAX_RESPONSE_SIZE
 */
function readBerElement(buf, pos) {
  if (pos + 2 > buf.length) return null;
  const tag = buf[pos];
  if ((tag & 0x1f) === 0x1f) throw new Error(`unsupported multi-byte BER tag at offset ${pos}`);
  let length = buf[pos + 1];
  let header = 2;
  if (length & 0x80) {
    const octets = length & 0x7f;
    if (octets === 0) throw new Error('indefinite-length BER encoding, which LDAP does not allow');
    if (octets > 4) throw new Error(`BER length uses ${octets} length octets`);
    if (pos + 2 + octets > buf.length) return null;
    length = 0;
    for (let i = 0; i < octets; i++) length = length * 256 + buf[pos + 2 + i];
    header += octets;
  }
  if (length > MAX_RESPONSE_SIZE) throw new Error(`BER length ${length} exceeds the ${MAX_RESPONSE_SIZE}-byte limit`);
  const end = pos + header + length;
  return end > buf.length ? null : { tag, valueStart: pos + header, end };
}

/** Elements inside a constructed element; throws if one runs past its parent. */
function readBerChildren(buf, parent) {
  const children = [];
  for (let pos = parent.valueStart; pos < parent.end;) {
    const child = readBerElement(buf, pos);
    if (!child || child.end > parent.end) {
      throw new Error(`truncated element inside tag 0x${parent.tag.toString(16)}`);
    }
    children.push(child);
    pos = child.end;
  }
  return children;
}

const berValue = (buf, element) => buf.subarray(element.valueStart, element.end);

/** Non-negative INTEGER or ENUMERATED that fits in 31 bits (message IDs, result codes). */
function readBerUnsigned(buf, element, expectedTag) {
  if (!element || element.tag !== expectedTag) {
    throw new Error(`expected tag 0x${expectedTag.toString(16)}, got ${element ? `0x${element.tag.toString(16)}` : 'nothing'}`);
  }
  const value = berValue(buf, element);
  if (value.length === 0 || value.length > 4 || (value[0] & 0x80) !== 0) {
    throw new Error(`unsupported integer encoding (${value.length} bytes)`);
  }
  return value.reduce((n, byte) => n * 256 + byte, 0);
}

/**
 * Decode an LDAPMessage envelope (RFC 4511 4.1.1). Controls, if any, are ignored.
 * @param {Buffer} pdu - exactly one complete LDAPMessage
 * @returns {{ messageId: number, opTag: number, op: object, pdu: Buffer }}
 */
function decodeLdapMessage(pdu) {
  const message = readBerElement(pdu, 0);
  if (message.tag !== LDAP_TAG.sequence) throw new Error(`expected an LDAPMessage SEQUENCE, got tag 0x${message.tag.toString(16)}`);
  const [id, op] = readBerChildren(pdu, message);
  if (!op) throw new Error('LDAPMessage has no protocolOp');
  return { messageId: readBerUnsigned(pdu, id, LDAP_TAG.integer), opTag: op.tag, op, pdu };
}

/**
 * LDAPResult fields of a response operation (RFC 4511 4.1.9).
 * @returns {{ resultCode: number, matchedDN: string, diagnosticMessage: string, responseName: string }}
 *   responseName is set only for an ExtendedResponse that carries one
 */
function decodeLdapResult({ pdu, op }) {
  const [code, matchedDN, diagnostic, ...rest] = readBerChildren(pdu, op);
  if (!diagnostic || matchedDN.tag !== LDAP_TAG.octetString || diagnostic.tag !== LDAP_TAG.octetString) {
    throw new Error(`malformed LDAPResult in tag 0x${op.tag.toString(16)}`);
  }
  const name = rest.find((el) => el.tag === LDAP_TAG.responseName);
  return {
    resultCode: readBerUnsigned(pdu, code, LDAP_TAG.enumerated),
    matchedDN: berValue(pdu, matchedDN).toString('utf8'),
    diagnosticMessage: berValue(pdu, diagnostic).toString('utf8'),
    responseName: name ? berValue(pdu, name).toString('latin1') : ''
  };
}

/**
 * Reads whole LDAPMessages from a socket, whatever the TCP segmentation: buffers partial reads
 * and splits reads that hold several messages (RFC 4511 5.2: messages are framed only by their
 * BER length).
 * @param {{ read: () => Promise<Buffer|null> }} sock
 * @returns {() => Promise<ReturnType<typeof decodeLdapMessage>>}
 */
function createLdapMessageReader(sock) {
  let buffered = Buffer.alloc(0);
  let received = 0; // every byte on the connection, so many small messages cannot evade the limit
  let emptyReads = 0;
  return async function nextMessage() {
    for (;;) {
      if (buffered.length > 0 && buffered[0] !== LDAP_TAG.sequence) {
        throw new Error(`response is not LDAP (first byte 0x${buffered[0].toString(16)})`);
      }
      const element = readBerElement(buffered, 0);
      if (element) {
        const pdu = buffered.subarray(0, element.end);
        buffered = buffered.subarray(element.end);
        return decodeLdapMessage(pdu);
      }
      const chunk = await sock.read();
      if (!chunk || chunk.length === 0) {
        if (!chunk || ++emptyReads >= MAX_EMPTY_READS) throw new Error('connection closed by the server');
        continue;
      }
      emptyReads = 0;
      received += chunk.length;
      if (received > MAX_RESPONSE_SIZE) throw new Error(`server sent more than ${MAX_RESPONSE_SIZE} bytes`);
      buffered = Buffer.concat([buffered, chunk]);
    }
  };
}

/**
 * Next message for `messageId`. A Notice of Disconnection or other unsolicited notification
 * (messageID 0, RFC 4511 4.4) or a message for another operation is an error.
 */
async function nextResponse(nextMessage, messageId) {
  const message = await nextMessage();
  if (message.messageId === messageId) return message;
  if (message.messageId === 0 && message.opTag === LDAP_TAG.extendedResponse) {
    const result = decodeLdapResult(message);
    const kind = result.responseName === NOTICE_OF_DISCONNECTION_OID ? 'a Notice of Disconnection' : 'an unsolicited notification';
    throw new Error(`server sent ${kind}: ${formatLdapResult(result)}`);
  }
  throw new Error(`unexpected message ID ${message.messageId} (expected ${messageId})`);
}

/** Run `step`, prefixing any error with "<phase> failed: ". */
async function inPhase(phase, step) {
  try {
    return await step();
  } catch (err) {
    throw new Error(`${phase} failed: ${err && err.message || 'Unknown error'}`, { cause: err });
  }
}

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

  // Check if error message indicates TLS/certificate issues
  const isTlsError = (errorMsg) => {
    return TLS_ERROR_KEYWORDS.some(keyword => errorMsg.includes(keyword));
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

  const nextMessage = createLdapMessageReader(sock);

  try {
    /* 2 ▸ LDAPv3 simple bind (messageID 1) */
    let bindRTT;
    metrics.bindStart = Date.now();
    markers.start('ldap-bind');
    try {
      // Defensive check for socket methods
      if (!sock || typeof sock.writeAll !== 'function' || typeof sock.read !== 'function') {
        throw new Error('Socket does not have required writeAll/read methods');
      }

      if (debugMode) {
        console.log('Debug: Sending bind request');
      }
      await sock.writeAll(ldapMessage(MESSAGE_ID.bind, bindRequest(bindDN, bindPwd)));
      const bindResult = await inPhase('Bind', async () => {
        const response = await nextResponse(nextMessage, MESSAGE_ID.bind);
        if (response.opTag !== LDAP_TAG.bindResponse) {
          throw new Error(`expected a BindResponse, got tag 0x${response.opTag.toString(16)}`);
        }
        return decodeLdapResult(response);
      });
      metrics.bindEnd = Date.now();

      bindRTT = metrics.bindEnd - metrics.bindStart;
      if (debugMode) {
        console.log(`Debug: Bind RTT: ${bindRTT} ms, result code ${bindResult.resultCode}`);
      }

      if (bindResult.resultCode !== 0) {
        throw new Error(`Authentication failed: ${formatLdapResult(bindResult)}`);
      }

      if (bindRTT > slowMs) {
        throw new Error(`Slow bind: ${bindRTT} ms (>${slowMs}ms threshold)`);
      }
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

    /* 3 ▸ Base-scope search on the bind DN (messageID 2) */
    // The bind succeeded, so the bind DN exists. Request no attributes: the check needs only
    // the result code, and the account's own entry can hold sensitive values.
    const searchReq = ldapMessage(MESSAGE_ID.search, searchRequest({
      baseObject: bindDN,
      scope: SEARCH_SCOPE_BASE,
      sizeLimit: 1,
      timeLimit: 5, // seconds
      presentAttribute: 'objectClass',
      attributes: [NO_ATTRIBUTES]
    }));

    if (debugMode) {
      console.log("Debug: Search strategy - base scope on bind DN, filter '(objectClass=*)', attributes '1.1'");
    }

    metrics.searchStart = Date.now();
    markers.start('ldap-search');
    let searchResult;
    let entries = 0;
    try {
      await sock.writeAll(searchReq);
      // Entries, references and intermediate responses may precede SearchResultDone (RFC 4511 4.5.2).
      searchResult = await inPhase('Search', async () => {
        for (;;) {
          const response = await nextResponse(nextMessage, MESSAGE_ID.search);
          switch (response.opTag) {
            case LDAP_TAG.searchResultEntry:
              entries++;
              break;
            case LDAP_TAG.searchResultReference:
            case LDAP_TAG.intermediateResponse:
              break;
            case LDAP_TAG.searchResultDone:
              return decodeLdapResult(response);
            default:
              throw new Error(`unexpected response tag 0x${response.opTag.toString(16)}`);
          }
        }
      });
      metrics.searchEnd = Date.now();
    } finally {
      markers.stop('ldap-search');
    }

    const searchRTT = metrics.searchEnd - metrics.searchStart;
    if (debugMode) {
      console.log(`Debug: Search RTT: ${searchRTT} ms, ${entries} entr${entries === 1 ? 'y' : 'ies'}, result code ${searchResult.resultCode}`);
    }

    if (searchResult.resultCode !== 0) {
      throw new Error(`Search failed: ${formatLdapResult(searchResult)}`);
    }

    if (searchRTT > slowMs) {
      throw new Error(`Slow search: ${searchRTT} ms (>${slowMs}ms threshold)`);
    }

    // Final performance summary (visible in GUI)
    const totalTime = metrics.searchEnd - metrics.connectionStart;
    const connectionTime = metrics.connectionEnd - metrics.connectionStart;
    console.log(`LDAP Monitor: PASS - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms, search: ${searchRTT}ms)`);

  } finally {
    /* End the LDAP session (RFC 4511 4.3), then close the socket */
    try {
      await sock.writeAll(ldapMessage(MESSAGE_ID.unbind, unbindRequest()));
    } catch {
      // The server may already have closed the connection
    }
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
