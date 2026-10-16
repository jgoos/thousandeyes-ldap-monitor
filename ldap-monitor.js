/**
 * ThousandEyes Transaction — LDAP health probe
 *
 * • Authenticated LDAPv3 simple bind
 * • Base-scope search of the Root DSE, or of a configured base DN
 * • Root DSE checks: LDAPv3 in supportedLDAPVersion, Active Directory isSynchronized and clock skew
 *   (currentTime), and optionally an expected naming context
 * • Fails (throws) on any error. Latency is not judged here: each step is a ThousandEyes marker
 *   (ldap-tcp-connect or ldaps-ssl-handshake, ldap-bind, ldap-search), and alert rules on marker
 *   duration flag slow steps (terraform/marker_alerts.tf)
 *
 * Target: the test URL, as an RFC 4516 LDAP URL
 *   ldaps://ldap.example.com            LDAPS on port 636, search the Root DSE
 *   ldaps://ldap.example.com:3269/dc=example,dc=com
 *   ldap://ldap.example.com:389         plain LDAP; needs ldapAllowCleartext (see below)
 * When the test URL is not an LDAP URL, the ldapHost/ldapPort credentials are used instead.
 *
 * Secure Credentials required:
 *   ldapMonUser  →  full bind DN   (e.g. "cn=monitor,ou=svc,dc=example,dc=com")
 *   ldapMonPass  →  password
 *
 * Optional Credentials:
 *   ldapCaBase64              →  CA certificate(s) for LDAPS, as PEM text or base64-encoded PEM
 *   ldapHost, ldapPort        →  server and port (389 or 636) when the test URL is not an LDAP URL
 *   ldapBaseDN                →  search base when the test URL has no "/" path (default: Root DSE)
 *   ldapAllowCleartext        →  'true' to allow sending the password without TLS (RFC 4513 5.1.3)
 *   ldapBindOnly              →  'true' to skip the search
 *   ldapExpectedNamingContext →  a DN the Root DSE must list in namingContexts (Root DSE search only)
 *   ldapMaxClockSkewSeconds   →  most the Root DSE currentTime may differ from the agent clock
 *                                (default: 300; 0 turns the check off)
 *   ldapRequireEntry          →  'true' to fail a search that returns no entry. Off by default: some
 *                                servers answer a base DN the account cannot read with success and
 *                                no entry, rather than noSuchObject
 *   ldapDebugMode             →  'true' for verbose debugging (default: false)
 *
 * A failure is one line that starts with its class:
 *   CONFIG: …                       missing or invalid configuration; nothing was sent
 *   TCP: …                          the connection could not be opened
 *   TLS: …                          the TLS handshake or certificate verification failed
 *   TIMEOUT: …                      a connect or a response took longer than the time limit allows
 *   BIND: …, SEARCH: …              a protocol error during that operation
 *   ROOTDSE: …                      the Root DSE reports a problem (see Root DSE checks)
 *   BIND rc=49 invalidCredentials: …, SEARCH rc=32 noSuchObject: …
 *                                   the server returned that LDAP result code
 */

import { net, credentials, test, markers } from 'thousandeyes';

// Constants
const MAX_RESPONSE_SIZE = 1000000; // 1MB safety limit for everything the server sends on one connection
const TLS_ERROR_KEYWORDS = ['certificate', 'CERT_', 'SSL', 'TLS'];
const CREDENTIAL_ALTERNATIVES = ['ldapbasedn', 'LdapBaseDN', 'LDAPBASEDN', 'ldap_base_dn', 'LDAP_BASE_DN'];
const TLS_ERROR_CODE = /^(ERR_TLS_|ERR_SSL_|CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_)/;
const NETWORK_ERROR_CODE = /^(ECONN|ETIMEDOUT|EHOST|ENET|ENOTFOUND|EAI_|EPIPE)/;
const DEFAULT_TEST_TIMEOUT_S = 30; // ThousandEyes default transaction time limit
const MAX_TEST_TIMEOUT_S = 180; // ThousandEyes maximum transaction time limit
const MIN_TIME_MARGIN_MS = 1000; // left before the time limit for reporting
const CLEANUP_TIMEOUT_MS = 1000; // most that Unbind and socket close may take together
const MAX_EMPTY_READS = 3; // consecutive empty reads treated as end of stream
const MAX_DIAGNOSTIC_LENGTH = 200; // characters of server diagnosticMessage kept in errors
const MAX_QUOTED_VALUES = 5; // server attribute values quoted in one message
const DEFAULT_MAX_CLOCK_SKEW_S = 300; // Kerberos' default tolerance for clock skew

/* ───────────── LDAP protocol codec (RFC 4511; BER per section 5.1) ───────────── */

const LDAP_TAG = {
  boolean: 0x01,
  integer: 0x02,
  octetString: 0x04,
  enumerated: 0x0a,
  sequence: 0x30,
  set: 0x31,
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
// Root DSE attributes the checks read (RFC 4512 5.1; isSynchronized and currentTime are Active Directory's).
const ROOT_DSE_ATTRIBUTES = ['namingContexts', 'supportedLDAPVersion', 'vendorVersion', 'isSynchronized', 'currentTime'];
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
 * Human-readable result code: "rc=<code> <name>: <description>".
 * @param {number} resultCode
 * @returns {string}
 */
const getLdapErrorMessage = (resultCode) => {
  const info = LDAP_RESULT_CODES[resultCode];
  return info
    ? `rc=${resultCode} ${info.name}: ${info.description}`
    : `rc=${resultCode}: Unknown LDAP result code (0x${resultCode.toString(16).padStart(2, '0')})`;
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
 * Attributes of a SearchResultEntry (RFC 4511 4.5.2), keyed by attribute type in lower case,
 * since attribute types are case-insensitive.
 * @returns {Map<string, string[]>}
 */
function decodeEntryAttributes({ pdu, op }) {
  const [objectName, attributes] = readBerChildren(pdu, op);
  if (!attributes || objectName.tag !== LDAP_TAG.octetString || attributes.tag !== LDAP_TAG.sequence) {
    throw new Error('malformed SearchResultEntry');
  }
  const entry = new Map();
  for (const attribute of readBerChildren(pdu, attributes)) {
    const [type, vals] = readBerChildren(pdu, attribute);
    if (!vals || type.tag !== LDAP_TAG.octetString || vals.tag !== LDAP_TAG.set) {
      throw new Error('malformed attribute in SearchResultEntry');
    }
    const values = readBerChildren(pdu, vals).map((value) => berValue(pdu, value).toString('utf8'));
    entry.set(berValue(pdu, type).toString('utf8').toLowerCase(), values);
  }
  return entry;
}

/**
 * Reads whole LDAPMessages from a socket, whatever the TCP segmentation: buffers partial reads
 * and splits reads that hold several messages (RFC 4511 5.2: messages are framed only by their
 * BER length).
 * @param {{ read: () => Promise<Buffer|null> }} sock
 * @param {() => number} remainingMs - time left in the probe budget; a read waits no longer
 * @returns {() => Promise<ReturnType<typeof decodeLdapMessage>>}
 */
function createLdapMessageReader(sock, remainingMs) {
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
      const chunk = await withTimeout(sock.read(), remainingMs(), 'waiting for the server response');
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
    throw new Error(`server sent ${kind}, ${formatLdapResult(result)}`);
  }
  throw new Error(`unexpected message ID ${message.messageId} (expected ${messageId})`);
}

/**
 * Run `step`, prefixing any error with its failure class: "<PHASE>: ", or "TIMEOUT: <phase>: " for
 * a response that did not arrive in time.
 */
async function inPhase(phase, step) {
  try {
    return await step();
  } catch (err) {
    const message = err && err.message || 'Unknown error';
    const timedOut = err && err.code === 'ETIMEDOUT';
    throw failure(timedOut ? 'TIMEOUT' : phase, timedOut ? `${phase.toLowerCase()}: ${message}` : message, err);
  }
}

/* ───────────── Time budget, transport and TLS helpers ───────────── */

/**
 * The test time limit in milliseconds. ThousandEyes reports `timeout` in seconds (its sample
 * script computes `settings.timeout / 2 * 1000`); a value above the 180-second maximum can only
 * be milliseconds already.
 * @param {unknown} timeout - test.getSettings().timeout
 * @returns {number}
 */
const testTimeLimitMs = (timeout) => {
  const value = Number(timeout);
  if (!Number.isFinite(value) || value <= 0) return DEFAULT_TEST_TIMEOUT_S * 1000;
  return value <= MAX_TEST_TIMEOUT_S ? value * 1000 : value;
};

/**
 * Time the probe may use, leaving a margin before ThousandEyes ends the transaction so that the
 * probe's own, more specific, timeout error is reported instead of a generic one.
 * @param {number} timeLimitMs
 * @returns {number}
 */
const probeBudgetMs = (timeLimitMs) =>
  timeLimitMs - Math.min(Math.max(MIN_TIME_MARGIN_MS, timeLimitMs * 0.1), timeLimitMs / 2);

/**
 * Settle like `promise`, or reject with an ETIMEDOUT error after `ms`.
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} what - described in the error, e.g. "connect to ldap.example.com:636"
 * @param {(value: T) => void} [onLateValue] - receives a value that arrives after the timeout,
 *   such as a socket that must still be closed
 * @returns {Promise<T>}
 * @template T
 */
function withTimeout(promise, ms, what, onLateValue) {
  const limit = Math.max(0, Math.round(ms));
  let timer;
  let timedOut = false;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(Object.assign(new Error(`${what} timed out after ${limit} ms`), { code: 'ETIMEDOUT' }));
    }, limit);
  });
  if (onLateValue) promise.then((value) => { if (timedOut) onLateValue(value); }, () => {});
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Error message with its code, when the message does not already include it. */
const describeError = (err) => {
  const message = err && err.message || 'Unknown error';
  return err && err.code && !message.includes(err.code) ? `${message} (${err.code})` : message;
};

/**
 * An error whose one-line message starts with its failure class (see the header), so an alert or
 * log line says what kind of failure it is before the details.
 * @param {string} failureClass - CONFIG, TCP, TLS, TIMEOUT, BIND or SEARCH
 * @param {string} message
 * @param {unknown} [cause]
 */
const failure = (failureClass, message, cause) =>
  new Error(`${failureClass}: ${message}`, cause === undefined ? undefined : { cause });

const configError = (message) => failure('CONFIG', message);

/**
 * Whether a connect error came from TLS rather than from the network. The error code decides when
 * there is one; otherwise the message is checked for TLS keywords with the host name removed, so
 * a host such as "certificate-gw.example.com" does not make a network error look like TLS.
 * @param {Error & { code?: string }} err
 * @param {string} host
 */
const isTlsError = (err, host) => {
  const code = err && err.code || '';
  if (TLS_ERROR_CODE.test(code)) return true;
  if (NETWORK_ERROR_CODE.test(code)) return false;
  const message = (err && err.message || '').split(host).join('');
  return TLS_ERROR_KEYWORDS.some((keyword) => message.includes(keyword));
};

/** "host:port" for messages, with an IPv6 address in brackets. */
const hostPort = (host, port) => `${host.includes(':') ? `[${host}]` : host}:${port}`;

/** IPv4 or IPv6 literal. TLS SNI must not carry an IP address (RFC 6066 section 3). */
const isIpAddress = (host) => /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');

/**
 * CA certificates from the ldapCaBase64 credential, which may hold PEM text or base64-encoded
 * PEM. Line breaks are restored, since a credential field may have turned them into spaces.
 * @param {string} value
 * @returns {string[]} one PEM block per certificate
 * @throws {Error} a configuration error when no certificate is found
 */
function parseCaCertificates(value) {
  const text = String(value).trim();
  const pem = text.includes('-----BEGIN') ? text : Buffer.from(text, 'base64').toString('utf8');
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks) {
    throw configError('ldapCaBase64 holds no certificate; expected PEM text ("-----BEGIN CERTIFICATE-----"), as-is or base64-encoded');
  }
  return blocks.map((block) => {
    const body = block.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
    return `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  });
}

/** Start or stop a ThousandEyes marker; a marker error is logged, never fatal. */
const startMarker = (name) => {
  try {
    markers.start(name);
  } catch (err) {
    console.log(`Warning: could not start marker ${name}: ${describeError(err)}`);
  }
};
const stopMarker = (name) => {
  try {
    markers.stop(name);
  } catch (err) {
    console.log(`Warning: could not stop marker ${name}: ${describeError(err)}`);
  }
};

/* ───────────── Root DSE checks ───────────── */

/**
 * Milliseconds since the epoch for a GeneralizedTime (RFC 4517 3.3.13), such as Active
 * Directory's "20261016201530.0Z".
 * @param {string} text
 * @returns {number} NaN when `text` is not a GeneralizedTime
 */
function parseGeneralizedTime(text) {
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})$/.exec(String(text).trim());
  if (!match) return NaN;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map((part) => (part === undefined ? undefined : Number(part)));
  const [fraction, zone] = match.slice(7);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) return NaN;
  let ms = Date.UTC(year, month - 1, day, hour, minute ?? 0, second ?? 0);
  // A fraction is of the last unit given: second, minute or hour.
  if (fraction) ms += Number(`0.${fraction}`) * (second !== undefined ? 1000 : minute !== undefined ? 60000 : 3600000);
  if (zone !== 'Z') ms -= (zone[0] === '-' ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3))) * 60000;
  return ms;
}

/** A DN for comparison, ignoring letter case and spaces around separators. */
const normalizeDn = (dn) => String(dn).trim().toLowerCase().replace(/\s*([,=+])\s*/g, '$1');

/** Server attribute values for a message: quoted, made safe, and at most MAX_QUOTED_VALUES. */
const quoteValues = (values) => values.slice(0, MAX_QUOTED_VALUES).map((v) => `"${sanitizeServerText(v)}"`).join(', ') +
  (values.length > MAX_QUOTED_VALUES ? `, and ${values.length - MAX_QUOTED_VALUES} more` : '');

/**
 * Check what the Root DSE (RFC 4512 5.1) says about the server. Attributes a server does not
 * publish are not checked, except namingContexts when an expected naming context is set.
 * @param {Map<string, string[]> | null} entry - the Root DSE attributes; null when no entry came back
 * @param {{ expectedNamingContext: string, maxClockSkewS: number, agentTimeMs: number }} options
 *   agentTimeMs is the agent clock when the server answered; maxClockSkewS 0 skips the skew check
 * @returns {string[]} facts for the PASS summary, such as the vendorVersion and clock skew
 * @throws {Error} a ROOTDSE failure that lists every problem found
 */
function checkRootDse(entry, { expectedNamingContext, maxClockSkewS, agentTimeMs }) {
  const values = (name) => (entry && entry.get(name.toLowerCase())) || [];
  const problems = [];
  const facts = [];

  const [vendorVersion] = values('vendorVersion');
  if (vendorVersion) facts.push(`vendorVersion: ${sanitizeServerText(vendorVersion)}`);

  // Active Directory publishes FALSE until the domain controller is fully synchronized.
  if (values('isSynchronized').some((v) => v.trim().toUpperCase() === 'FALSE')) {
    problems.push('isSynchronized is FALSE: the server reports that it is not fully synchronized');
  }

  const versions = values('supportedLDAPVersion');
  if (versions.length > 0 && !versions.some((v) => v.trim() === '3')) {
    problems.push(`supportedLDAPVersion lists ${quoteValues(versions)} but not 3`);
  }

  if (expectedNamingContext) {
    const contexts = values('namingContexts');
    if (!entry) {
      problems.push(`the server returned no Root DSE entry; expected namingContexts to include "${expectedNamingContext}"`);
    } else if (contexts.length === 0) {
      problems.push(`the Root DSE lists no namingContexts; expected "${expectedNamingContext}"`);
    } else if (!contexts.some((dn) => normalizeDn(dn) === normalizeDn(expectedNamingContext))) {
      problems.push(`namingContexts does not include "${expectedNamingContext}"; the server lists ${quoteValues(contexts)}`);
    }
  }

  // The agent clock is the reference. Kerberos fails beyond its tolerance, 5 minutes by default.
  const [currentTime] = values('currentTime');
  const serverTimeMs = currentTime ? parseGeneralizedTime(currentTime) : NaN;
  if (Number.isFinite(serverTimeMs)) {
    const skewS = Math.round((serverTimeMs - agentTimeMs) / 1000);
    facts.push(`clock skew: ${skewS < 0 ? '-' : '+'}${Math.abs(skewS)} s`);
    if (maxClockSkewS > 0 && Math.abs(skewS) > maxClockSkewS) {
      problems.push(`server clock is ${Math.abs(skewS)} s ${skewS > 0 ? 'ahead of' : 'behind'} the agent clock ` +
        `(currentTime ${sanitizeServerText(currentTime)}); the limit is ${maxClockSkewS} s (ldapMaxClockSkewSeconds)`);
    }
  }

  if (problems.length > 0) throw failure('ROOTDSE', problems.join('; '));
  return facts;
}

/* ───────────── Target configuration ───────────── */

/** Credential flag: 'true', '1' or 'yes', in any letter case. */
const isEnabled = (value) => ['true', '1', 'yes'].includes(String(value || '').trim().toLowerCase());

/**
 * A whole-number credential, or `fallback` when it is not set.
 * @throws {Error} a configuration error for anything but digits
 */
const wholeNumberSetting = (name, value, fallback) => {
  const text = String(value ?? '').trim();
  if (text === '') return fallback;
  if (!/^\d+$/.test(text)) throw configError(`${name} must be a whole number, not "${sanitizeServerText(text)}"`);
  return Number(text);
};

/**
 * Parse an RFC 4516 LDAP URL: ldap[s]://host[:port][/dn[?attributes?scope?filter?extensions]].
 * The scheme picks TLS, the port defaults to 389 or 636, and the DN is the search base. A "/"
 * with an empty DN selects the Root DSE explicitly; no "/" at all leaves the base unset (null).
 * Attributes, scope, filter and extensions must be empty: the probe always runs a base-scope
 * (objectClass=*) search that returns no attributes.
 * @param {unknown} url - test.getSettings().url
 * @returns {{ host: string, port: number, tls: boolean, baseDN: string | null } | null}
 *   null when `url` is not an ldap:// or ldaps:// URL
 * @throws {Error} a configuration error for a malformed LDAP URL
 */
function parseLdapUrl(url) {
  const text = String(url || '').trim();
  if (!/^ldaps?:\/\//i.test(text)) return null;
  const match = /^(ldaps?):\/\/(\[[^\]]*\]|[^:/?#]*)(?::(\d*))?(?:\/([^?#]*)(\?[^#]*)?)?$/i.exec(text);
  if (!match) throw configError(`the test URL "${text}" is not a valid LDAP URL`);
  const [, scheme, rawHost, rawPort, rawDN, query = ''] = match;
  const tls = scheme.toLowerCase() === 'ldaps';
  if (!rawHost) throw configError(`the test URL "${text}" has no host`);
  // A registered name may be percent-encoded (RFC 3986 section 3.2.2); an IPv6 literal sits in brackets.
  let host;
  if (rawHost.startsWith('[')) {
    host = rawHost.slice(1, -1);
    if (!/^[0-9A-Fa-f:.]+$/.test(host)) throw configError(`the test URL "${text}" has an invalid IPv6 address`);
  } else {
    try {
      host = decodeURIComponent(rawHost);
    } catch {
      throw configError(`the host in the test URL "${text}" has invalid percent-encoding`);
    }
    if (!/^[A-Za-z0-9._-]+$/.test(host)) throw configError(`the test URL "${text}" has an invalid host name`);
  }
  const port = rawPort ? Number(rawPort) : (tls ? 636 : 389);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw configError(`the test URL "${text}" has an invalid port`);
  if (query.slice(1).split('?').some((part) => part !== '')) {
    throw configError('LDAP URL attributes, scope, filter and extensions are not supported; give only the base DN after the host');
  }
  let baseDN = null;
  try {
    if (rawDN !== undefined) baseDN = decodeURIComponent(rawDN);
  } catch {
    throw configError(`the DN in the test URL "${text}" has invalid percent-encoding`);
  }
  return { host, port, tls, baseDN };
}

/**
 * Where to connect and what to search. The test URL wins when it is an LDAP URL; otherwise the
 * ldapHost and ldapPort credentials are used, with port 636 meaning LDAPS. The search base is the
 * URL's DN when the URL has a "/" path (an empty DN there is the Root DSE), else the ldapBaseDN
 * credential, else the Root DSE ("").
 * @returns {{ host: string, port: number, tls: boolean, baseDN: string, source: string }}
 * @throws {Error} a configuration error when no server is configured or the URL is malformed
 */
function resolveTarget({ testUrl, ldapHost, ldapPort, ldapBaseDN }) {
  const fromUrl = parseLdapUrl(testUrl);
  if (fromUrl) return { ...fromUrl, baseDN: fromUrl.baseDN ?? ldapBaseDN, source: 'test URL' };

  const host = String(ldapHost || '').trim();
  if (!host) {
    throw configError('no LDAP server configured. Set the test URL to ldaps://<host> (or ldap://<host>:389), or set the ldapHost credential');
  }
  const port = parseInt(ldapPort, 10) || 636;
  if (port !== 389 && port !== 636) {
    throw configError(`invalid port ${port} in the ldapPort credential: must be 389 (LDAP) or 636 (LDAPS); use an ldap:// or ldaps:// test URL for other ports`);
  }
  return { host, port, tls: port === 636, baseDN: ldapBaseDN, source: 'ldapHost credential' };
}

/**
 * Settings from the test and from Secure Credentials, before validation.
 * Uses secure credentials for configuration since testVars are not available
 */
const getTestConfig = () => {
  // Get test settings defensively for TypeScript compatibility
  let testTimeout = null;
  let testUrl = '';
  
  if (test && 'getSettings' in test) {
    try {
      const getSettingsMethod = test['getSettings'];
      if (typeof getSettingsMethod === 'function') {
        const settings = getSettingsMethod.call(test);
        if (settings) {
          testTimeout = settings.timeout;
          testUrl = settings.url;
        }
      }
    } catch {
      // Ignore if getSettings fails
    }
  }

  // Helper function for secure credential access
  const getCredential = (name) => {
    try {
      return credentials.get(name);
    } catch {
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

  // Configuration with secure credentials and sensible defaults
  return {
    testUrl,
    ldapHost,
    ldapPort,
    ldapBaseDN: typeof ldapBaseDN === 'string' ? ldapBaseDN.trim() : '',
    allowCleartext: isEnabled(getCredential('ldapAllowCleartext')),
    timeoutMs: testTimeLimitMs(testTimeout),
    retryDelayMs: 100,
    maxRetries: 2,
    tlsMinVersion: 'TLSv1.2',
    bindOnlyMode: isEnabled(getCredential('ldapBindOnly')),
    expectedNamingContext: String(getCredential('ldapExpectedNamingContext') ?? '').trim(),
    maxClockSkewS: wholeNumberSetting('ldapMaxClockSkewSeconds', getCredential('ldapMaxClockSkewSeconds'), DEFAULT_MAX_CLOCK_SKEW_S),
    requireEntry: isEnabled(getCredential('ldapRequireEntry'))
  };
};

async function runTest() {
  // The time budget starts now: every network wait below is bounded by what is left of it.
  const probeStart = Date.now();

  // Get configuration from credentials and defaults
  const cfg = getTestConfig();

  /* ─────────── dynamic configuration loaded ─────────── */
  const {
    timeoutMs,
    retryDelayMs,
    maxRetries,
    tlsMinVersion,
    bindOnlyMode,
    allowCleartext,
    expectedNamingContext,
    maxClockSkewS,
    requireEntry
  } = cfg;
  
  // Helper function for secure credential access  
  const getCredential = (name) => {
    try {
      return credentials.get(name);
    } catch {
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
  
  /* Input validation */
  if (!bindDN || !bindPwd) {
    throw configError('missing credentials: ensure ldapMonUser and ldapMonPass are configured');
  }

  const { host, port, tls: useTls, baseDN, source } = resolveTarget(cfg);
  if (debugMode) {
    console.log(`Debug: Target ${useTls ? 'ldaps' : 'ldap'}://${hostPort(host, port)} from the ${source}; search base ${baseDN ? `"${baseDN}"` : 'Root DSE'}`);
  }
  if (expectedNamingContext && (bindOnlyMode || baseDN)) {
    throw configError(`ldapExpectedNamingContext needs the Root DSE search, so it cannot be used with ${bindOnlyMode ? 'ldapBindOnly' : `the search base "${baseDN}"`}`);
  }

  // A simple bind sends the password as is; without TLS anyone on the path can read it.
  if (!useTls) {
    if (!allowCleartext) {
      throw configError(`refusing to send the bind password to ${hostPort(host, port)} without TLS (RFC 4513 section 5.1.3). Use ldaps://, or set the ldapAllowCleartext credential to true to accept the risk`);
    }
    console.log(`Warning: sending the bind password to ${hostPort(host, port)} without TLS (ldapAllowCleartext is set)`);
  }

  const deadline = probeStart + probeBudgetMs(timeoutMs);
  const remainingMs = () => deadline - Date.now();


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
        } catch {
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
        } catch {
          // Ignore certificate access errors
        }
      }
      
      const cipherName = cipher && cipher.name ? cipher.name : 'unknown';
      const commonName = cn || 'unknown';
      console.log(`TLS cipher: ${cipherName}; peer CN: ${commonName}`);
      
    } catch {
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
        
      } catch {
        // If any timer approach fails, resolve immediately
        resolve();
      }
    });
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

  /* 1 ▸ Open the socket (TLS for ldaps://, or port 636 from the credentials) */
  // Certificate problems and bad CA configuration will not go away on retry, so they fail at once;
  // other connect errors are retried while the time budget allows.
  let tlsOptions;
  if (useTls) {
    tlsOptions = { minVersion: tlsMinVersion, rejectUnauthorized: true };
    if (!isIpAddress(host)) tlsOptions.servername = host;
    if (caBase64) {
      tlsOptions.ca = parseCaCertificates(caBase64);
      if (debugMode) {
        console.log(`Debug: Using ${tlsOptions.ca.length} custom CA certificate(s) for LDAPS connection`);
      }
    } else if (debugMode) {
      console.log('Debug: Using system CA certificates');
    }
    console.log(`Establishing LDAPS connection with ${caBase64 ? 'custom CA certificate' : 'system CA certificates'}`);
  }

  // ThousandEyes rejects restarting a marker, so the connect marker spans all attempts and each
  // attempt has its own marker.
  const connectMarkerName = useTls ? 'ldaps-ssl-handshake' : 'ldap-tcp-connect';
  const closeQuietly = (lateSocket) => {
    try {
      if (lateSocket && typeof lateSocket.end === 'function') lateSocket.end();
    } catch {
      // Nothing to report for a socket nobody uses
    }
  };
  let sock;
  let attempt = 0;
  for (;;) {
    attempt++;
    startMarker(`ldap-attempt-${attempt}`);
    if (attempt === 1) startMarker(connectMarkerName);
    metrics.connectionStart = Date.now();
    try {
      const connecting = useTls ? net.connectTls(port, host, tlsOptions) : net.connect(port, host);
      sock = await withTimeout(connecting, remainingMs(), `connect to ${hostPort(host, port)}`, closeQuietly);
      metrics.connectionEnd = Date.now();
      stopMarker(`ldap-attempt-${attempt}`);
      break;
    } catch (err) {
      stopMarker(`ldap-attempt-${attempt}`);
      const tlsFailure = useTls && isTlsError(err, host);
      console.log(`${tlsFailure ? 'Certificate/TLS error on attempt' : 'Connection attempt'} ${attempt}${tlsFailure ? '' : ' failed'}: ${describeError(err)}`);

      if (tlsFailure) {
        stopMarker(connectMarkerName);
        const hint = caBase64 ? '' : '. If the server certificate comes from a private CA, provide it in the ldapCaBase64 credential';
        throw failure('TLS', `handshake with ${hostPort(host, port)} failed: ${describeError(err)}${hint}`, err);
      }
      if (attempt > maxRetries || remainingMs() <= retryDelayMs) {
        stopMarker(connectMarkerName);
        if (err && err.code === 'ETIMEDOUT') throw failure('TIMEOUT', `${err.message} (attempt ${attempt})`, err);
        throw failure('TCP', `connection to ${hostPort(host, port)} failed after ${attempt} attempt${attempt === 1 ? '' : 's'}: ${describeError(err)}`, err);
      }
      await createDelay(retryDelayMs);
    }
  }
  stopMarker(connectMarkerName);

  if (useTls) {
    logTLSInfo(sock);
  }

  // The time budget bounds every wait; the socket idle timeout, where supported, is a backstop.
  if (typeof sock.setTimeout === 'function') {
    sock.setTimeout(timeoutMs);
  }

  // Set test variable defensively for TypeScript compatibility
  if (test && 'setVariable' in test) {
    try {
      const setVariableMethod = test['setVariable']; // Use bracket notation for TypeScript compatibility
      if (typeof setVariableMethod === 'function') {
        setVariableMethod.call(test, 'retries', attempt - 1);
      }
    } catch {
      // Ignore if setVariable fails
    }
  }

  const nextMessage = createLdapMessageReader(sock, remainingMs);

  try {
    /* 2 ▸ LDAPv3 simple bind (messageID 1) */
    let bindRTT;
    metrics.bindStart = Date.now();
    markers.start('ldap-bind');
    try {
      if (debugMode) {
        console.log('Debug: Sending bind request');
      }
      const bindResult = await inPhase('BIND', async () => {
        // Defensive check for socket methods
        if (!sock || typeof sock.writeAll !== 'function' || typeof sock.read !== 'function') {
          throw new Error('Socket does not have required writeAll/read methods');
        }
        await sock.writeAll(ldapMessage(MESSAGE_ID.bind, bindRequest(bindDN, bindPwd)));
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
        throw new Error(`BIND ${formatLdapResult(bindResult)}`);
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

    /* 3 ▸ Base-scope search of the search base, the Root DSE by default (messageID 2) */
    // From the Root DSE, request only the attributes the checks read. From a base DN, request no
    // attributes: the check needs only the result code, and the entry may be the account's own.
    const attributes = baseDN ? [NO_ATTRIBUTES] : ROOT_DSE_ATTRIBUTES;
    const searchReq = ldapMessage(MESSAGE_ID.search, searchRequest({
      baseObject: baseDN,
      scope: SEARCH_SCOPE_BASE,
      sizeLimit: 1,
      timeLimit: 5, // seconds
      presentAttribute: 'objectClass',
      attributes
    }));

    if (debugMode) {
      console.log(`Debug: Search - base scope on ${baseDN ? `"${baseDN}"` : 'the Root DSE'}, filter '(objectClass=*)', attributes '${attributes.join(' ')}'`);
    }

    metrics.searchStart = Date.now();
    markers.start('ldap-search');
    let searchResult;
    let entries = 0;
    let rootDse = null;
    try {
      // Entries, references and intermediate responses may precede SearchResultDone (RFC 4511 4.5.2).
      searchResult = await inPhase('SEARCH', async () => {
        await sock.writeAll(searchReq);
        for (;;) {
          const response = await nextResponse(nextMessage, MESSAGE_ID.search);
          switch (response.opTag) {
            case LDAP_TAG.searchResultEntry:
              entries++;
              if (!baseDN && !rootDse) rootDse = decodeEntryAttributes(response);
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
      throw new Error(`SEARCH ${formatLdapResult(searchResult)}`);
    }

    if (requireEntry && entries === 0) {
      throw failure('SEARCH', `no entry returned for ${baseDN ? `"${baseDN}"` : 'the Root DSE'}; the base DN may not exist, or the account may not be allowed to read it (ldapRequireEntry is set)`);
    }

    let facts = [];
    if (!baseDN) {
      if (debugMode) {
        for (const [type, values] of rootDse || []) console.log(`Debug: Root DSE ${type}: ${quoteValues(values)}`);
      }
      facts = checkRootDse(rootDse, {
        expectedNamingContext,
        maxClockSkewS,
        agentTimeMs: (metrics.searchStart + metrics.searchEnd) / 2
      });
    }

    // Final performance summary (visible in GUI)
    const totalTime = metrics.searchEnd - metrics.connectionStart;
    const connectionTime = metrics.connectionEnd - metrics.connectionStart;
    console.log(`LDAP Monitor: PASS - Total ${totalTime}ms (connect: ${connectionTime}ms, bind: ${bindRTT}ms, search: ${searchRTT}ms)${facts.map((fact) => `; ${fact}`).join('')}`);

  } finally {
    /* End the LDAP session (RFC 4511 4.3), then close the socket. Both share one short window:
       at most CLEANUP_TIMEOUT_MS and half the time left before ThousandEyes ends the transaction,
       so cleanup cannot push the result past the time limit. */
    const timeLeftMs = probeStart + timeoutMs - Date.now();
    const cleanupDeadline = Date.now() + Math.min(CLEANUP_TIMEOUT_MS, Math.max(0, timeLeftMs / 2));
    const cleanupLeftMs = () => cleanupDeadline - Date.now();
    try {
      await withTimeout(sock.writeAll(ldapMessage(MESSAGE_ID.unbind, unbindRequest())), cleanupLeftMs(), 'Unbind');
    } catch {
      // The server may already have closed the connection
    }
    if (typeof sock.end === 'function') {
      try {
        await withTimeout(Promise.resolve(sock.end()), cleanupLeftMs(), 'closing the socket');
      } catch (closeErr) {
        console.error(`Error closing socket: ${describeError(closeErr)}`);
      }
    }
  }
}

// Execute the LDAP test with proper error handling
runTest().catch(err => {
  console.error('Test failed:', err && err.message || 'Unknown error');
  throw err;
});
