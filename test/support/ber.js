// Minimal BER/LDAP encoder and decoder for tests. Written independently of ldap-monitor.js so it
// can act as an oracle for what the script sends and receives (RFC 4511 section 4 and 5.1).

/** BER length octets; `longForm` forces the 4-byte form (0x84 ...), which BER permits. */
const lengthOctets = (n, longForm) => {
  if (longForm) return [0x84, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  if (n < 0x80) return [n];
  const out = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return [0x80 | out.length, ...out];
};

export const tlv = (tag, value, { longForm = false } = {}) =>
  Buffer.concat([Buffer.from([tag, ...lengthOctets(value.length, longForm)]), value]);

const octetString = (s, opts) => tlv(0x04, Buffer.from(s, 'utf8'), opts);
const enumerated = (n) => tlv(0x0a, Buffer.from([n]));
const smallInteger = (n) => tlv(0x02, Buffer.from([n]));

export const TAG = {
  bindRequest: 0x60,
  bindResponse: 0x61,
  unbindRequest: 0x42,
  searchRequest: 0x63,
  searchResultEntry: 0x64,
  searchResultDone: 0x65,
  extendedResponse: 0x78,
  integer: 0x02,
  enumerated: 0x0a,
};

/** LDAP PDU builders for fake server responses. `longForm` applies to every length inside. */
export const ldap = {
  message: (messageId, op, { longForm = false } = {}) =>
    tlv(0x30, Buffer.concat([smallInteger(messageId), op]), { longForm }),

  result: (tag, resultCode, { matchedDN = '', diagnostic = '', longForm = false } = {}) =>
    tlv(tag, Buffer.concat([
      enumerated(resultCode),
      octetString(matchedDN, { longForm }),
      octetString(diagnostic, { longForm }),
    ]), { longForm }),

  bindResponse: (messageId, resultCode, opts = {}) =>
    ldap.message(messageId, ldap.result(TAG.bindResponse, resultCode, opts), opts),

  searchDone: (messageId, resultCode, opts = {}) =>
    ldap.message(messageId, ldap.result(TAG.searchResultDone, resultCode, opts), opts),

  /** @param {Record<string, string[]>} attributes */
  searchEntry: (messageId, dn, attributes, { longForm = false } = {}) => {
    const attrs = Object.entries(attributes).map(([type, values]) =>
      tlv(0x30, Buffer.concat([octetString(type), tlv(0x31, Buffer.concat(values.map((v) => octetString(v))))])));
    const entry = tlv(TAG.searchResultEntry, Buffer.concat([
      octetString(dn, { longForm }),
      tlv(0x30, Buffer.concat(attrs), { longForm }),
    ]), { longForm });
    return ldap.message(messageId, entry, { longForm });
  },

  /** Unsolicited Notice of Disconnection (RFC 4511 section 4.4.1): messageID 0. */
  noticeOfDisconnection: (resultCode, diagnostic = '') =>
    ldap.message(0, tlv(TAG.extendedResponse, Buffer.concat([
      enumerated(resultCode),
      octetString(''),
      octetString(diagnostic),
      tlv(0x8a, Buffer.from('1.3.6.1.4.1.1466.20036')),
    ]))),
};

/** Read one TLV at `pos`. Returns null when the buffer does not yet hold the whole element. */
export function readTlv(buf, pos = 0) {
  if (pos + 2 > buf.length) return null;
  const tag = buf[pos];
  let length = buf[pos + 1];
  let header = 2;
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n === 0 || n > 4) throw new Error(`unsupported BER length form 0x${length.toString(16)}`);
    if (pos + 2 + n > buf.length) return null;
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[pos + 2 + i];
    header += n;
  }
  const end = pos + header + length;
  if (end > buf.length) return null;
  return { tag, value: buf.subarray(pos + header, end), end };
}

/** Children of a constructed element's value. */
export function readChildren(value) {
  const out = [];
  for (let pos = 0; pos < value.length;) {
    const el = readTlv(value, pos);
    if (!el) throw new Error('truncated BER element');
    out.push(el);
    pos = el.end;
  }
  return out;
}

const uint = (value) => value.reduce((n, b) => n * 256 + b, 0);

/** Split a byte stream into complete LDAPMessages; returns { pdus, rest }. */
export function splitMessages(buf) {
  const pdus = [];
  let pos = 0;
  for (let el = readTlv(buf, pos); el; el = readTlv(buf, pos)) {
    pdus.push(buf.subarray(pos, el.end));
    pos = el.end;
  }
  return { pdus, rest: buf.subarray(pos) };
}

/** Decode the parts of an LDAP request the tests assert on. */
export function decodeRequest(pdu) {
  const message = readTlv(pdu);
  const [id, op] = readChildren(message.value);
  const request = { messageId: uint(id.value), opTag: op.tag };
  if (op.tag === TAG.bindRequest) {
    const [version, name, auth] = readChildren(op.value);
    Object.assign(request, {
      version: uint(version.value),
      name: name.value.toString('utf8'),
      authTag: auth.tag,
      password: auth.value.toString('utf8'),
    });
  } else if (op.tag === TAG.searchRequest) {
    const [base, scope, deref, sizeLimit, timeLimit, typesOnly, filter, attributes] = readChildren(op.value);
    Object.assign(request, {
      baseObject: base.value.toString('utf8'),
      scope: { tag: scope.tag, value: uint(scope.value) },
      derefAliases: { tag: deref.tag, value: uint(deref.value) },
      sizeLimit: uint(sizeLimit.value),
      timeLimit: uint(timeLimit.value),
      typesOnly: typesOnly.value[0] !== 0,
      filterTag: filter.tag,
      attributes: readChildren(attributes.value).map((a) => a.value.toString('utf8')),
    });
  }
  return request;
}
