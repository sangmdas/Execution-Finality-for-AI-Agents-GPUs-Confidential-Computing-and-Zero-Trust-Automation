import crypto from 'node:crypto';

export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

function assertUnicodeScalarString(s) {
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    if (cu >= 0xD800 && cu <= 0xDBFF) {
      if (i + 1 >= s.length) throw new Error('unpaired UTF-16 high surrogate');
      const lo = s.charCodeAt(i + 1);
      if (lo < 0xDC00 || lo > 0xDFFF) throw new Error('unpaired UTF-16 high surrogate');
      i++;
    } else if (cu >= 0xDC00 && cu <= 0xDFFF) {
      throw new Error('unpaired UTF-16 low surrogate');
    }
  }
}

function compareUtf8(a, b) {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export function normalizeCanonical(v) {
  if (v === null || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('integer outside portable safe range or non-integer');
    return v;
  }
  if (typeof v === 'string') { assertUnicodeScalarString(v); return v.normalize('NFC'); }
  if (Array.isArray(v)) return v.map(normalizeCanonical);
  if (typeof v === 'object') {
    const entries = [];
    const seen = new Set();
    for (const [rawKey, val] of Object.entries(v)) {
      assertUnicodeScalarString(rawKey);
      const key = rawKey.normalize('NFC');
      if (seen.has(key)) throw new Error(`key collision after Unicode normalization: ${key}`);
      seen.add(key);
      entries.push([key, normalizeCanonical(val)]);
    }
    entries.sort((a, b) => compareUtf8(a[0], b[0]));
    const out = Object.create(null);
    for (const [key, val] of entries) out[key] = val;
    return out;
  }
  throw new Error(`unsupported type ${typeof v}`);
}

function encodeCanonical(x) {
  if (x === null || typeof x === 'boolean' || typeof x === 'number' || typeof x === 'string') {
    return JSON.stringify(x);
  }
  if (Array.isArray(x)) return '[' + x.map(encodeCanonical).join(',') + ']';
  const keys = Object.keys(x).sort(compareUtf8);
  return '{' + keys.map(k => JSON.stringify(k) + ':' + encodeCanonical(x[k])).join(',') + '}';
}

export function canonical(v) {
  return encodeCanonical(normalizeCanonical(v));
}

export function sha256(v) {
  return crypto.createHash('sha256').update(Buffer.from(canonical(v), 'utf8')).digest('hex');
}

export function hmacSha256(v, key) {
  return crypto.createHmac('sha256', key).update(Buffer.from(canonical(v), 'utf8')).digest('hex');
}
