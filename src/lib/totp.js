import { base32Decode } from './base32.js';

const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const keyCache = new Map();

async function hmacKey(secret, algorithm) {
  const cacheKey = `${algorithm}:${secret}`;
  let key = keyCache.get(cacheKey);
  if (!key) {
    key = await crypto.subtle.importKey(
      'raw',
      base32Decode(secret),
      { name: 'HMAC', hash: HASHES[algorithm] ?? 'SHA-1' },
      false,
      ['sign'],
    );
    keyCache.set(cacheKey, key);
  }
  return key;
}

export function clearKeyCache() {
  keyCache.clear();
}

// Steam Guard : 5 caractères dans l'alphabet de Steam au lieu de chiffres.
const STEAM_CHARS = '23456789BCDFGHJKMNPQRTVWXY';
function steamCode(bin) {
  let out = '';
  for (let i = 0; i < 5; i++) {
    out += STEAM_CHARS[bin % STEAM_CHARS.length];
    bin = Math.floor(bin / STEAM_CHARS.length);
  }
  return out;
}

export async function hotp(secret, counter, { algorithm = 'SHA1', digits = 6, encoding } = {}) {
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret, algorithm), msg));
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  if (encoding === 'steam') return steamCode(bin);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function totpCounter(period = 30, now = Date.now()) {
  return Math.floor(now / 1000 / period);
}

export function secondsLeft(period = 30, now = Date.now()) {
  return period - (Math.floor(now / 1000) % period);
}

export function totp(secret, { period = 30, now = Date.now(), ...opts } = {}) {
  return hotp(secret, totpCounter(period, now), opts);
}
