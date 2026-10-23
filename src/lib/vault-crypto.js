// Chiffrement du coffre.
// Une clé de données (DEK, 256 bits aléatoires) chiffre la liste des comptes en AES-GCM.
// Cette DEK est « emballée » deux fois, indépendamment :
//   - par une clé dérivée du mot de passe (PBKDF2-SHA256),
//   - par une clé dérivée de la sortie PRF du passkey Touch ID (HKDF-SHA256).
// Les deux chemins mènent à la même DEK ; aucun secret n'est stocké en clair.

export const PBKDF2_ITERATIONS = 600_000;

const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function toB64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export async function keyFromPassword(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function keyFromPrf(prfOutput) {
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode('authenticator-vault/kek-prf/v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function seal(key, bytes, aad) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes);
  return { iv: toB64(iv), ct: toB64(ct) };
}

async function open(key, box, aad) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(box.iv), additionalData: enc.encode(aad) },
    key,
    fromB64(box.ct),
  );
  return new Uint8Array(pt);
}

const dekKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

export const wrapDek = (kek, dek) => seal(kek, dek, 'dek/v1');
export const unwrapDek = (kek, box) => open(kek, box, 'dek/v1');

async function pipe(bytes, stream) {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
}

// Compressé puis chiffré (z: 1) : le coffre doit tenir dans le quota de chrome.storage.sync.
export async function encryptJson(dek, value) {
  const packed = await pipe(enc.encode(JSON.stringify(value)), new CompressionStream('gzip'));
  return { ...(await seal(await dekKey(dek), packed, 'data/v1')), z: 1 };
}

export async function decryptJson(dek, box) {
  const raw = await open(await dekKey(dek), box, 'data/v1');
  return JSON.parse(dec.decode(box.z ? await pipe(raw, new DecompressionStream('gzip')) : raw));
}

// Crée un coffre complet protégé par mot de passe. Renvoie { vault, dek }.
export async function createVaultRecord(password, accounts = []) {
  const dek = randomBytes(32);
  const salt = randomBytes(16);
  const kek = await keyFromPassword(password, salt);
  const vault = {
    v: 1,
    kdf: { name: 'PBKDF2-SHA256', salt: toB64(salt), iterations: PBKDF2_ITERATIONS },
    wrapped: { pwd: await wrapDek(kek, dek), bio: null },
    data: await encryptJson(dek, accounts),
  };
  return { vault, dek };
}

// Lève une erreur si le mot de passe est faux (échec d'authentification AES-GCM).
export async function openWithPassword(vault, password) {
  const kek = await keyFromPassword(password, fromB64(vault.kdf.salt), vault.kdf.iterations);
  try {
    return await unwrapDek(kek, vault.wrapped.pwd);
  } catch {
    throw new Error('Mot de passe incorrect');
  }
}

export async function rewrapPassword(vault, dek, newPassword) {
  const salt = randomBytes(16);
  const kek = await keyFromPassword(newPassword, salt);
  return {
    ...vault,
    kdf: { name: 'PBKDF2-SHA256', salt: toB64(salt), iterations: PBKDF2_ITERATIONS },
    wrapped: { ...vault.wrapped, pwd: await wrapDek(kek, dek) },
  };
}
