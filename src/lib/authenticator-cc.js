// Déchiffrement des exports « avec mot de passe » de l'extension Authenticator (authenticator.cc).
// Formats relus dans leur code (src/import.ts, src/models/encryption.ts, src/store/Accounts.ts) :
// - v3 : un objet { dataType: 'Key', id, salt, hash } + des entrées { dataType: 'EncOTPStorage', keyId, data }.
//        Clé = Argon2id(mot de passe, salt ; t=2, m=19 Mio, p=1, 32 octets) en base64 sans « = »,
//        utilisée comme phrase de passe CryptoJS pour `data` (JSON de l'entrée).
// - v2 : `key: { enc }` en tête ; la vraie phrase = hex(CryptoJS.AES.decrypt(enc, mot de passe)),
//        puis chaque `secret` (entrées `encrypted: true`) est chiffré avec elle.
// - v1 : entrées `encrypted: true`, `secret` chiffré directement avec le mot de passe.
// CryptoJS.AES avec une phrase de passe = format OpenSSL « Salted__ » : EVP_BytesToKey (MD5), AES-256-CBC.
import { argon2idAsync } from '../vendor/noble-hashes/argon2.js';
import { md5 } from '../vendor/noble-hashes/legacy.js';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

function evpBytesToKey(pass, salt) {
  const out = new Uint8Array(48);
  let prev = new Uint8Array(0);
  for (let filled = 0; filled < 48; filled += 16) {
    prev = md5(Uint8Array.from([...prev, ...pass, ...salt]));
    out.set(prev, filled);
  }
  return { key: out.slice(0, 32), iv: out.slice(32, 48) };
}

// Équivalent de CryptoJS.AES.decrypt(b64, passphrase). Lève une erreur si la phrase est fausse.
export async function cryptoJsDecrypt(b64, passphrase) {
  const raw = fromB64(b64);
  if (String.fromCharCode(...raw.slice(0, 8)) !== 'Salted__') throw new Error('Format CryptoJS inattendu');
  const { key, iv } = evpBytesToKey(enc.encode(passphrase), raw.slice(8, 16));
  const k = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, k, raw.slice(16)));
}

const decryptText = async (b64, passphrase) => dec.decode(await cryptoJsDecrypt(b64, passphrase));

const isKey = (v) => v && typeof v === 'object' && v.dataType === 'Key';

async function argonPassphrase(password, salt) {
  const hash = await argon2idAsync(enc.encode(password), enc.encode(salt), { t: 2, m: 19 * 1024, p: 1, dkLen: 32 });
  return toB64(hash).replace(/=+$/, '');
}

// Renvoie les entrées en clair (même forme que l'export sans mot de passe).
export async function decryptAuthenticatorCc(json, password) {
  const passphrases = new Map(); // keyId -> phrase v3
  let v2Phrase = null;
  if (json.key?.enc || json.enc) {
    v2Phrase = toHex(await cryptoJsDecrypt(json.key?.enc ?? json.enc, password).catch(() => {
      throw new Error('Mot de passe incorrect');
    }));
  }
  const out = [];
  let failed = 0;
  for (const [id, item] of Object.entries(json)) {
    if (!item || typeof item !== 'object' || isKey(item) || id === 'key') continue;
    try {
      if (item.dataType === 'EncOTPStorage') {
        if (!passphrases.has(item.keyId)) {
          const key = json[item.keyId];
          if (!isKey(key)) throw new Error('clé absente du fichier');
          passphrases.set(item.keyId, await argonPassphrase(password, key.salt));
        }
        const { dataType, keyId, data, ...rest } = item;
        out.push({ ...rest, ...JSON.parse(await decryptText(data, passphrases.get(keyId))), encrypted: false });
      } else if (item.encrypted) {
        const secret = await decryptText(item.secret, v2Phrase ?? password);
        if (!secret) throw new Error('vide');
        out.push({ ...item, secret, encrypted: false });
      } else {
        out.push(item);
      }
    } catch {
      failed += 1;
    }
  }
  if (!out.length && failed) throw new Error('Mot de passe incorrect');
  return { entries: out, failed };
}
