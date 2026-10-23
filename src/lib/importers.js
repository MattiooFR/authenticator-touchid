import { base32Decode, base32Encode, normalizeBase32 } from './base32.js';

const ALGOS = ['SHA1', 'SHA256', 'SHA512'];

export function makeAccount(fields) {
  const secret = normalizeBase32(fields.secret ?? '');
  base32Decode(secret); // valide le secret, lève une erreur lisible sinon
  const algorithm = String(fields.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
  const digits = Number(fields.digits ?? 6);
  const period = Number(fields.period ?? 30);
  if (!ALGOS.includes(algorithm)) throw new Error(`Algorithme non géré : ${algorithm}`);
  if (![6, 7, 8].includes(digits)) throw new Error(`Nombre de chiffres non géré : ${digits}`);
  if (!(period > 0 && period <= 300)) throw new Error(`Période invalide : ${period}`);
  return {
    id: crypto.randomUUID(),
    type: fields.type === 'hotp' ? 'hotp' : 'totp',
    issuer: String(fields.issuer ?? '').trim(),
    account: String(fields.account ?? '').trim(),
    secret,
    algorithm,
    digits,
    period,
    counter: Number(fields.counter ?? 0),
    ...(fields.encoding === 'steam' && fields.type !== 'hotp' ? { encoding: 'steam' } : {}),
    domains: [...new Set(fields.domains ?? [])],
    uses: fields.uses ?? {},
    createdAt: fields.createdAt ?? Date.now(),
  };
}

export function parseOtpauth(uri) {
  const u = new URL(uri.trim());
  if (u.protocol !== 'otpauth:') throw new Error('Ce n’est pas un lien otpauth://');
  const host = u.host.toLowerCase();
  if (!['totp', 'hotp', 'steam'].includes(host)) throw new Error(`Type non géré : ${host}`);
  const type = host === 'hotp' ? 'hotp' : 'totp';
  const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
  const [labelIssuer, labelAccount] = label.includes(':') ? label.split(/:(.*)/s) : ['', label];
  const p = u.searchParams;
  return makeAccount({
    type,
    issuer: p.get('issuer') || labelIssuer,
    account: labelAccount ?? '',
    secret: p.get('secret'),
    algorithm: p.get('algorithm') ?? undefined,
    digits: p.get('digits') ?? undefined,
    period: p.get('period') ?? undefined,
    counter: p.get('counter') ?? undefined,
    encoding: host === 'steam' || p.get('encoder') === 'steam' ? 'steam' : undefined,
  });
}

export function toOtpauth(acc) {
  const label = encodeURIComponent(acc.issuer ? `${acc.issuer}:${acc.account}` : acc.account);
  const p = new URLSearchParams({ secret: acc.secret });
  if (acc.issuer) p.set('issuer', acc.issuer);
  if (acc.algorithm !== 'SHA1') p.set('algorithm', acc.algorithm);
  if (acc.digits !== 6) p.set('digits', String(acc.digits));
  if (acc.type === 'hotp') p.set('counter', String(acc.counter));
  else if (acc.period !== 30) p.set('period', String(acc.period));
  if (acc.encoding === 'steam') p.set('encoder', 'steam'); // convention Aegis / andOTP
  return `otpauth://${acc.type}/${label}?${p}`;
}

// --- Export Google Authenticator (otpauth-migration://offline?data=…, protobuf) ---

function readVarint(buf, pos) {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= buf.length) throw new Error('Données de migration tronquées');
    const b = buf[pos++];
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return [Number(result), pos];
    shift += 7n;
  }
}

function readMessage(buf) {
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    let tag;
    [tag, pos] = readVarint(buf, pos);
    const field = tag >>> 3;
    const wire = tag & 7;
    if (wire === 0) {
      let v;
      [v, pos] = readVarint(buf, pos);
      fields.push([field, v]);
    } else if (wire === 2) {
      let len;
      [len, pos] = readVarint(buf, pos);
      fields.push([field, buf.subarray(pos, pos + len)]);
      pos += len;
    } else {
      throw new Error('Format de migration inattendu');
    }
  }
  return fields;
}

export function parseMigration(uri) {
  const data = new URL(uri.trim()).searchParams.get('data');
  if (!data) throw new Error('Lien de migration sans données');
  const bin = Uint8Array.from(atob(data.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const text = new TextDecoder();
  return readMessage(bin)
    .filter(([f]) => f === 1)
    .map(([, raw]) => {
      const p = Object.fromEntries(readMessage(raw).map(([f, v]) => [f, v]));
      return makeAccount({
        secret: base32Encode(p[1]),
        account: p[2] ? text.decode(p[2]) : '',
        issuer: p[3] ? text.decode(p[3]) : '',
        algorithm: { 2: 'SHA256', 3: 'SHA512' }[p[4]] ?? 'SHA1',
        digits: p[5] === 2 ? 8 : 6,
        type: p[6] === 1 ? 'hotp' : 'totp',
        counter: p[7] ?? 0,
      });
    });
}

// --- Sauvegarde JSON de l'extension Authenticator (authenticator.cc) ---

function hexToBase32(hex) {
  const clean = hex.replace(/\s/g, '');
  return base32Encode(Uint8Array.from(clean.match(/.{1,2}/g) ?? [], (h) => parseInt(h, 16)));
}

function parseAuthenticatorCcEntries(entries, skipped) {
  const accounts = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object' || e.dataType === 'Key' || !('secret' in e || 'data' in e)) continue;
    const name = [e.issuer, e.account].filter(Boolean).join(' / ') || '(sans nom)';
    if (e.encrypted || e.dataType === 'EncOTPStorage') {
      skipped.push(`${name} : entrée chiffrée, il faut le mot de passe de l’export`);
      continue;
    }
    const type = String(e.type ?? 'totp').toLowerCase();
    // Anciennes sauvegardes : le type est caché dans un préfixe du secret
    let secret = String(e.secret);
    let kind = type;
    if (/^stm-/.test(secret)) [kind, secret] = ['steam', secret.slice(4)];
    else if (/^(blz|bliz)-/.test(secret)) [kind, secret] = ['battle', secret.replace(/^(blz|bliz)-/, '')];
    const isHex = kind === 'hex' || kind === 'hhex';
    const algo = typeof e.algorithm === 'number' ? ALGOS[e.algorithm - 1] : e.algorithm;
    try {
      accounts.push(makeAccount({
        type: kind === 'hotp' || kind === 'hhex' ? 'hotp' : 'totp',
        issuer: e.issuer,
        account: e.account,
        secret: isHex ? hexToBase32(secret) : secret,
        algorithm: algo,
        // Battle.net : 8 chiffres ; Steam : 5 caractères (encoding)
        digits: kind === 'battle' ? 8 : e.digits,
        encoding: kind === 'steam' ? 'steam' : undefined,
        period: e.period,
        counter: e.counter,
      }));
    } catch (err) {
      skipped.push(`${name} : ${err.message}`);
    }
  }
  return accounts;
}

// Export d'Authenticator protégé par mot de passe : déchiffre puis importe.
export async function parseAuthenticatorCcEncrypted(text, password) {
  const { decryptAuthenticatorCc } = await import('./authenticator-cc.js');
  const { entries, failed } = await decryptAuthenticatorCc(JSON.parse(String(text).trim()), password);
  const skipped = failed ? [`${failed} entrée(s) n’ont pas pu être déchiffrées`] : [];
  return { accounts: parseAuthenticatorCcEntries(entries, skipped), skipped };
}

// Vrai si le texte est un export Authenticator chiffré (il faut alors un mot de passe).
export function isEncryptedAuthenticatorCc(text) {
  const t = String(text).trim();
  if (!t.startsWith('{')) return false;
  try {
    const json = JSON.parse(t);
    return Object.values(json).some((e) => e && typeof e === 'object' && (e.dataType === 'EncOTPStorage' || e.encrypted === true));
  } catch {
    return false;
  }
}

// Accepte : liens otpauth:// ou otpauth-migration:// (un par ligne), JSON authenticator.cc,
// ou tableau JSON de comptes. Renvoie { accounts, skipped }.
export function parseImport(text) {
  const skipped = [];
  const trimmed = String(text).trim();
  if (!trimmed) return { accounts: [], skipped };

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const json = JSON.parse(trimmed);
    if (json?.format === 'authenticator-vault-backup') {
      throw new Error('C’est une sauvegarde chiffrée : utilise « Restaurer une sauvegarde chiffrée »');
    }
    const entries = Array.isArray(json) ? json : Object.values(json);
    return { accounts: parseAuthenticatorCcEntries(entries, skipped), skipped };
  }

  const accounts = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (!l) continue;
    try {
      if (l.startsWith('otpauth-migration://')) accounts.push(...parseMigration(l));
      else if (l.startsWith('otpauth://')) accounts.push(parseOtpauth(l));
      else skipped.push(`Ligne ignorée : ${l.slice(0, 40)}…`);
    } catch (err) {
      skipped.push(`${l.slice(0, 40)}… : ${err.message}`);
    }
  }
  return { accounts, skipped };
}

// Ajoute les nouveaux comptes sans doublon (même secret + même type). Renvoie { merged, added }.
export function mergeAccounts(existing, incoming) {
  const seen = new Set(existing.map((a) => `${a.type}:${a.secret}`));
  const added = [];
  for (const acc of incoming) {
    const k = `${acc.type}:${acc.secret}`;
    if (seen.has(k)) continue;
    seen.add(k);
    added.push(acc);
  }
  return { merged: [...existing, ...added], added };
}
