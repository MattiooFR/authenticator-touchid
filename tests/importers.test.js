import { describe, expect, it } from 'vitest';
import { mergeAccounts, parseImport, parseOtpauth, toOtpauth } from '../src/lib/importers.js';

describe('otpauth', () => {
  it('lit émetteur, compte et paramètres', () => {
    const acc = parseOtpauth('otpauth://totp/Supabase:moi%40exemple.com?secret=JBSWY3DPEHPK3PXP&issuer=Supabase&digits=8&period=60&algorithm=SHA256');
    expect(acc).toMatchObject({ type: 'totp', issuer: 'Supabase', account: 'moi@exemple.com', secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 60, algorithm: 'SHA256' });
  });
  it('fait l’aller-retour', () => {
    const acc = parseOtpauth('otpauth://hotp/Acme:bob?secret=JBSWY3DPEHPK3PXP&issuer=Acme&counter=7');
    expect(parseOtpauth(toOtpauth(acc))).toMatchObject({ type: 'hotp', issuer: 'Acme', account: 'bob', counter: 7 });
  });
  it('refuse un secret invalide', () => {
    expect(() => parseOtpauth('otpauth://totp/x?secret=01!')).toThrow();
  });
});

// Encodeur protobuf minimal pour fabriquer un export Google Authenticator.
const varint = (n) => { const o = []; while (n > 127) { o.push((n & 127) | 128); n >>>= 7; } o.push(n); return o; };
const lenField = (f, bytes) => [...varint((f << 3) | 2), ...varint(bytes.length), ...bytes];
const intField = (f, v) => [...varint(f << 3), ...varint(v)];
const utf8 = (s) => [...new TextEncoder().encode(s)];

describe('otpauth-migration (Google Authenticator)', () => {
  it('décode les comptes', () => {
    const secret = utf8('12345678901234567890');
    const otp = [...lenField(1, secret), ...lenField(2, utf8('alice@x.com')), ...lenField(3, utf8('GitHub')), ...intField(4, 1), ...intField(5, 1), ...intField(6, 2)];
    const payload = [...lenField(1, otp), ...intField(2, 1)];
    const data = encodeURIComponent(btoa(String.fromCharCode(...payload)));
    const { accounts } = parseImport(`otpauth-migration://offline?data=${data}`);
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({ issuer: 'GitHub', account: 'alice@x.com', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', type: 'totp', digits: 6 });
  });
});

describe('sauvegarde de l’extension Authenticator', () => {
  it('importe les entrées en clair et signale les autres', () => {
    const json = JSON.stringify({
      a1: { account: 'moi', issuer: 'Dashlane', secret: 'JBSWY3DPEHPK3PXP', type: 'totp', encrypted: false, hash: 'a1', index: 0, counter: 0 },
      a2: { account: 'pro', issuer: 'Supabase', secret: 'U2FsdGVkX1+abc', type: 'totp', encrypted: true, hash: 'a2' },
      a3: { account: 's', issuer: 'Steam', secret: 'JBSWY3DPEHPK3PXP', type: 'steam', encrypted: false },
      a4: { account: 'h', issuer: 'Hex', secret: '3132333435', type: 'hex', encrypted: false, algorithm: 2 },
    });
    const { accounts, skipped } = parseImport(json);
    expect(accounts.map((a) => a.issuer)).toEqual(['Dashlane', 'Steam', 'Hex']);
    expect(accounts[1]).toMatchObject({ encoding: 'steam' });
    expect(accounts[2]).toMatchObject({ secret: 'GEZDGNBV', algorithm: 'SHA256' });
    expect(skipped).toHaveLength(1);
  });
  it('accepte des liens otpauth un par ligne et ignore le bruit', () => {
    const { accounts, skipped } = parseImport('otpauth://totp/A?secret=JBSWY3DPEHPK3PXP\n\nbonjour\notpauth://totp/B?secret=GEZDGNBV');
    expect(accounts).toHaveLength(2);
    expect(skipped).toHaveLength(1);
  });
});

it('mergeAccounts ignore les doublons de secret', () => {
  const a = parseOtpauth('otpauth://totp/A?secret=JBSWY3DPEHPK3PXP');
  const b = parseOtpauth('otpauth://totp/A2?secret=jbsw y3dp ehpk 3pxp');
  const c = parseOtpauth('otpauth://totp/C?secret=GEZDGNBV');
  const { merged, added } = mergeAccounts([a], [b, c]);
  expect(merged).toHaveLength(2);
  expect(added.map((x) => x.issuer)).toEqual(['']);
  expect(added[0].account).toBe('C');
});
