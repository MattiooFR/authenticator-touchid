import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { isEncryptedAuthenticatorCc, parseAuthenticatorCcEncrypted, parseImport } from '../src/lib/importers.js';
import { totp } from '../src/lib/totp.js';

// Fixtures chiffrées avec le vrai crypto-js 4.2.0, comme le fait authenticator.cc
const fx = JSON.parse(readFileSync(new URL('./fixtures-authenticator-cc.json', import.meta.url), 'utf8'));
const text = (o) => JSON.stringify(o);

describe('exports chiffrés authenticator.cc', () => {
  it('détecte un export chiffré', () => {
    expect(isEncryptedAuthenticatorCc(text(fx.v3))).toBe(true);
    expect(isEncryptedAuthenticatorCc(text(fx.v1))).toBe(true);
    expect(isEncryptedAuthenticatorCc('{"a":{"secret":"JBSWY3DPEHPK3PXP"}}')).toBe(false);
    expect(isEncryptedAuthenticatorCc('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP')).toBe(false);
  });

  it('v3 (Argon2id + clé) : déchiffre, y compris Steam', async () => {
    const { accounts, skipped } = await parseAuthenticatorCcEncrypted(text(fx.v3), fx.password);
    expect(skipped).toEqual([]);
    expect(accounts.map((a) => [a.issuer, a.secret, a.encoding ?? null])).toEqual([
      ['GitHub', 'JBSWY3DPEHPK3PXP', null],
      ['Steam', 'JBSWY3DPEHPK3PXP', 'steam'],
    ]);
  });

  it('v3 : mauvais mot de passe refusé', async () => {
    await expect(parseAuthenticatorCcEncrypted(text(fx.v3), 'faux')).rejects.toThrow('Mot de passe incorrect');
  });

  it('v2 (clé maître chiffrée)', async () => {
    const { accounts } = await parseAuthenticatorCcEncrypted(text(fx.v2), fx.password);
    expect(accounts).toHaveLength(1);
    expect(accounts[0].secret).toBe('GEZDGNBVGY3TQOJQ');
  });

  it('v1 (secret chiffré par le mot de passe) avec préfixe Battle.net', async () => {
    const { accounts } = await parseAuthenticatorCcEncrypted(text(fx.v1), fx.password);
    expect(accounts[0]).toMatchObject({ secret: 'JBSWY3DPEHPK3PXP', digits: 8, type: 'totp' });
  });

  it('sans mot de passe : signale les entrées chiffrées', () => {
    const { accounts, skipped } = parseImport(text(fx.v3));
    expect(accounts).toEqual([]);
    expect(skipped).toHaveLength(2);
  });
});

describe('Steam Guard', () => {
  it('donne 5 caractères de l’alphabet Steam', async () => {
    const code = await totp('JBSWY3DPEHPK3PXP', { encoding: 'steam', now: 0 });
    expect(code).toMatch(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
  });

  it('lien otpauth://steam et encoder=steam', () => {
    const { accounts } = parseImport('otpauth://steam/Steam:moi?secret=JBSWY3DPEHPK3PXP\notpauth://totp/S:x?secret=JBSWY3DPEHPK3PXP&encoder=steam');
    expect(accounts.map((a) => a.encoding)).toEqual(['steam', 'steam']);
  });
});
