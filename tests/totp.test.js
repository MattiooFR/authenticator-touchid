import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode } from '../src/lib/base32.js';
import { hotp, totp } from '../src/lib/totp.js';

const ascii = (s) => base32Encode(new TextEncoder().encode(s));

describe('base32', () => {
  it('fait l’aller-retour', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255, 77, 13]);
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
  });
  it('tolère espaces, minuscules et padding', () => {
    expect(base32Decode('jbsw y3dp ehpk 3pxp====')).toEqual(base32Decode('JBSWY3DPEHPK3PXP'));
  });
  it('refuse un caractère invalide', () => {
    expect(() => base32Decode('ABC1')).toThrow(/invalide/);
  });
});

describe('HOTP RFC 4226', () => {
  const secret = ascii('12345678901234567890');
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  it.each(expected.map((c, i) => [i, c]))('compteur %i → %s', async (i, code) => {
    expect(await hotp(secret, i)).toBe(code);
  });
});

describe('TOTP RFC 6238 (8 chiffres)', () => {
  const secrets = {
    SHA1: ascii('12345678901234567890'),
    SHA256: ascii('12345678901234567890123456789012'),
    SHA512: ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  it.each(vectors)('t=%i', async (t, sha1, sha256, sha512) => {
    const now = t * 1000;
    expect(await totp(secrets.SHA1, { now, digits: 8, algorithm: 'SHA1' })).toBe(sha1);
    expect(await totp(secrets.SHA256, { now, digits: 8, algorithm: 'SHA256' })).toBe(sha256);
    expect(await totp(secrets.SHA512, { now, digits: 8, algorithm: 'SHA512' })).toBe(sha512);
  });
});
