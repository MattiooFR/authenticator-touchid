import { describe, expect, it } from 'vitest';
import {
  createVaultRecord, decryptJson, keyFromPrf, openWithPassword, randomBytes, rewrapPassword, unwrapDek, wrapDek,
} from '../src/lib/vault-crypto.js';

describe('coffre', () => {
  it('chiffre puis rouvre avec le bon mot de passe', async () => {
    const { vault, dek } = await createVaultRecord('correct horse battery', [{ issuer: 'X' }]);
    expect(JSON.stringify(vault)).not.toContain('"X"');
    const dek2 = await openWithPassword(vault, 'correct horse battery');
    expect(dek2).toEqual(dek);
    expect(await decryptJson(dek2, vault.data)).toEqual([{ issuer: 'X' }]);
  });

  it('refuse un mauvais mot de passe', async () => {
    const { vault } = await createVaultRecord('correct horse battery');
    await expect(openWithPassword(vault, 'faux')).rejects.toThrow('Mot de passe incorrect');
  });

  it('changer le mot de passe garde la même DEK et invalide l’ancien', async () => {
    const { vault, dek } = await createVaultRecord('ancien mot de passe');
    const v2 = await rewrapPassword(vault, dek, 'nouveau mot de passe');
    expect(await openWithPassword(v2, 'nouveau mot de passe')).toEqual(dek);
    await expect(openWithPassword(v2, 'ancien mot de passe')).rejects.toThrow();
  });

  it('la clé PRF (Touch ID) emballe et déballe la même DEK', async () => {
    const dek = randomBytes(32);
    const prf = randomBytes(32);
    const box = await wrapDek(await keyFromPrf(prf), dek);
    expect(await unwrapDek(await keyFromPrf(prf), box)).toEqual(dek);
    await expect(unwrapDek(await keyFromPrf(randomBytes(32)), box)).rejects.toThrow();
  });
}, 30_000);
