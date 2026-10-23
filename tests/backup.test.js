import { beforeAll, describe, expect, it } from 'vitest';

let backup;
beforeAll(async () => {
  globalThis.chrome = { storage: { local: {}, session: {}, sync: {} } };
  backup = await import('../src/lib/backup.js');
});

describe('splitChunks', () => {
  it('découpe et recolle à l’identique', () => {
    const text = 'x'.repeat(16_000) + 'fin';
    const parts = backup.splitChunks(text);
    expect(parts).toHaveLength(3);
    expect(parts.every((p) => p.length <= 7000)).toBe(true);
    expect(parts.join('')).toBe(text);
  });
});

it('dailyFilesToDelete garde les 30 plus récents et ignore les autres fichiers', () => {
  const names = Array.from({ length: 35 }, (_, i) => `authenticator-2026-${String(Math.floor(i / 28) + 1).padStart(2, '0')}-${String((i % 28) + 1).padStart(2, '0')}.json`);
  names.push('authenticator-latest.json', 'notes.txt');
  const del = backup.dailyFilesToDelete(names);
  expect(del).toHaveLength(5);
  expect(del).toContain('authenticator-2026-01-01.json');
  expect(del).not.toContain('authenticator-latest.json');
});

it('buildRecord ne contient que des données chiffrées', () => {
  const vault = { kdf: { salt: 's' }, wrapped: { pwd: { iv: 'a', ct: 'b' }, bio: null }, data: { iv: 'c', ct: 'd', z: 1 } };
  const r = backup.buildRecord(vault, { id: 'abc', name: 'Mac' });
  expect(r).toMatchObject({ format: 'authenticator-vault-backup', device: { id: 'abc' }, data: vault.data });
});
