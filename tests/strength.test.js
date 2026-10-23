import { describe, expect, it } from 'vitest';
import { MIN_LEVEL, estimateStrength, formatDuration } from '../src/lib/strength.js';

const level = (pw) => estimateStrength(pw).level;

describe('estimateStrength', () => {
  it.each([
    'azerty', 'motdepasse', 'Password123!', 'P@ssw0rd2024', 'Marseille13', 'Soleil2026!', 'abcdefgh12345678', 'aaaaaaaaaaaaaaaa',
    'Mathieu1990',
  ])('refuse %s', (pw) => expect(level(pw)).toBeLessThan(MIN_LEVEL));

  it.each([
    'cheval-agrafe-batterie-correct',
    'Gh7#kLp2qR9!mZ4x',
    'tortue violette mange 42 crêpes',
    'correcthorsebatterystaple',
    'MonChatMangeDesCroquettesAuSaumon',
  ])('accepte %s', (pw) => expect(level(pw)).toBeGreaterThanOrEqual(MIN_LEVEL));

  it('répéter le même mot ne compte pas', () => {
    expect(level('motdepasse motdepasse motdepasse motdepasse')).toBeLessThan(MIN_LEVEL);
  });

  it('plus long = plus fort', () => {
    expect(estimateStrength('lampe-orage-tulipe').bits).toBeLessThan(estimateStrength('lampe-orage-tulipe-hamac').bits);
  });
});

it('formatDuration', () => {
  expect(formatDuration(0.2)).toBe('instantané');
  expect(formatDuration(90)).toBe('1 minute');
  expect(formatDuration(3 * 86_400)).toBe('3 jours');
  expect(formatDuration(31_557_600 * 250)).toBe('2 siècles');
  expect(formatDuration(31_557_600 * 12_345).replace(/\s/g, ' ')).toBe('12 345 ans');
  expect(formatDuration(1e30)).toBe('plus que l’âge de l’univers');
});
