import { describe, expect, it } from 'vitest';
import { issuerMatchesSite, matchesQuery, rankForSite, recordUse, siteFromUrl } from '../src/lib/domains.js';

describe('siteFromUrl', () => {
  it.each([
    ['https://app.supabase.com/dashboard', 'supabase.com'],
    ['https://www.dashlane.com/', 'dashlane.com'],
    ['https://accounts.google.co.uk/x', 'google.co.uk'],
    ['http://github.com', 'github.com'],
    ['https://192.168.1.10:8443/login', '192.168.1.10'],
    ['chrome://extensions', null],
    ['chrome-extension://abc/app.html', null],
    ['about:blank', null],
    ['pas une url', null],
  ])('%s → %s', (url, site) => expect(siteFromUrl(url)).toBe(site));
});

describe('issuerMatchesSite', () => {
  it('reconnaît le nom de l’émetteur dans le domaine', () => {
    expect(issuerMatchesSite('Supabase', 'supabase.com')).toBe(true);
    expect(issuerMatchesSite('Match IT', 'matchit.io')).toBe(true);
    expect(issuerMatchesSite('Google', 'google.fr')).toBe(true);
    expect(issuerMatchesSite('GitHub', 'gitlab.com')).toBe(false);
    expect(issuerMatchesSite('X', 'x.com')).toBe(false); // trop court, trop de faux positifs
  });
});

describe('rankForSite', () => {
  const a = (issuer, domains = [], uses = {}) => ({ id: issuer, issuer, account: '', domains, uses });
  it('appris d’abord (par usage), puis deviné, puis le reste', () => {
    const accounts = [a('Perso', ['ovh.com'], { 'ovh.com': 1 }), a('OVH'), a('Pro', ['ovh.com'], { 'ovh.com': 9 }), a('Stripe')];
    const r = rankForSite(accounts, 'ovh.com');
    expect(r.learned.map((x) => x.id)).toEqual(['Pro', 'Perso']);
    expect(r.guessed.map((x) => x.id)).toEqual(['OVH']);
    expect(r.others.map((x) => x.id)).toEqual(['Stripe']);
  });
});

describe('recordUse', () => {
  it('ajoute le domaine une seule fois et compte les usages', () => {
    let acc = { id: '1', domains: [], uses: {} };
    acc = recordUse(acc, 'supabase.com', 1);
    acc = recordUse(acc, 'supabase.com', 2);
    expect(acc.domains).toEqual(['supabase.com']);
    expect(acc.uses['supabase.com']).toBe(2);
    expect(recordUse(acc, null)).toBe(acc);
  });
});

it('matchesQuery cherche aussi dans les domaines', () => {
  expect(matchesQuery({ issuer: 'Perso', account: 'moi', domains: ['ovh.com'] }, 'ovh')).toBe(true);
});
