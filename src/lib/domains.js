// Suffixes à deux niveaux les plus courants. Sans la Public Suffix List complète,
// on garde « exemple.co.uk » plutôt que « co.uk ».
const TWO_LEVEL = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.kr',
  'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.hk', 'com.sg', 'co.in', 'co.za', 'co.il',
  'gouv.fr', 'asso.fr', 'com.es', 'com.pl', 'com.ua', 'co.id', 'com.my', 'com.ph', 'com.vn',
]);

// Pages où un code n'est jamais « utilisé » : ne rien apprendre dessus.
const IGNORED = new Set(['localhost', 'newtab', 'extensions']);

export function siteFromUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || IGNORED.has(host)) return null;
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join('.');
  return TWO_LEVEL.has(last2) ? labels.slice(-3).join('.') : last2;
}

const squash = (s) => String(s ?? '').toLowerCase().normalize('NFD').replace(/[^a-z0-9]/g, '');

// « Supabase » ↔ supabase.com, « Google » ↔ google.fr, « Match IT » ↔ matchit.io
export function issuerMatchesSite(issuer, site) {
  if (!site) return false;
  const label = squash(site.split('.')[0]);
  const name = squash(issuer);
  if (label.length < 3 || name.length < 3) return false;
  return name === label || name.includes(label) || (name.length >= 4 && label.includes(name));
}

// Idée reprise de l'extension Authenticator : le titre de l'onglet cite souvent le service
// (« Connexion · Dashlane ») même quand le domaine ne lui ressemble pas.
export function issuerMatchesTitle(issuer, title) {
  const name = squash(issuer);
  return name.length >= 4 && squash(title).includes(name);
}

// Trie les comptes pour le site courant.
// learned  : codes déjà copiés sur ce site (appris automatiquement), du plus utilisé au moins utilisé
// guessed  : jamais utilisés ici, mais le nom de l'émetteur ressemble au domaine ou au titre de l'onglet
export function rankForSite(accounts, site, title = '') {
  const learned = [];
  const guessed = [];
  const others = [];
  for (const acc of accounts) {
    if (site && acc.domains?.includes(site)) learned.push(acc);
    else if (site && (issuerMatchesSite(acc.issuer, site) || issuerMatchesTitle(acc.issuer, title))) guessed.push(acc);
    else others.push(acc);
  }
  learned.sort((a, b) => (b.uses?.[site] ?? 0) - (a.uses?.[site] ?? 0));
  return { learned, guessed, others };
}

export function recordUse(account, site, now = Date.now()) {
  if (!site) return account;
  const domains = account.domains?.includes(site) ? account.domains : [...(account.domains ?? []), site];
  const uses = { ...(account.uses ?? {}), [site]: (account.uses?.[site] ?? 0) + 1 };
  return { ...account, domains, uses, lastUsedAt: now };
}

export function matchesQuery(account, query) {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [account.issuer, account.account, ...(account.domains ?? [])].some((v) => String(v ?? '').toLowerCase().includes(q));
}
