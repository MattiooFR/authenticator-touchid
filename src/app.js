import { hotp, secondsLeft, totp, totpCounter } from './lib/totp.js';
import { matchesQuery, rankForSite, recordUse, siteFromUrl } from './lib/domains.js';
import {
  isEncryptedAuthenticatorCc, makeAccount, mergeAccounts, parseAuthenticatorCcEncrypted, parseImport, toOtpauth,
} from './lib/importers.js';
import { INSTALL_COMMAND, askBackground } from './lib/touchid.js';
import { LEVELS, MIN_LEVEL, ATTACK_GPUS, estimateStrength, formatDuration, strengthHint } from './lib/strength.js';
import * as backup from './lib/backup.js';
import { fillActiveTab } from './lib/autofill.js';
import * as vault from './lib/vault.js';

const params = new URLSearchParams(location.search);
const isTab = params.has('tab');
const isPopup = !isTab;
document.body.classList.toggle('tab', isTab);
chrome.runtime.connect({ name: 'app' }); // permet le verrouillage « dès la fermeture de la fenêtre »

const root = document.getElementById('app');
const state = {
  view: 'loading',
  accounts: [],
  site: null,
  title: '',
  tabId: null,
  query: '',
  showAll: false,
  editId: null,
  settings: vault.DEFAULT_SETTINGS,
  hasBio: false,
  bioAvailable: false,
  bioInstalled: false,
  backupProblems: [],
  pendingAssoc: null,
};

// ---------- utilitaires DOM ----------

const ICONS = {
  gear: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  scan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2M7 12h10"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>',
  back: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg>',
  dots: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>',
  sort: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 4v16M3 8l4-4 4 4M17 20V4M13 16l4 4 4-4"/></svg>',
  grip: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.6"/><circle cx="15" cy="6" r="1.6"/><circle cx="9" cy="12" r="1.6"/><circle cx="15" cy="12" r="1.6"/><circle cx="9" cy="18" r="1.6"/><circle cx="15" cy="18" r="1.6"/></svg>',
  expand: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>',
};

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'class') el.className = v;
    else if (k === 'icon') el.innerHTML = ICONS[v]; // SVG statiques uniquement
    else if (k in el && k !== 'list') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const iconBtn = (icon, title, onclick) => h('button', { class: 'icon-btn', icon, title, 'aria-label': title, onclick });

function header(title, { back = false, actions = [] } = {}) {
  return h('header', {},
    back ? iconBtn('back', 'Retour', () => go('list')) : null,
    h('h1', {}, title),
    ...actions,
  );
}

let toastTimer;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
}

function go(view, extra = {}) {
  Object.assign(state, { view }, extra);
  render();
}

function openInTab(hash = '') {
  chrome.tabs.create({ url: chrome.runtime.getURL(`app.html?tab=1${hash}`) });
  if (!isTab) window.close();
}

function download(filename, text, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  h('a', { href: url, download: filename }).click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const formatCode = (code) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code);
const today = () => new Date().toISOString().slice(0, 10);

// ---------- données ----------

async function persist() {
  await vault.saveAccounts(state.accounts);
}

async function refreshMeta() {
  const v = await vault.getVault();
  state.hasBio = vault.hasTouchId(v);
  state.settings = await vault.getSettings();
}

async function detectSite() {
  if (isTab) return { site: null, title: '', tabId: null };
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return { site: tab?.url ? siteFromUrl(tab.url) : null, title: tab?.title ?? '', tabId: tab?.id ?? null };
  } catch {
    return { site: null, title: '', tabId: null };
  }
}

// Jauge de force sous un champ mot de passe. Renvoie { el, ok() }.
function strengthMeter(input) {
  const bar = h('div', { class: 'meter' }, ...Array.from({ length: 5 }, () => h('span')));
  const label = h('div', { class: 'meter-label' });
  const hint = h('div', { class: 'notice' });
  let current = { level: 0 };
  const update = () => {
    const pw = input.value;
    current = estimateStrength(pw);
    const { label: name, color } = LEVELS[current.level];
    [...bar.children].forEach((seg, i) => (seg.style.background = pw && i <= current.level ? color : ''));
    label.replaceChildren(...(pw
      ? [h('strong', { style: `color:${color}` }, name), ` · craqué en ${formatDuration(current.seconds)}`]
      : ['']));
    hint.textContent = pw ? strengthHint(pw, current) : '';
  };
  input.addEventListener('input', update);
  update();
  return {
    el: h('div', { class: 'strength' }, bar, label, hint,
      h('div', { class: 'notice', title: 'Hypothèse : une sauvegarde chiffrée a fuité et l’attaquant teste des mots de passe hors ligne.' },
        `Estimation pour ${ATTACK_GPUS} cartes graphiques qui attaquent une sauvegarde volée.`)),
    ok: () => current.level >= MIN_LEVEL,
  };
}

// Rattrape une sauvegarde que le service worker n'a pas pu écrire (dossier), puis affiche les alertes.
function checkBackups() {
  backup.runBackups().then(async () => {
    const problems = await backup.backupProblems();
    const changed = JSON.stringify(problems) !== JSON.stringify(state.backupProblems);
    state.backupProblems = problems;
    if (changed && state.view === 'list' && !state.query) render();
  }).catch(() => {});
}

async function afterUnlock() {
  checkBackups();
  state.accounts = await vault.loadAccounts();
  const target = location.hash.slice(1);
  go(['import', 'settings'].includes(target) ? target : 'list');
}

// ---------- vues ----------

function viewSetup() {
  const pw = h('input', { type: 'password', placeholder: 'Mot de passe', autocomplete: 'new-password', autofocus: true });
  const meter = strengthMeter(pw);
  const pw2 = h('input', { type: 'password', placeholder: 'Confirmer', autocomplete: 'new-password' });
  const err = h('div', { class: 'error' });
  const submit = async (e) => {
    e.preventDefault();
    if (!meter.ok()) return (err.textContent = 'Mot de passe trop facile à craquer : il protège aussi tes sauvegardes.');
    if (pw.value !== pw2.value) return (err.textContent = 'Les deux mots de passe ne correspondent pas.');
    err.textContent = 'Chiffrement…';
    await vault.createVault(pw.value);
    await refreshMeta();
    state.accounts = [];
    go('welcome');
  };
  return [
    h('div', { class: 'hero' },
      h('div', { class: 'logo' }, '🔐'),
      h('h2', {}, 'Créer ton coffre'),
      h('p', {}, 'Le mot de passe sert de secours et chiffre tes sauvegardes. Au quotidien, tu ouvriras avec Touch ID.'),
    ),
    h('form', { class: 'content stack', onsubmit: submit }, pw, meter.el, pw2, h('button', { class: 'btn primary block big' }, 'Créer le coffre'), err),
    restoreSection(),
  ];
}

// Nouvel appareil : propose les sauvegardes trouvées dans le compte Google.
function restoreSection() {
  const wrap = h('div', { class: 'content' });
  backup.listSyncBackups().then((found) => {
    if (!found.length) return;
    const choice = h('select', {}, ...found.map((b, i) => h('option', { value: i },
      `${b.device} · ${new Date(b.createdAt).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })}`)));
    const pw = h('input', { type: 'password', placeholder: 'Mot de passe de la sauvegarde', autocomplete: 'current-password' });
    const err = h('div', { class: 'error' });
    const restore = async (password) => {
      err.textContent = 'Déchiffrement…';
      try {
        await vault.adoptBackup(found[Number(choice.value)].record, password);
        await refreshMeta();
        toast('Sauvegarde restaurée');
        await afterUnlock();
      } catch (e) {
        err.textContent = e.message;
      }
    };
    wrap.append(h('div', { class: 'section stack' },
      h('h3', {}, 'Ou restaurer ta sauvegarde'),
      h('p', {}, 'Une sauvegarde chiffrée existe dans ton compte Google. Touch ID se réactive ensuite dans les réglages.'),
      choice,
      h('form', { class: 'stack', onsubmit: (e) => { e.preventDefault(); restore(pw.value); } },
        pw, h('button', { class: 'btn block' }, 'Restaurer avec le mot de passe')),
      err,
    ));
  }).catch(() => {});
  return wrap;
}

function viewWelcome() {
  const err = h('div', { class: 'error' });
  return [
    h('div', { class: 'hero' },
      h('div', { class: 'logo' }, '✅'),
      h('h2', {}, 'Coffre créé'),
      h('p', {}, 'Deux étapes pour finir.'),
    ),
    h('div', { class: 'content stack' },
      state.hasBio
        ? h('div', { class: 'notice' }, '✓ Touch ID activé')
        : state.bioAvailable
          ? h('button', { class: 'btn primary block big', onclick: () => startEnroll(err, () => go('welcome')) }, '1. Activer Touch ID')
          : state.bioInstalled ? h('div', { class: 'notice' }, 'Touch ID indisponible pour l’instant.') : touchIdInstallHelp(),
      h('button', { class: 'btn block big', onclick: () => go('import') }, '2. Importer mes comptes'),
      h('button', { class: 'link', onclick: () => go('list') }, 'Plus tard'),
      err,
    ),
  ];
}

// Le dialogue Touch ID ferme la popup : c'est le service worker qui attend l'empreinte.
async function startEnroll(errEl, done) {
  errEl.textContent = 'Pose ton doigt sur Touch ID…';
  const res = await askBackground('touchid-enroll');
  if (!res?.ok) {
    errEl.textContent = res?.code === 'cancel' ? '' : (res?.error ?? 'Échec');
    return;
  }
  await refreshMeta();
  errEl.textContent = '';
  toast('Touch ID activé');
  done();
}

// Tant que l'app Touch ID n'est pas installée, on dit comment faire.
function touchIdInstallHelp() {
  return h('div', { class: 'stack' },
    h('p', {}, 'Chrome ne donne pas accès à Touch ID aux extensions. Une petite app Mac s’en charge (comme pour Bitwarden ou 1Password). Installe-la une fois, dans le Terminal :'),
    h('code', { class: 'cmd' }, INSTALL_COMMAND),
    h('button', { class: 'btn block', onclick: () => navigator.clipboard.writeText(INSTALL_COMMAND).then(() => toast('Commande copiée')) }, 'Copier la commande'),
    h('p', {}, 'Puis rouvre cette fenêtre.'),
  );
}

let autoBioDone = false; // une seule demande automatique par ouverture
function viewLocked() {
  const pw = h('input', { type: 'password', placeholder: 'Mot de passe', autocomplete: 'current-password' });
  const err = h('div', { class: 'error' });
  const tryBio = async () => {
    err.textContent = 'Pose ton doigt sur Touch ID…';
    const res = await askBackground('touchid-unlock');
    if (res?.ok) return afterUnlock();
    err.textContent = res?.code === 'cancel' ? '' : (res?.error ?? 'Échec');
    pw.focus();
  };
  const submit = async (e) => {
    e.preventDefault();
    if (!pw.value) return;
    err.textContent = 'Déchiffrement…';
    try {
      await vault.unlockWithPassword(pw.value);
      await afterUnlock();
    } catch (e2) {
      err.textContent = e2.message;
      pw.select();
    }
  };
  // Touch ID se lance tout seul à l'ouverture : un clic sur l'icône + l'empreinte, c'est tout.
  queueMicrotask(() => {
    pw.focus();
    if (state.hasBio && state.bioAvailable && !autoBioDone) {
      autoBioDone = true;
      tryBio();
    }
  });

  return [
    h('div', { class: 'hero' },
      h('div', { class: 'logo' }, '🔒'),
      h('h2', {}, 'Coffre verrouillé'),
      state.site ? h('p', {}, `Sur ${state.site}`) : h('p', {}, ' '),
    ),
    h('div', { class: 'content stack' },
      state.hasBio ? h('button', { class: 'btn primary block big', onclick: tryBio }, '👆 Déverrouiller avec Touch ID') : null,
      h('form', { class: 'stack', onsubmit: submit },
        pw,
        h('button', { class: state.hasBio ? 'btn block' : 'btn primary block big' }, 'Déverrouiller avec le mot de passe'),
      ),
      err,
    ),
  ];
}

// Rafraîchissement des codes sans reconstruire la liste.
let cards = [];
let tickTimer;

async function updateCodes() {
  const now = Date.now();
  for (const c of cards) {
    const a = c.acc;
    if (a.type === 'hotp') continue;
    const left = secondsLeft(a.period, now);
    c.el.style.setProperty('--p', String(left / a.period));
    c.el.classList.toggle('expiring', left <= 5);
    const counter = totpCounter(a.period, now);
    if (c.counter !== counter) {
      c.counter = counter;
      c.code.textContent = formatCode(await totp(a.secret, { ...a, now }));
    }
    if (left <= 5) {
      const next = await totp(a.secret, { ...a, now: now + left * 1000 });
      c.next.textContent = `suivant : ${formatCode(next)}`;
    } else c.next.textContent = '';
  }
}

async function copyAccount({ id }) {
  const acc = state.accounts.find((a) => a.id === id);
  if (!acc) return;
  let code;
  try {
    code = acc.type === 'hotp' ? await hotp(acc.secret, acc.counter, acc) : await totp(acc.secret, acc);
    await navigator.clipboard.writeText(code);
  } catch (err) {
    toast(`Copie impossible : ${err.message}`);
    return;
  }
  const smart = state.settings.smartFilter;
  const associated = Boolean(state.site && acc.domains?.includes(state.site));
  // Un site jamais associé à ce compte : on demande au lieu d'associer en silence.
  // La question ne vit qu'en mémoire : fermer la fenêtre revient à répondre non.
  const ask = smart && state.site && !associated;
  const bumped = acc.type === 'hotp' ? { ...acc, counter: acc.counter + 1 } : acc;
  const updated = smart && associated ? recordUse(bumped, state.site) : bumped;
  const filled = state.settings.autofill && state.site ? await fillActiveTab(code, state.tabId) : false;
  state.accounts = state.accounts.map((a) => (a.id === id ? updated : a));
  state.pendingAssoc = ask ? { id, site: state.site } : null;
  await persist();
  await vault.touch();
  toast(filled ? 'Copié et rempli' : 'Copié');
  if (!ask && !isTab && state.settings.closeAfterCopy) setTimeout(() => window.close(), 450);
  else if (ask || acc.type === 'hotp') render();
}

async function answerAssoc(yes) {
  const pending = state.pendingAssoc;
  state.pendingAssoc = null;
  if (yes && pending) {
    state.accounts = state.accounts.map((a) => (a.id === pending.id ? recordUse(a, pending.site) : a));
    await persist();
    toast(`Associé à ${pending.site}`);
  }
  if (yes && !isTab && state.settings.closeAfterCopy) setTimeout(() => window.close(), 450);
  render();
}

const compareByName = (a, b) =>
  (a.issuer || a.account).localeCompare(b.issuer || b.account, 'fr', { sensitivity: 'base' });

function visibleAccounts() {
  const site = state.settings.smartFilter ? state.site : null;
  const { learned, guessed, others } = rankForSite(state.accounts, site, state.title);
  // Ordre choisi par l'utilisateur (vue « Réorganiser »), sinon alphabétique
  const byName = state.settings.customOrder ? () => 0 : compareByName;
  const tag = (list, kind) => list.map((acc) => ({ acc, kind }));
  if (state.query) {
    return { items: [...tag(learned, 'learned'), ...tag(guessed, 'guessed'), ...tag(others.sort(byName), null)].filter((x) => matchesQuery(x.acc, state.query)), filtered: false };
  }
  const matching = [...tag(learned, 'learned'), ...tag(guessed, 'guessed')];
  if (site && matching.length && !state.showAll) {
    return { items: matching, filtered: true, hidden: others.length };
  }
  return { items: [...matching, ...tag(others.sort(byName), null)], filtered: false };
}

function card({ acc, kind }, index) {
  const code = h('div', { class: 'code' }, acc.type === 'hotp' ? '••• •••' : '');
  const next = h('div', { class: 'next' });
  const el = h('div', {
    class: `card${index === 0 && (state.query || state.site) ? ' first' : ''}`,
    tabindex: 0,
    title: 'Cliquer pour copier',
    onclick: () => copyAccount(acc),
    onkeydown: (e) => e.key === 'Enter' && copyAccount(acc),
  },
    h('div', { class: 'who' },
      h('span', { class: 'issuer' }, acc.issuer || acc.account || 'Sans nom'),
      kind === 'guessed' ? h('span', { class: 'badge', title: 'Le nom ressemble au site. Copie le code pour confirmer.' }, 'suggéré') : null,
      acc.issuer && acc.account ? h('div', { class: 'account' }, acc.account) : null,
    ),
    code,
    next,
    h('div', { class: 'side' },
      acc.type === 'hotp' ? h('span', { class: 'notice' }, `#${acc.counter}`) : h('div', { class: 'ring' }),
      h('button', {
        class: 'icon-btn',
        icon: 'dots',
        title: 'Modifier',
        onclick: (e) => {
          e.stopPropagation();
          go('edit', { editId: acc.id });
        },
      }),
    ),
  );
  cards.push({ acc, el, code, next, counter: null });
  return el;
}

function viewList() {
  cards = [];
  const search = h('input', {
    class: 'search',
    type: 'search',
    placeholder: 'Rechercher',
    value: state.query,
    autofocus: true,
    oninput: (e) => {
      state.query = e.target.value;
      renderList();
    },
    onkeydown: (e) => {
      if (e.key === 'Enter' && cards[0]) copyAccount(cards[0].acc);
      if (e.key === 'Escape' && state.query) {
        e.preventDefault();
        state.query = '';
        search.value = '';
        renderList();
      }
    },
  });
  const listWrap = h('div');

  function renderList() {
    cards = [];
    const { items, filtered, hidden } = visibleAccounts();
    const bar = state.site && state.settings.smartFilter && !state.query
      ? h('div', { class: 'site-bar' },
          h('span', {}, 'Sur ', h('strong', {}, state.site)),
          filtered
            ? h('button', { class: 'link', onclick: () => { state.showAll = true; renderList(); } }, `Tous les comptes (${items.length + hidden})`)
            : state.showAll
              ? h('button', { class: 'link', onclick: () => { state.showAll = false; renderList(); } }, 'Seulement ce site')
              : h('span', {}, 'aucun compte associé'),
        )
      : null;
    let body;
    if (!state.accounts.length) {
      body = h('div', { class: 'empty' },
        'Aucun compte pour l’instant.',
        h('div', {}, h('button', { class: 'btn primary', onclick: () => go('import') }, 'Importer mes comptes')),
      );
    } else if (!items.length) {
      body = h('div', { class: 'empty' }, `Rien ne correspond à « ${state.query} ».`);
    } else {
      body = h('div', { class: 'list' }, items.map(card));
    }
    const problem = state.backupProblems[0];
    const warn = problem
      ? h('button', { class: 'banner', onclick: () => go('settings') },
          `⚠ Sauvegarde ${problem.target === 'sync' ? 'Google' : 'dossier'} : ${problem.error}`)
      : null;
    const pendingAcc = state.pendingAssoc && state.accounts.find((a) => a.id === state.pendingAssoc.id);
    const ask = pendingAcc
      ? h('div', { class: 'ask' },
          h('p', {}, 'Associer ', h('strong', {}, pendingAcc.issuer || pendingAcc.account || 'ce compte'), ' à ', h('strong', {}, state.pendingAssoc.site), ' ?'),
          h('div', { class: 'row' },
            h('button', { class: 'btn', onclick: () => answerAssoc(false) }, 'Non'),
            h('button', { class: 'btn primary', onclick: () => answerAssoc(true) }, 'Oui, associer'),
          ),
        )
      : null;
    listWrap.replaceChildren(...[warn, ask, bar, body].filter(Boolean));
    updateCodes();
  }

  clearInterval(tickTimer);
  tickTimer = setInterval(updateCodes, 500);
  renderList();
  return [
    header('Authenticator', {
      actions: [
        iconBtn('scan', 'Scanner le QR code de la page', scanPage),
        iconBtn('plus', 'Ajouter un compte', () => go('add')),
        state.accounts.length > 1 ? iconBtn('sort', 'Réorganiser', () => go('reorder')) : null,
        isTab ? null : iconBtn('expand', 'Ouvrir dans un onglet', () => openInTab()),
        iconBtn('gear', 'Réglages', () => go('settings')),
        iconBtn('lock', 'Verrouiller', async () => {
          await vault.lock();
          go('locked');
        }),
      ],
    }),
    h('div', { class: 'content' }, search, listWrap),
  ];
}

// Réorganiser : glisser-déposer (poignée) ou flèches ↑ ↓, enregistré à chaque changement.
function viewReorder() {
  const list = h('div', { class: 'reorder' });
  let dragId = null;

  const save = async (accounts) => {
    state.accounts = accounts;
    await persist();
    if (!state.settings.customOrder) {
      await vault.saveSettings({ customOrder: true });
      state.settings = await vault.getSettings();
    }
    draw();
  };
  const move = (from, to) => {
    if (to < 0 || to >= state.accounts.length || from === to) return;
    const next = [...state.accounts];
    const [acc] = next.splice(from, 1);
    next.splice(to, 0, acc);
    save(next).then(() => list.querySelector(`[data-id="${acc.id}"] .handle`)?.focus());
  };

  function draw() {
    // Premier passage : on part de l'ordre affiché (alphabétique si jamais réorganisé)
    const ordered = state.settings.customOrder ? state.accounts : [...state.accounts].sort(compareByName);
    if (!state.settings.customOrder) state.accounts = ordered;
    list.replaceChildren(...ordered.map((acc, i) => {
      const row = h('div', {
        class: 'reorder-row',
        draggable: true,
        'data-id': acc.id,
        ondragstart: (e) => {
          dragId = acc.id;
          e.dataTransfer.effectAllowed = 'move';
          row.classList.add('dragging');
        },
        ondragend: () => {
          dragId = null;
          row.classList.remove('dragging');
          list.querySelectorAll('.over-top, .over-bottom').forEach((el) => el.classList.remove('over-top', 'over-bottom'));
        },
        ondragover: (e) => {
          if (!dragId || dragId === acc.id) return;
          e.preventDefault();
          const below = e.offsetY > row.offsetHeight / 2;
          row.classList.toggle('over-bottom', below);
          row.classList.toggle('over-top', !below);
        },
        ondragleave: () => row.classList.remove('over-top', 'over-bottom'),
        ondrop: (e) => {
          e.preventDefault();
          const from = state.accounts.findIndex((a) => a.id === dragId);
          let to = i + (row.classList.contains('over-bottom') ? 1 : 0);
          if (from < to) to -= 1;
          move(from, to);
        },
      },
        h('button', {
          class: 'handle',
          icon: 'grip',
          title: 'Glisser, ou flèches ↑ ↓ du clavier',
          'aria-label': `Déplacer ${acc.issuer || acc.account}`,
          onkeydown: (e) => {
            if (e.key === 'ArrowUp') { e.preventDefault(); move(i, e.altKey ? 0 : i - 1); }
            if (e.key === 'ArrowDown') { e.preventDefault(); move(i, e.altKey ? state.accounts.length - 1 : i + 1); }
          },
        }),
        h('div', { class: 'who' },
          h('span', { class: 'issuer' }, acc.issuer || acc.account || 'Sans nom'),
          acc.issuer && acc.account ? h('div', { class: 'account' }, acc.account) : null,
        ),
        h('button', { class: 'icon-btn small', title: 'Tout en haut', disabled: i === 0, onclick: () => move(i, 0) }, '⤒'),
        h('button', { class: 'icon-btn small', title: 'Monter', disabled: i === 0, onclick: () => move(i, i - 1) }, '↑'),
        h('button', { class: 'icon-btn small', title: 'Descendre', disabled: i === ordered.length - 1, onclick: () => move(i, i + 1) }, '↓'),
      );
      return row;
    }));
  }
  draw();

  return [
    header('Réorganiser', { back: true }),
    h('div', { class: 'content' },
      h('p', { class: 'notice' }, 'Glisse un compte par sa poignée, ou utilise les flèches. Sur un site, les comptes associés restent en tête.'),
      h('div', { class: 'row-actions' },
        h('button', { class: 'btn', onclick: () => save([...state.accounts].sort(compareByName)) }, 'Trier de A à Z'),
      ),
      list,
    ),
  ];
}

async function addAccounts(incoming, { site } = {}) {
  const withSite = site ? incoming.map((a) => ({ ...a, domains: [...new Set([...(a.domains ?? []), site])] })) : incoming;
  const { merged, added } = mergeAccounts(state.accounts, withSite);
  state.accounts = merged;
  await persist();
  return added;
}

async function scanPage() {
  try {
    if (!('BarcodeDetector' in window)) throw new Error('Lecture de QR code non disponible dans ce Chrome');
    const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' });
    const bitmap = await createImageBitmap(await (await fetch(dataUrl)).blob());
    const found = await new BarcodeDetector({ formats: ['qr_code'] }).detect(bitmap);
    const texts = found.map((f) => f.rawValue).filter((t) => /^otpauth(-migration)?:\/\//i.test(t));
    if (!texts.length) throw new Error('Aucun QR code 2FA visible sur la page');
    const { accounts } = parseImport(texts.join('\n'));
    const added = await addAccounts(accounts, { site: state.site });
    toast(added.length ? `${added.length} compte(s) ajouté(s)` : 'Ce compte existe déjà');
    render();
  } catch (err) {
    toast(err.message);
  }
}

function viewAdd() {
  const uri = h('input', { placeholder: 'otpauth://totp/…', autofocus: true });
  const issuer = h('input', { placeholder: 'Ex. Supabase' });
  const account = h('input', { placeholder: 'Ex. moi@exemple.com' });
  const secret = h('input', { placeholder: 'JBSW Y3DP EHPK 3PXP', autocomplete: 'off', spellcheck: false });
  const algorithm = h('select', {}, ...['SHA1', 'SHA256', 'SHA512'].map((v) => h('option', { value: v }, v)));
  const digits = h('select', {}, ...[6, 7, 8].map((v) => h('option', { value: v }, `${v} chiffres`)));
  const period = h('input', { type: 'number', value: 30, min: 1, max: 300 });
  const type = h('select', {}, h('option', { value: 'totp' }, 'TOTP (temps)'), h('option', { value: 'hotp' }, 'HOTP (compteur)'));
  const link = h('input', { type: 'checkbox', checked: Boolean(state.site) });
  const err = h('div', { class: 'error' });

  const submit = async (e) => {
    e.preventDefault();
    try {
      let accounts;
      if (uri.value.trim()) {
        const parsed = parseImport(uri.value);
        if (!parsed.accounts.length) throw new Error(parsed.skipped[0] ?? 'Lien invalide');
        accounts = parsed.accounts;
      } else {
        if (!secret.value.trim()) throw new Error('Colle un lien otpauth:// ou renseigne le secret');
        accounts = [makeAccount({
          issuer: issuer.value, account: account.value, secret: secret.value,
          algorithm: algorithm.value, digits: digits.value, period: period.value, type: type.value,
        })];
      }
      const added = await addAccounts(accounts, { site: link.checked ? state.site : null });
      toast(added.length ? 'Compte ajouté' : 'Ce compte existe déjà');
      go('list');
    } catch (e2) {
      err.textContent = e2.message;
    }
  };

  return [
    header('Ajouter un compte', { back: true }),
    h('form', { class: 'content', onsubmit: submit },
      h('div', { class: 'section' },
        h('h3', {}, 'Le plus simple'),
        h('p', {}, 'Affiche le QR code sur le site puis clique sur l’icône scanner en haut de la liste. Ou colle le lien otpauth ici :'),
        uri,
      ),
      h('div', { class: 'section' },
        h('h3', {}, 'À la main'),
        h('label', {}, 'Service'), issuer,
        h('label', {}, 'Compte'), account,
        h('label', {}, 'Clé secrète'), secret,
        h('details', {},
          h('summary', {}, 'Options avancées'),
          h('label', {}, 'Type'), type,
          h('div', { class: 'row' },
            h('div', {}, h('label', {}, 'Algorithme'), algorithm),
            h('div', {}, h('label', {}, 'Chiffres'), digits),
            h('div', {}, h('label', {}, 'Période (s)'), period),
          ),
        ),
      ),
      state.site ? h('label', { class: 'check' }, link, `Associer à ${state.site}`) : null,
      h('button', { class: 'btn primary block big', style: 'margin-top:12px' }, 'Ajouter'),
      err,
    ),
  ];
}

function normalizeDomainInput(value) {
  const v = value.trim();
  if (!v) return null;
  return siteFromUrl(/^https?:\/\//i.test(v) ? v : `https://${v}`);
}

function viewEdit() {
  const acc = state.accounts.find((a) => a.id === state.editId);
  if (!acc) return viewList();
  const draft = { ...acc, domains: [...(acc.domains ?? [])] };
  const issuer = h('input', { value: acc.issuer });
  const account = h('input', { value: acc.account });
  const chips = h('div', { class: 'chips' });
  const newDomain = h('input', { placeholder: 'exemple.com' });
  const err = h('div', { class: 'error' });

  const drawChips = () => {
    chips.replaceChildren(...(draft.domains.length
      ? draft.domains.map((d) => h('span', { class: 'chip' }, d, h('button', {
          type: 'button',
          title: `Retirer ${d}`,
          onclick: () => {
            draft.domains = draft.domains.filter((x) => x !== d);
            drawChips();
          },
        }, '×')))
      : [h('span', { class: 'notice' }, 'Aucun. Il s’ajoute tout seul quand tu copies le code sur un site.')]));
  };
  drawChips();

  const addDomain = () => {
    const d = normalizeDomainInput(newDomain.value);
    if (!d) return (err.textContent = 'Domaine invalide');
    err.textContent = '';
    if (!draft.domains.includes(d)) draft.domains.push(d);
    newDomain.value = '';
    drawChips();
  };
  newDomain.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addDomain();
    }
  });

  const save = async (e) => {
    e.preventDefault();
    const uses = Object.fromEntries(Object.entries(draft.uses ?? {}).filter(([d]) => draft.domains.includes(d)));
    state.accounts = state.accounts.map((a) => (a.id === acc.id ? { ...draft, issuer: issuer.value.trim(), account: account.value.trim(), uses } : a));
    await persist();
    toast('Enregistré');
    go('list');
  };

  let armed = false;
  const del = h('button', {
    type: 'button',
    class: 'btn danger block',
    onclick: async () => {
      if (!armed) {
        armed = true;
        del.classList.add('armed');
        del.textContent = 'Confirmer : supprimer définitivement';
        return;
      }
      state.accounts = state.accounts.filter((a) => a.id !== acc.id);
      await persist();
      toast('Compte supprimé');
      go('list');
    },
  }, 'Supprimer ce compte');

  return [
    header('Modifier', { back: true }),
    h('form', { class: 'content', onsubmit: save },
      h('div', { class: 'section' },
        h('label', {}, 'Service'), issuer,
        h('label', {}, 'Compte'), account,
      ),
      h('div', { class: 'section' },
        h('h3', {}, 'Sites associés'),
        h('p', {}, 'Le compte apparaît en premier, et seul, quand tu es sur ces sites.'),
        chips,
        h('div', { class: 'row' }, newDomain, h('button', { type: 'button', class: 'btn', style: 'flex:0', onclick: addDomain }, 'Ajouter')),
      ),
      h('button', { class: 'btn primary block big' }, 'Enregistrer'),
      err,
      h('div', { style: 'margin-top:14px' }, del),
    ),
  ];
}

function viewImport() {
  const text = h('textarea', { placeholder: 'Colle ici :\n• des liens otpauth:// (un par ligne)\n• un lien otpauth-migration:// (Google Authenticator)\n• le JSON de sauvegarde de l’extension Authenticator' });
  const file = h('input', { type: 'file', accept: '.json,.txt,application/json,text/plain' });
  const err = h('div', { class: 'error' });
  const backupFile = h('input', { type: 'file', accept: '.json,application/json' });
  const backupPw = h('input', { type: 'password', placeholder: 'Mot de passe de la sauvegarde' });
  // Export Authenticator « avec mot de passe » : le champ apparaît quand on en détecte un.
  const importPw = h('input', { type: 'password', placeholder: 'Mot de passe de l’export Authenticator', style: 'display:none;margin-top:8px' });
  const syncPw = () => (importPw.style.display = isEncryptedAuthenticatorCc(text.value) ? '' : 'none');
  text.addEventListener('input', syncPw);

  file.addEventListener('change', async () => {
    if (file.files[0]) text.value = await file.files[0].text();
    syncPw();
    if (importPw.style.display === '') importPw.focus();
  });

  const doImport = async () => {
    err.textContent = '';
    try {
      let result;
      if (isEncryptedAuthenticatorCc(text.value)) {
        if (!importPw.value) throw new Error('Cet export est protégé : entre son mot de passe.');
        err.textContent = 'Déchiffrement…';
        result = await parseAuthenticatorCcEncrypted(text.value, importPw.value);
      } else {
        result = parseImport(text.value);
      }
      const { accounts, skipped } = result;
      const added = await addAccounts(accounts);
      const dup = accounts.length - added.length;
      err.textContent = [
        `${added.length} compte(s) importé(s)${dup ? `, ${dup} déjà présent(s)` : ''}.`,
        ...skipped,
      ].join('\n');
      err.style.whiteSpace = 'pre-line';
      err.style.color = added.length ? 'var(--ok)' : '';
      if (added.length) {
        text.value = '';
        importPw.value = '';
        syncPw();
      }
    } catch (e) {
      err.textContent = e.message;
    }
  };

  const doRestore = async () => {
    err.textContent = '';
    try {
      if (!backupFile.files[0]) throw new Error('Choisis le fichier de sauvegarde');
      const backup = JSON.parse(await backupFile.files[0].text());
      const accounts = await vault.readBackup(backup, backupPw.value);
      const added = await addAccounts(accounts);
      err.style.color = 'var(--ok)';
      err.textContent = `${added.length} compte(s) restauré(s), ${accounts.length - added.length} déjà présent(s).`;
    } catch (e) {
      err.style.color = '';
      err.textContent = e.message;
    }
  };

  return [
    header('Importer', { back: true }),
    h('div', { class: 'content' },
      h('div', { class: 'section' },
        h('h3', {}, 'Depuis ton ancienne extension'),
        h('p', {}, 'Dans Authenticator : engrenage → Sauvegarde → télécharge le fichier (avec ou sans mot de passe, et aussi le .txt). Puis choisis ce fichier ou colle son contenu.'),
        isTab ? file : h('button', { class: 'link', onclick: () => openInTab('#import') }, 'Choisir un fichier (ouvre un onglet)'),
        h('div', { style: 'height:8px' }),
        text,
        importPw,
        h('button', { class: 'btn primary block', style: 'margin-top:8px', onclick: doImport }, 'Importer'),
      ),
      isTab
        ? h('div', { class: 'section' },
            h('h3', {}, 'Restaurer une sauvegarde chiffrée de ce coffre'),
            backupFile,
            h('div', { style: 'height:8px' }),
            backupPw,
            h('button', { class: 'btn block', style: 'margin-top:8px', onclick: doRestore }, 'Restaurer'),
          )
        : null,
      err,
    ),
  ];
}

function viewSettings() {
  const err = h('div', { class: 'error' });
  const s = state.settings;

  const autoLock = h('select', {
    onchange: async (e) => {
      await vault.saveSettings({ autoLockMinutes: Number(e.target.value) });
      await refreshMeta();
      toast('Enregistré');
    },
  }, ...[[-1, 'Dès que je ferme la fenêtre'], [1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [30, '30 minutes'],
    [60, '1 heure'], [240, '4 heures'], [0, 'À la fermeture de Chrome']]
    .map(([v, l]) => h('option', { value: v, selected: s.autoLockMinutes === v }, l)));

  const toggle = (key, labelText, def) => h('label', { class: 'check' },
    h('input', {
      type: 'checkbox',
      checked: s[key] ?? def,
      onchange: async (e) => {
        await vault.saveSettings({ [key]: e.target.checked });
        await refreshMeta();
      },
    }),
    labelText,
  );

  const cur = h('input', { type: 'password', placeholder: 'Mot de passe actuel', autocomplete: 'current-password' });
  const next = h('input', { type: 'password', placeholder: 'Nouveau mot de passe', autocomplete: 'new-password' });
  const nextMeter = strengthMeter(next);
  const next2 = h('input', { type: 'password', placeholder: 'Confirmer', autocomplete: 'new-password' });
  const changePw = async () => {
    err.textContent = '';
    if (!nextMeter.ok()) return (err.textContent = 'Nouveau mot de passe trop facile à craquer.');
    if (next.value !== next2.value) return (err.textContent = 'Les deux mots de passe ne correspondent pas.');
    try {
      await vault.changePassword(cur.value, next.value);
      cur.value = next.value = next2.value = '';
      toast('Mot de passe changé');
    } catch (e) {
      err.textContent = e.message;
    }
  };

  let plainArmed = false;
  const plainBtn = h('button', {
    class: 'btn danger block',
    onclick: () => {
      if (!plainArmed) {
        plainArmed = true;
        plainBtn.classList.add('armed');
        plainBtn.textContent = 'Confirmer : fichier lisible par n’importe qui';
        return;
      }
      download(`authenticator-EN-CLAIR-${today()}.txt`, state.accounts.map(toOtpauth).join('\n') + '\n', 'text/plain');
    },
  }, 'Exporter en clair (liens otpauth)');

  return [
    header('Réglages', { back: true }),
    h('div', { class: 'content' },
      h('div', { class: 'section' },
        h('h3', {}, 'Touch ID'),
        state.hasBio
          ? [
              h('p', {}, '✓ Activé. Le coffre s’ouvre avec ton empreinte ; le mot de passe reste le secours.'),
              h('button', {
                class: 'btn block',
                onclick: async () => {
                  await vault.disableTouchId();
                  await refreshMeta();
                  toast('Touch ID désactivé');
                  render();
                },
              }, 'Désactiver Touch ID'),
            ]
          : state.bioAvailable
            ? [
                h('p', {}, 'Ouvre le coffre avec ton empreinte au lieu du mot de passe.'),
                h('button', { class: 'btn primary block', onclick: () => startEnroll(err, render) }, 'Activer Touch ID'),
              ]
            : state.bioInstalled
              ? h('p', {}, 'Touch ID n’est pas disponible pour l’instant (Mac fermé, clavier sans capteur ou aucune empreinte).')
              : touchIdInstallHelp(),
      ),
      h('div', { class: 'section' },
        h('h3', {}, 'Verrouillage'),
        h('label', {}, 'Reverrouiller automatiquement'), autoLock,
        h('div', { style: 'height:8px' }),
        toggle('lockOnScreenLock', 'Verrouiller quand l’écran du Mac se verrouille', true),
        toggle('closeAfterCopy', 'Fermer la fenêtre après avoir copié un code', true),
      ),
      h('div', { class: 'section' },
        h('h3', {}, 'Confort'),
        toggle('autofill', 'Remplir le code dans la page en plus de le copier', true),
        h('p', {}, 'Seulement dans un champ qui ressemble à un champ 2FA. Sinon, le code est juste copié.'),
        toggle('smartFilter', 'Filtre intelligent par site', true),
        h('p', {}, 'Quand tu copies un code sur un nouveau site, propose de l’associer au compte. Ensuite, n’affiche que les comptes associés quand tu y es.'),
      ),
      backupSection(err),
      h('div', { class: 'section stack' },
        h('h3', {}, 'Import et export manuels'),
        h('button', { class: 'btn block', onclick: () => go('import') }, 'Importer des comptes'),
        h('button', {
          class: 'btn block',
          onclick: async () => {
            const record = backup.buildRecord(await vault.getVault(), await backup.deviceInfo());
            download(`authenticator-sauvegarde-${today()}.json`, JSON.stringify(record, null, 2));
          },
        }, 'Exporter une sauvegarde chiffrée'),
        plainBtn,
      ),
      h('div', { class: 'section stack' },
        h('h3', {}, 'Mot de passe'),
        cur, next, next2,
        h('button', { class: 'btn block', onclick: changePw }, 'Changer le mot de passe'),
      ),
      err,
    ),
  ];
}

function ago(ts) {
  if (!ts) return 'jamais';
  const min = Math.round((Date.now() - ts) / 60_000);
  if (min < 1) return 'à l’instant';
  if (min < 60) return `il y a ${min} min`;
  if (min < 1440) return `il y a ${Math.round(min / 60)} h`;
  return `il y a ${Math.round(min / 1440)} j`;
}

function backupSection(err) {
  const s = state.settings;
  const wrap = h('div', { class: 'section' }, h('h3', {}, 'Sauvegarde automatique'));
  const draw = async () => {
    const [status, dir] = await Promise.all([backup.getBackupStatus(), backup.getFolderHandle()]);
    const line = (st) => !st ? 'Pas encore sauvegardé'
      : st.ok ? `✓ Sauvegardé ${ago(st.at)}` : `⚠ ${st.error}`;
    const refresh = async () => {
      await backup.runBackups({ force: true });
      state.backupProblems = await backup.backupProblems();
      await refreshMeta();
      draw();
    };
    const setToggle = async (key, value) => {
      await vault.saveSettings({ [key]: value });
      await refreshMeta();
      await refresh();
    };

    const chooseFolder = async () => {
      if (!isTab) return openInTab('#settings');
      try {
        const handle = await window.showDirectoryPicker({ id: 'authenticator-backups', mode: 'readwrite', startIn: 'documents' });
        await backup.setFolderHandle(handle);
        await setToggle('backupFolder', true);
      } catch (e) {
        if (e.name !== 'AbortError') err.textContent = e.message;
      }
    };
    const reconnect = async () => {
      if (!isTab) return openInTab('#settings');
      if ((await dir.requestPermission({ mode: 'readwrite' })) === 'granted') await refresh();
    };

    wrap.replaceChildren(...[
      h('h3', {}, 'Sauvegarde automatique'),
      h('p', {}, 'Le coffre est sauvegardé chiffré à chaque changement. Il faut ton mot de passe (ou Touch ID) pour le relire.'),
      h('label', { class: 'check' },
        h('input', { type: 'checkbox', checked: s.backupSync, onchange: (e) => setToggle('backupSync', e.target.checked) }),
        'Dans mon compte Google (synchro Chrome)'),
      s.backupSync ? h('p', {}, line(status.sync), ' · nécessite la synchro Chrome activée pour les extensions.') : null,
      h('label', { class: 'check' },
        h('input', {
          type: 'checkbox',
          checked: s.backupFolder,
          onchange: (e) => (e.target.checked && !dir ? chooseFolder() : setToggle('backupFolder', e.target.checked)),
        }),
        'Dans un dossier (iCloud Drive, Dropbox…)'),
      s.backupFolder && dir
        ? h('p', {}, `📁 ${dir.name} · `, line(status.folder), ` · garde ${backup.KEEP_DAILY} jours d’historique.`)
        : null,
      s.backupFolder && status.folder?.code === 'permission'
        ? h('button', { class: 'btn primary block', onclick: reconnect }, 'Reconnecter le dossier')
        : null,
      s.backupFolder || !s.backupSync ? h('div', { class: 'row', style: 'margin-top:8px' },
        h('button', { class: 'btn', onclick: chooseFolder }, dir ? 'Changer de dossier' : 'Choisir le dossier'),
        h('button', { class: 'btn', onclick: refresh }, 'Sauvegarder maintenant'),
      ) : h('button', { class: 'btn block', style: 'margin-top:8px', onclick: refresh }, 'Sauvegarder maintenant'),
    ].filter(Boolean));
  };
  draw();
  return wrap;
}

const VIEWS = {
  loading: () => [],
  setup: viewSetup,
  welcome: viewWelcome,
  locked: viewLocked,
  list: viewList,
  add: viewAdd,
  edit: viewEdit,
  reorder: viewReorder,
  import: viewImport,
  settings: viewSettings,
};

function render() {
  if (state.view !== 'list') clearInterval(tickTimer);
  root.replaceChildren(...VIEWS[state.view]().flat().filter(Boolean));
  root.querySelector('[autofocus]')?.focus();
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !['list', 'locked', 'setup', 'loading'].includes(state.view)) {
    e.preventDefault();
    go('list');
  }
});

// Toute interaction repousse le verrouillage automatique.
document.addEventListener('pointerdown', () => vault.touch(), { passive: true });

// Un autre onglet ou le verrouillage auto a fermé le coffre : on suit.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes.dek && !changes.dek.newValue && !['locked', 'setup'].includes(state.view)) {
    state.accounts = [];
    go('locked');
  }
});

(async function init() {
  const [{ site, title, tabId }, bio] = await Promise.all([
    detectSite(),
    askBackground('touchid-status').catch(() => null),
  ]);
  Object.assign(state, { site, title, tabId, bioAvailable: Boolean(bio?.available), bioInstalled: Boolean(bio?.installed) });

  await refreshMeta();
  if (!(await vault.getVault())) return go('setup');
  if (await vault.currentDek()) {
    await vault.touch();
    return afterUnlock();
  }
  go('locked');
})();
