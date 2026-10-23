// Estimation prudente de la force d'un mot de passe, sans dictionnaire embarqué.
// On découpe le mot de passe en morceaux (lettres, chiffres, symboles) et on suppose que
// l'attaquant devine intelligemment : un bloc de lettres compte comme un mot du dictionnaire,
// une année ou une suite (abcd, 1234, azerty) ne vaut presque rien.
// Le scénario : une sauvegarde chiffrée a fuité, l'attaquant essaie hors ligne.

import { PBKDF2_ITERATIONS } from './vault-crypto.js';

// Une RTX 4090 fait ~9 millions de PBKDF2-SHA256 par seconde à 1 000 itérations (hashcat 10900).
const GUESSES_PER_GPU = (9e6 * 1000) / PBKDF2_ITERATIONS;
export const ATTACK_GPUS = 100;
export const GUESSES_PER_SECOND = GUESSES_PER_GPU * ATTACK_GPUS;

const COMMON = new Set([
  'password', 'motdepasse', 'azerty', 'qwerty', 'qwertz', 'soleil', 'bonjour', 'loulou', 'doudou', 'chouchou',
  'marseille', 'paris', 'iloveyou', 'jetaime', 'admin', 'welcome', 'letmein', 'monkey', 'dragon', 'football',
  'baseball', 'princess', 'sunshine', 'master', 'shadow', 'superman', 'batman', 'trustno', 'secret', 'coucou',
  'nicolas', 'thomas', 'camille', 'julien', 'mathieu', 'matthieu', 'chocolat', 'liberte', 'freedom', 'google',
  'facebook', 'linkedin', 'apple', 'samsung', 'authenticator', 'passw', 'changeme', 'default', 'test', 'user',
]);

const SEQUENCES = [
  'abcdefghijklmnopqrstuvwxyz', '0123456789', 'azertyuiop', 'qsdfghjklm', 'wxcvbn', 'qwertyuiop', 'asdfghjkl',
  'zxcvbnm', '1234567890',
];

const LEET = { '@': 'a', 4: 'a', 3: 'e', 1: 'i', '!': 'i', 0: 'o', $: 's', 5: 's', 7: 't' };

const log2 = Math.log2;

function isSequence(s) {
  if (s.length < 3) return false;
  const low = s.toLowerCase();
  if (/^(.)\1+$/.test(low)) return true;
  return SEQUENCES.some((seq) => seq.includes(low) || [...seq].reverse().join('').includes(low));
}

function chunkBits(chunk) {
  const n = chunk.length;
  if (isSequence(chunk)) return 2 + log2(n);
  if (/^\d+$/.test(chunk)) {
    if (/^(19|20)\d\d$/.test(chunk)) return 7; // une année
    if (n <= 2) return n * log2(10);
    return n * log2(10) * 0.9;
  }
  if (/^\p{L}+$/u.test(chunk)) {
    const lower = chunk.toLowerCase();
    const caps = chunk === lower ? 0 : chunk[0] !== lower[0] && chunk.slice(1) === lower.slice(1) ? 1 : n;
    const random = n * log2(26);
    // Un mot de 4 lettres ou plus : on le suppose dans un dictionnaire de ~30 000 mots (15 bits).
    // Un long bloc sans espace (« correcthorsebatterystaple ») contient plusieurs mots collés :
    // on compte un mot par tranche de 8 lettres.
    const word = n >= 4 ? Math.min(random, 15 * Math.ceil(n / 8)) : random;
    return word + Math.min(caps, n);
  }
  if (/^\p{L}+$/u.test(chunk.normalize('NFD').replace(/\p{M}/gu, ''))) return n * log2(26) + 2;
  return n * log2(33); // symboles
}

function normalizeLeet(s) {
  return [...s.toLowerCase()].map((c) => LEET[c] ?? c).join('');
}

export function estimateStrength(password) {
  const pw = String(password ?? '');
  if (!pw) return { bits: 0, guesses: 1, seconds: 0, level: 0 };

  const squashed = normalizeLeet(pw).replace(/[^a-z]/g, '');
  let bits;
  if ([...COMMON].some((w) => squashed === w || (squashed.length <= w.length + 3 && squashed.includes(w)))) {
    bits = 10;
  } else {
    // Découpe en blocs de même nature ; les séparateurs (espace, tiret…) coûtent peu.
    // Les MotsEnCamelCase sont découpés en mots : leurs majuscules sont prévisibles.
    const chunks = pw.match(/\p{Lu}?\p{Ll}+|\p{Lu}+(?!\p{Ll})|\p{L}+|\d+|[^\p{L}\d]+/gu) ?? [];
    bits = 0;
    const seen = new Set();
    for (const c of chunks) {
      const key = normalizeLeet(c);
      if (seen.has(key)) {
        bits += 2; // bloc répété
        continue;
      }
      seen.add(key);
      bits += /^[\s\-_.]+$/.test(c) && c.length <= 2 ? 1.5 : chunkBits(c);
      if (COMMON.has(key)) bits -= Math.max(0, chunkBits(c) - 6);
    }
    bits += log2(Math.max(1, chunks.length)); // ordre des blocs
  }
  bits = Math.max(0, bits);
  const guesses = 2 ** bits / 2;
  const seconds = guesses / GUESSES_PER_SECOND;
  const years = seconds / 31_557_600;
  const level = seconds < 86_400 ? 0 : years < 1 ? 1 : years < 1000 ? 2 : years < 1e6 ? 3 : 4;
  return { bits, guesses, seconds, level };
}

export const LEVELS = [
  { label: 'Très faible', color: 'var(--danger)' },
  { label: 'Faible', color: 'var(--danger)' },
  { label: 'Moyen', color: 'var(--warn)' },
  { label: 'Bon', color: 'var(--ok)' },
  { label: 'Excellent', color: 'var(--ok)' },
];

// Niveau minimal pour créer le coffre ou changer le mot de passe.
export const MIN_LEVEL = 3;

export function formatDuration(seconds) {
  const YEAR = 31_557_600;
  // [à partir de, unité, singulier, pluriel]
  const units = [
    [YEAR * 1e9, YEAR * 1e9, 'milliard d’années', 'milliards d’années'],
    [YEAR * 1e6, YEAR * 1e6, 'million d’années', 'millions d’années'],
    [YEAR * 1000, YEAR, 'an', 'ans'],
    [YEAR * 100, YEAR * 100, 'siècle', 'siècles'],
    [YEAR, YEAR, 'an', 'ans'],
    [2_629_800, 2_629_800, 'mois', 'mois'],
    [86_400, 86_400, 'jour', 'jours'],
    [3600, 3600, 'heure', 'heures'],
    [60, 60, 'minute', 'minutes'],
    [1, 1, 'seconde', 'secondes'],
  ];
  if (!(seconds >= 1)) return 'instantané';
  if (seconds > YEAR * 1e12) return 'plus que l’âge de l’univers';
  const [, size, one, many] = units.find(([from]) => seconds >= from);
  const n = Math.floor(seconds / size);
  return `${n.toLocaleString('fr-FR')} ${n === 1 ? one : many}`;
}

export function strengthHint(password, { level }) {
  if (level >= MIN_LEVEL) return '';
  if (password.length < 10) return 'Trop court. Le plus simple : 4 mots au hasard séparés par des tirets.';
  if (/^\p{L}+$/u.test(password)) return 'Ajoute un ou deux mots, ou des chiffres au milieu.';
  return 'Ajoute un mot de plus. Évite les prénoms, les années et les suites (1234, azerty).';
}
