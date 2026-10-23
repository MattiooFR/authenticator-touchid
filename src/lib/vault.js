// Couche stockage : coffre chiffré dans chrome.storage.local, clé de session (DEK) dans
// chrome.storage.session (mémoire uniquement, effacée à la fermeture de Chrome ou au verrouillage).
import {
  createVaultRecord, decryptJson, encryptJson, fromB64, keyFromPrf, openWithPassword,
  rewrapPassword, toB64, unwrapDek, wrapDek,
} from './vault-crypto.js';
import { callHost } from './touchid.js';

const local = chrome.storage.local;
const session = chrome.storage.session;

// autoLockMinutes : > 0 = délai d'inactivité, 0 = à la fermeture de Chrome, -1 = dès la fermeture de la fenêtre
export const DEFAULT_SETTINGS = {
  autoLockMinutes: 30,
  lockOnScreenLock: true,
  closeAfterCopy: true,
  autofill: true,
  smartFilter: true,
  customOrder: false, // true dès que l'utilisateur a réorganisé ses comptes ; sinon ordre alphabétique
  backupSync: true,
  backupFolder: false,
};

export async function getSettings() {
  const { settings } = await local.get('settings');
  return { ...DEFAULT_SETTINGS, ...settings };
}

export async function saveSettings(patch) {
  await local.set({ settings: { ...(await getSettings()), ...patch } });
}

export async function getVault() {
  const { vault } = await local.get('vault');
  return vault ?? null;
}

async function startSession(dek) {
  await session.set({ dek: toB64(dek), lastActive: Date.now() });
}

export async function touch() {
  const { dek } = await session.get('dek');
  if (dek) await session.set({ lastActive: Date.now() });
}

export async function lock() {
  await session.remove(['dek', 'lastActive']);
}

// Renvoie la DEK si le coffre est ouvert et que le délai d'inactivité n'est pas dépassé.
export async function currentDek() {
  const { dek, lastActive } = await session.get(['dek', 'lastActive']);
  if (!dek) return null;
  const { autoLockMinutes } = await getSettings();
  if (autoLockMinutes > 0 && Date.now() - (lastActive ?? 0) > autoLockMinutes * 60_000) {
    await lock();
    return null;
  }
  return fromB64(dek);
}

export async function createVault(password) {
  const { vault, dek } = await createVaultRecord(password);
  await local.set({ vault });
  await startSession(dek);
}

export async function unlockWithPassword(password) {
  const dek = await openWithPassword(await getVault(), password);
  await startSession(dek);
}

// Touch ID valide : bio créé par l'hôte natif (les anciens passkeys n'ont pas de clé « key »).
export const hasTouchId = (vault) => Boolean(vault?.wrapped?.bio?.key);

export async function unlockWithTouchId() {
  const vault = await getVault();
  const bio = vault?.wrapped?.bio;
  if (!hasTouchId(vault)) throw new Error('Touch ID n’est pas activé');
  const { secret } = await callHost({ cmd: 'derive', key: bio.key, peer: bio.peer, reason: 'ouvrir ton coffre Authenticator' });
  let dek;
  try {
    dek = await unwrapDek(await keyFromPrf(fromB64(secret)), bio.box);
  } catch {
    throw new Error('La clé Touch ID ne correspond plus au coffre : réactive Touch ID dans les réglages');
  }
  await startSession(dek);
}

async function requireDek() {
  const dek = await currentDek();
  if (!dek) throw new Error('Coffre verrouillé');
  return dek;
}

export async function enableTouchId() {
  const dek = await requireDek();
  const { key, peer, secret } = await callHost({ cmd: 'enroll', reason: 'activer Touch ID pour Authenticator' });
  const box = await wrapDek(await keyFromPrf(fromB64(secret)), dek);
  const vault = await getVault();
  vault.wrapped.bio = { type: 'secure-enclave', key, peer, box, createdAt: Date.now() };
  await local.set({ vault });
}

export async function disableTouchId() {
  const vault = await getVault();
  vault.wrapped.bio = null;
  await local.set({ vault });
}

export async function changePassword(currentPassword, newPassword) {
  const vault = await getVault();
  const dek = await openWithPassword(vault, currentPassword);
  await local.set({ vault: await rewrapPassword(vault, dek, newPassword) });
}

export async function loadAccounts() {
  const dek = await requireDek();
  return decryptJson(dek, (await getVault()).data);
}

export async function saveAccounts(accounts) {
  const dek = await requireDek();
  const vault = await getVault();
  vault.data = await encryptJson(dek, accounts);
  await local.set({ vault });
}

async function dekFromBackup(backup, password) {
  if (backup?.format !== 'authenticator-vault-backup') throw new Error('Ce fichier n’est pas une sauvegarde de ce coffre');
  return openWithPassword(backup, password);
}

// Lit les comptes d'une sauvegarde (pour les fusionner dans le coffre actuel).
export async function readBackup(backup, password) {
  return decryptJson(await dekFromBackup(backup, password), backup.data);
}

// Nouvel appareil : la sauvegarde devient le coffre (même mot de passe, même clé).
// Touch ID repart à zéro : la clé de la Secure Enclave ne quitte jamais le Mac qui l'a créée.
export async function adoptBackup(backup, password) {
  const dek = await dekFromBackup(backup, password);
  await decryptJson(dek, backup.data);
  const vault = { v: 1, kdf: backup.kdf, wrapped: { pwd: backup.wrapped.pwd, bio: null }, data: backup.data };
  await local.set({ vault });
  await startSession(dek);
}
