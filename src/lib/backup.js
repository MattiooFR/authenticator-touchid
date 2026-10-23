// Sauvegardes automatiques du coffre chiffré.
// Le coffre stocké est déjà chiffré : on peut le sauvegarder sans le déverrouiller,
// donc depuis le service worker, à chaque changement.
//   - Chrome sync : un emplacement par appareil (aucun appareil n'écrase l'autre), découpé en morceaux.
//   - Dossier choisi (iCloud Drive…) : authenticator-latest.json + une copie par jour, 30 jours gardés.
import { getSettings } from './vault.js';

export const SYNC_PREFIX = 'bk:';
const CHUNK_SIZE = 7000; // < 8 Ko par élément (QUOTA_BYTES_PER_ITEM), clé et guillemets compris
export const KEEP_DAILY = 30;
const DAILY_RE = /^authenticator-\d{4}-\d{2}-\d{2}\.json$/;

export function splitChunks(text, size = CHUNK_SIZE) {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out.length ? out : [''];
}

export function dailyFilesToDelete(names, keep = KEEP_DAILY) {
  return names.filter((n) => DAILY_RE.test(n)).sort().reverse().slice(keep);
}

export async function deviceInfo() {
  const { device } = await chrome.storage.local.get('device');
  if (device) return device;
  const { os } = await chrome.runtime.getPlatformInfo();
  const label = { mac: 'Mac', win: 'Windows', linux: 'Linux', cros: 'Chromebook' }[os] ?? os;
  const created = { id: crypto.randomUUID().slice(0, 8), name: `${label} (${new Date().toLocaleDateString('fr-FR')})` };
  await chrome.storage.local.set({ device: created });
  return created;
}

export function buildRecord(vault, device) {
  return {
    format: 'authenticator-vault-backup',
    v: 1,
    createdAt: new Date().toISOString(),
    device,
    kdf: vault.kdf,
    wrapped: { pwd: vault.wrapped.pwd, bio: null }, // la clé Touch ID ne sert que sur ce Mac
    data: vault.data,
  };
}

async function contentHash(record) {
  const { createdAt, ...rest } = record;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(rest)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- statut ----------

export async function getBackupStatus() {
  const { backupStatus } = await chrome.storage.local.get('backupStatus');
  return backupStatus ?? {};
}

async function setStatus(target, patch) {
  const status = await getBackupStatus();
  status[target] = { ...status[target], ...patch };
  await chrome.storage.local.set({ backupStatus: status });
}

// Problème à signaler : une cible activée qui n'a jamais réussi ou dont le dernier essai a échoué.
export async function backupProblems() {
  const [settings, status, dir] = await Promise.all([getSettings(), getBackupStatus(), getFolderHandle()]);
  const problems = [];
  if (settings.backupSync && !status.sync?.ok) problems.push({ target: 'sync', error: status.sync?.error ?? 'Pas encore sauvegardé' });
  if (settings.backupFolder) {
    if (!dir) problems.push({ target: 'folder', error: 'Aucun dossier choisi' });
    else if (!status.folder?.ok) problems.push({ target: 'folder', error: status.folder?.error ?? 'Pas encore sauvegardé', code: status.folder?.code });
  }
  return problems;
}

async function updateBadge() {
  const problems = await backupProblems();
  await chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
  await chrome.action.setBadgeText({ text: problems.length ? '!' : '' });
  await chrome.action.setTitle({ title: problems.length ? `Authenticator : sauvegarde à vérifier (${problems[0].error})` : 'Authenticator' });
}

// ---------- Chrome sync ----------

function friendlySyncError(err) {
  const msg = err?.message ?? String(err);
  if (/QUOTA_BYTES/.test(msg)) return 'Trop de données pour la synchro Chrome (100 Ko max). Utilise la sauvegarde dans un dossier.';
  if (/MAX_WRITE_OPERATIONS/.test(msg)) return 'Trop d’écritures, nouvel essai dans une minute.';
  return msg;
}

async function writeSync(record) {
  const prefix = `${SYNC_PREFIX}${record.device.id}:`;
  const parts = splitChunks(JSON.stringify(record));
  const items = { [`${prefix}meta`]: { n: parts.length, createdAt: record.createdAt, device: record.device.name } };
  parts.forEach((p, i) => (items[`${prefix}${i}`] = p));
  const all = await chrome.storage.sync.get(null);
  const stale = Object.keys(all).filter((k) => k.startsWith(prefix) && !k.endsWith(':meta') && Number(k.slice(prefix.length)) >= parts.length);
  await chrome.storage.sync.set(items);
  if (stale.length) await chrome.storage.sync.remove(stale);
}

// Toutes les sauvegardes trouvées dans le compte Google, la plus récente d'abord.
export async function listSyncBackups() {
  const all = await chrome.storage.sync.get(null);
  const out = [];
  for (const key of Object.keys(all)) {
    if (!key.startsWith(SYNC_PREFIX) || !key.endsWith(':meta')) continue;
    const prefix = key.slice(0, -'meta'.length);
    const meta = all[key];
    try {
      const text = Array.from({ length: meta.n }, (_, i) => all[`${prefix}${i}`] ?? '').join('');
      const record = JSON.parse(text);
      if (record.format === 'authenticator-vault-backup') out.push({ device: meta.device, createdAt: meta.createdAt, record });
    } catch {
      // morceaux incomplets (synchro en cours) : ignorés
    }
  }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

// ---------- dossier (File System Access) ----------

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('authenticator', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('handles');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbOp(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('handles', mode);
    const req = fn(tx.objectStore('handles'));
    tx.oncomplete = () => resolve(req?.result);
    tx.onerror = () => reject(tx.error);
  });
}

export const getFolderHandle = () => idbOp('readonly', (s) => s.get('backupDir')).catch(() => null);
export const setFolderHandle = (handle) => idbOp('readwrite', (s) => s.put(handle, 'backupDir'));
export const clearFolderHandle = () => idbOp('readwrite', (s) => s.delete('backupDir'));

export async function folderPermission(dir) {
  try {
    return await dir.queryPermission({ mode: 'readwrite' });
  } catch {
    return 'prompt';
  }
}

async function writeFolder(record) {
  const dir = await getFolderHandle();
  if (!dir) throw Object.assign(new Error('Aucun dossier choisi'), { code: 'missing' });
  if ((await folderPermission(dir)) !== 'granted') {
    throw Object.assign(new Error('Chrome demande de reconnecter le dossier'), { code: 'permission' });
  }
  const text = JSON.stringify(record, null, 2);
  for (const name of ['authenticator-latest.json', `authenticator-${record.createdAt.slice(0, 10)}.json`]) {
    const file = await dir.getFileHandle(name, { create: true });
    if (!file.createWritable) throw Object.assign(new Error('Écriture impossible ici'), { code: 'unsupported' });
    const w = await file.createWritable();
    await w.write(text);
    await w.close();
  }
  const names = [];
  for await (const name of dir.keys()) names.push(name);
  for (const old of dailyFilesToDelete(names)) await dir.removeEntry(old);
}

// ---------- orchestration ----------

let running = null;

export function runBackups(opts) {
  // Une seule exécution à la fois (service worker et popup peuvent appeler en même temps).
  running = (running ?? Promise.resolve()).then(() => doRunBackups(opts)).finally(() => (running = null));
  return running;
}

async function doRunBackups({ force = false } = {}) {
  const { vault } = await chrome.storage.local.get('vault');
  if (!vault) return;
  const settings = await getSettings();
  const record = buildRecord(vault, await deviceInfo());
  const hash = await contentHash(record);
  const status = await getBackupStatus();

  if (settings.backupSync && (force || status.sync?.hash !== hash || !status.sync?.ok)) {
    try {
      await writeSync(record);
      await setStatus('sync', { ok: true, at: Date.now(), hash, error: null });
    } catch (err) {
      await setStatus('sync', { ok: false, error: friendlySyncError(err), errorAt: Date.now() });
    }
  }

  if (settings.backupFolder && (force || status.folder?.hash !== hash || !status.folder?.ok)) {
    try {
      await writeFolder(record);
      await setStatus('folder', { ok: true, at: Date.now(), hash, error: null, code: null });
    } catch (err) {
      // Le service worker ne sait pas toujours écrire : la popup réessaiera à son ouverture.
      if (err.code !== 'unsupported') await setStatus('folder', { ok: false, error: err.message, code: err.code ?? null, errorAt: Date.now() });
    }
  }

  await updateBadge();
}
