// Verrouillage automatique et sauvegardes automatiques.
import { runBackups } from './lib/backup.js';
import { hostStatus } from './lib/touchid.js';
import { currentDek, enableTouchId, getSettings, lock, unlockWithTouchId } from './lib/vault.js';

function ensureAlarms() {
  chrome.alarms.create('autolock', { periodInMinutes: 1 });
  chrome.alarms.create('backup-retry', { periodInMinutes: 30 });
}

chrome.runtime.onInstalled.addListener(() => {
  ensureAlarms();
  runBackups();
});

chrome.runtime.onStartup.addListener(() => {
  ensureAlarms();
  runBackups();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  // currentDek() verrouille d'elle-même si le délai est dépassé
  if (alarm.name === 'autolock') currentDek();
  if (alarm.name === 'backup' || alarm.name === 'backup-retry') runBackups();
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === 'locked' && (await getSettings()).lockOnScreenLock) await lock();
});

// Réglage « dès que je ferme la fenêtre » : chaque page de l'extension ouvre un port,
// on verrouille quand le dernier se ferme.
let openPages = 0;
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'app') return;
  openPages += 1;
  port.onDisconnect.addListener(async () => {
    openPages -= 1;
    if (openPages > 0 || (await getSettings()).autoLockMinutes !== -1) return;
    // La popup se ferme juste avant que la fenêtre Touch ID s'ouvre : on laisse 2 s à la relève.
    setTimeout(() => openPages === 0 && lock(), 2000);
  });
});

// Sauvegarde quelques secondes après chaque changement du coffre ou des réglages de sauvegarde.
let pending;
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  const settingsChanged = changes.settings &&
    ['backupSync', 'backupFolder'].some((k) => changes.settings.oldValue?.[k] !== changes.settings.newValue?.[k]);
  if (!changes.vault && !settingsChanged) return;
  clearTimeout(pending);
  pending = setTimeout(() => runBackups(), 3000);
  chrome.alarms.create('backup', { delayInMinutes: 1 }); // filet si le service worker s'endort avant
});

// Touch ID passe par ici : le dialogue macOS ferme la popup, le service worker, lui, reste.
// Après un déverrouillage réussi, on rouvre la popup pour enchaîner.
let pendingTouchId = null;
async function runTouchId(type) {
  try {
    if (type === 'touchid-unlock') await unlockWithTouchId();
    else await enableTouchId();
    if (type === 'touchid-unlock') chrome.action.openPopup().catch(() => {});
    return { ok: true };
  } catch (err) {
    return { ok: false, code: err.code ?? 'error', error: err.message };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id) return false;
  if (msg?.type === 'touchid-status') {
    hostStatus().then(reply);
    return true;
  }
  if (msg?.type === 'touchid-unlock' || msg?.type === 'touchid-enroll') {
    // Un seul dialogue à la fois : un second clic attend le premier.
    pendingTouchId ??= runTouchId(msg.type).finally(() => (pendingTouchId = null));
    pendingTouchId.then(reply);
    return true;
  }
  return false;
});
