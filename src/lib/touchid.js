// Touch ID par l'hôte natif (dossier native/ du projet), comme Bitwarden et 1Password :
// Chrome n'offre aucune API Touch ID aux extensions. L'hôte garde une clé dans la Secure Enclave
// et ne rend le secret qu'après l'empreinte.
export const HOST = 'com.authenticator.touchid';
export const INSTALL_COMMAND = './native/install.sh   (depuis le dossier du projet)';

// Appel direct à l'hôte. À faire depuis le service worker : le dialogue Touch ID ferme la popup,
// et la réponse serait perdue avec elle.
export async function callHost(message) {
  let res;
  try {
    res = await chrome.runtime.sendNativeMessage(HOST, message);
  } catch {
    const err = new Error('L’app Touch ID n’est pas installée sur ce Mac.');
    err.code = 'missing';
    throw err;
  }
  if (!res?.ok) {
    const err = new Error(res?.error ?? 'Réponse vide de l’app Touch ID.');
    err.code = res?.code ?? 'error';
    throw err;
  }
  return res;
}

export async function hostStatus() {
  try {
    const r = await callHost({ cmd: 'ping' });
    return { installed: true, available: Boolean(r.biometry && r.secureEnclave), reason: r.biometryError ?? '' };
  } catch {
    return { installed: false, available: false, reason: '' };
  }
}

// Côté pages : demande au service worker. Renvoie { ok, error, code }.
export function askBackground(type) {
  return chrome.runtime.sendMessage({ type });
}
