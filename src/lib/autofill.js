// Remplissage du code dans la page. N'agit que sur l'onglet où la popup a été ouverte
// (permission activeTab), et seulement quand le champ visé ressemble vraiment à un champ 2FA.

// Injectée telle quelle dans la page : doit rester autonome (aucune référence extérieure).
export function fillOtpInPage(code) {
  const KEYWORDS = /one.?time|otp|totp|2fa|mfa|two.?factor|second.?factor|verif|auth.*code|security.?code|code|token|pin/i;
  const NOISE = /search|recherche|email|e-mail|user|login|phone|tel[eé]phone|promo|coupon|captcha|zip|postal/i;

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly;
  };
  const fillable = (el) => !el.value || /^\d{0,8}$/.test(el.value.replace(/\s/g, ''));
  const describe = (el) => [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.getAttribute('data-testid'),
    el.labels?.[0]?.textContent].filter(Boolean).join(' ');

  const setValue = (el, value) => {
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(el, value); // contourne les inputs contrôlés (React, Vue)
    for (const type of ['keydown', 'keypress', 'keyup']) el.dispatchEvent(new KeyboardEvent(type, { bubbles: true }));
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const inputs = [...document.querySelectorAll('input')]
    .filter((el) => ['text', 'tel', 'number', 'password'].includes(el.type) && visible(el));
  if (!inputs.length) return false;

  // Cases séparées (une case par chiffre)
  const singles = inputs.filter((el) => el.maxLength === 1 && fillable(el));
  if (singles.length === code.length) {
    [...code].forEach((digit, i) => setValue(singles[i], digit));
    return true;
  }

  const active = document.activeElement;
  const score = (el) => {
    const text = describe(el);
    let s = 0;
    if (el.autocomplete === 'one-time-code') s += 100;
    if (KEYWORDS.test(text)) s += 40;
    if (NOISE.test(text)) s -= 60;
    if (el === active) s += 20;
    if (el.inputMode === 'numeric' || el.type === 'tel' || el.type === 'number' || /\\d|\[0-9\]/.test(el.pattern)) s += 15;
    if (el.maxLength === code.length) s += 15;
    if (el.type === 'password') s -= 25;
    return s;
  };
  const [best] = inputs.filter(fillable).map((el) => [score(el), el]).sort((a, b) => b[0] - a[0]);
  // Seuil : un vrai indice (mot-clé, autocomplete) ou un champ actif numérique de la bonne longueur.
  if (!best || best[0] < 35) return false;
  setValue(best[1], code);
  return true;
}

// tabId : l'onglet d'origine quand on vient de la fenêtre Touch ID (sinon l'onglet actif).
export async function fillActiveTab(code, tabId = null) {
  const tab = tabId ? { id: tabId } : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id) return false;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      func: fillOtpInPage,
      args: [code],
    });
    return results.some((r) => r.result === true);
  } catch {
    try {
      const [r] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fillOtpInPage, args: [code] });
      return r?.result === true;
    } catch {
      return false; // page interdite (chrome://, Web Store…)
    }
  }
}
