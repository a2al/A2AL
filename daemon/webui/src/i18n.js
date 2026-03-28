import en from './locales/en.js';
import zh from './locales/zh.js';
import ja from './locales/ja.js';

const STORAGE = 'a2al_locale';
const bundles = { en, 'zh-CN': zh, ja };

let locale = 'en';
let listeners = [];

function detect() {
  try {
    const s = localStorage.getItem(STORAGE);
    if (s && bundles[s]) return s;
  } catch (_) {}
  const nav = (navigator.language || 'en').toLowerCase();
  if (nav.startsWith('zh')) return 'zh-CN';
  if (nav.startsWith('ja')) return 'ja';
  return 'en';
}

function interpolate(str, vars) {
  if (!vars) return str;
  return str.replace(/\{(\w+)\}/g, (_, k) => (vars[k] != null ? String(vars[k]) : `{${k}}`));
}

export function init() {
  locale = detect();
}

export function getLocale() {
  return locale;
}

export function setLocale(code) {
  if (!bundles[code]) return;
  locale = code;
  try {
    localStorage.setItem(STORAGE, code);
  } catch (_) {}
  listeners.forEach((fn) => fn());
}

export function subscribe(fn) {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((x) => x !== fn);
  };
}

export function t(key, vars) {
  const table = bundles[locale] || en;
  const raw = table[key] ?? en[key] ?? key;
  return interpolate(raw, vars);
}

export function relTime(iso) {
  if (!iso) return '—';
  const diffSec = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  const past = diffSec > 0;
  const s = Math.abs(diffSec);
  if (s < 10) return t('time.just_now');
  const loc = locale === 'zh-CN' ? 'zh-CN' : locale === 'ja' ? 'ja' : 'en';
  const rtf = new Intl.RelativeTimeFormat(loc, { numeric: 'auto' });
  let n;
  let u;
  if (s < 60) {
    n = s;
    u = 'second';
  } else if (s < 3600) {
    n = Math.round(s / 60);
    u = 'minute';
  } else if (s < 86400) {
    n = Math.round(s / 3600);
    u = 'hour';
  } else {
    n = Math.round(s / 86400);
    u = 'day';
  }
  return rtf.format(past ? -n : n, u);
}
