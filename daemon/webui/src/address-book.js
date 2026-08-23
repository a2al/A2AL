import { api } from './api.js';
import { t } from './i18n.js';
import { toast } from './toast.js';

const ALIASES_KEY = 'a2al_aliases';
const FAV_KEY = 'a2al_favorites';
const OLD_ALIAS_PREFIX = 'a2al_alias_';

let aliases = {};
let favorites = [];
let imported = false;
let persistTimer = 0;

export function getAliases() {
  return aliases;
}

export function getFavorites() {
  return favorites;
}

export function setAliasInBook(aid, alias) {
  if (!aid) return;
  const trimmed = String(alias || '').trim();
  if (trimmed) aliases[aid] = trimmed;
  else delete aliases[aid];
  schedulePersist();
}

export function setFavorites(list) {
  favorites = Array.isArray(list) ? list : [];
  schedulePersist();
}

function snapshot() {
  return { imported: true, aliases, favorites };
}

export function schedulePersist() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistNow().catch(() => {});
  }, 300);
}

async function persistNow() {
  try {
    const saved = await api('/node/address-book', {
      method: 'PUT',
      body: JSON.stringify(snapshot()),
    });
    applyRemote(saved);
  } catch (e) {
    toast(t('common.error', { msg: e.message || e }), 'err');
  }
}

function applyRemote(book) {
  imported = !!book?.imported;
  aliases = book?.aliases && typeof book.aliases === 'object' ? { ...book.aliases } : {};
  favorites = Array.isArray(book?.favorites) ? book.favorites.slice() : [];
}

function peekLocalAliases() {
  const map = {};
  try {
    const raw = localStorage.getItem(ALIASES_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') Object.assign(map, parsed);
    }
  } catch (_) {}
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (!k || !k.startsWith(OLD_ALIAS_PREFIX)) continue;
      const aid = k.slice(OLD_ALIAS_PREFIX.length);
      const v = (localStorage.getItem(k) || '').trim();
      if (aid && v && !map[aid]) map[aid] = v;
    }
  } catch (_) {}
  try {
    const favs = JSON.parse(localStorage.getItem(FAV_KEY) || '[]');
    if (Array.isArray(favs)) {
      for (const f of favs) {
        if (!f?.aid) continue;
        const a = String(f.alias || '').trim();
        if (a && !map[f.aid]) map[f.aid] = a;
      }
    }
  } catch (_) {}
  return map;
}

function peekLocalFavorites() {
  try {
    const favs = JSON.parse(localStorage.getItem(FAV_KEY) || '[]');
    if (!Array.isArray(favs)) return [];
    return favs
      .filter((f) => f && f.aid)
      .map((f) => {
        const { alias: _drop, ...rest } = f;
        return rest;
      });
  } catch (_) {
    return [];
  }
}

function localHasData(localAliases, localFavs) {
  return Object.keys(localAliases).length > 0 || localFavs.length > 0;
}

function mergeImport(remote, localAliases, localFavs) {
  const aliasesOut = { ...localAliases, ...remote.aliases };
  const byAid = new Map();
  for (const f of remote.favorites || []) {
    if (f?.aid) byAid.set(f.aid, f);
  }
  for (const f of localFavs) {
    if (f?.aid && !byAid.has(f.aid)) byAid.set(f.aid, f);
  }
  return {
    imported: true,
    aliases: aliasesOut,
    favorites: [...byAid.values()],
  };
}

export async function hydrateAddressBook() {
  let remote = emptyBook();
  try {
    remote = applyAndReturn(await api('/node/address-book'));
  } catch (_) {
    applyRemote(emptyBook());
  }
  if (remote.imported) return;
  const localAliases = peekLocalAliases();
  const localFavs = peekLocalFavorites();
  if (!localHasData(localAliases, localFavs)) return;
  const merged = mergeImport(remote, localAliases, localFavs);
  applyRemote(merged);
  await persistNow();
}

function applyAndReturn(book) {
  applyRemote(book);
  return { imported, aliases, favorites };
}

function emptyBook() {
  return { imported: false, aliases: {}, favorites: [] };
}
