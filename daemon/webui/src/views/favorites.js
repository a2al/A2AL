import { setAliasOf, ensureAlias } from '../util.js';

const KEY = 'a2al_favorites';

export function loadFavs() {
  try { return JSON.parse(localStorage.getItem(KEY) || '[]'); } catch { return []; }
}

function saveFavs(list) {
  localStorage.setItem(KEY, JSON.stringify(list));
}

export function isFaved(aid) {
  return loadFavs().some((f) => f.aid === aid);
}

/**
 * Add an AID to favorites.
 * Returns { added: true } or { added: false, reason: 'dup' }.
 * Alias is stored in the central map (util.js), not on the fav entry.
 */
export function addFav(aid, alias, skill, protocols) {
  const list = loadFavs();
  if (list.some((f) => f.aid === aid)) return { added: false, reason: 'dup' };
  if (alias) setAliasOf(aid, alias);
  else ensureAlias(aid);
  const id = list.length === 0 ? 1 : Math.max(...list.map((f) => f.id)) + 1;
  list.push({
    id,
    aid,
    skill: skill || '',
    protocols: Array.isArray(protocols) ? protocols : [],
    addedAt: Date.now(),
  });
  saveFavs(list);
  return { added: true };
}

export function removeFav(id) {
  saveFavs(loadFavs().filter((f) => f.id !== id));
}
