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

/** Returns the next available alias string (AID-N, where N is not already used). */
export function nextDefaultAlias(list) {
  const used = new Set(
    list.map((f) => { const m = f.alias.match(/^AID-(\d+)$/); return m ? Number(m[1]) : 0; })
  );
  let n = 1;
  while (used.has(n)) n++;
  return `AID-${n}`;
}

/**
 * Add an AID to favorites.
 * Returns { added: true } or { added: false, reason: 'dup' }.
 */
export function addFav(aid, alias, skill, protocols) {
  const list = loadFavs();
  if (list.some((f) => f.aid === aid)) return { added: false, reason: 'dup' };
  const id = list.length === 0 ? 1 : Math.max(...list.map((f) => f.id)) + 1;
  list.push({
    id,
    aid,
    alias: alias || nextDefaultAlias(list),
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

export function updateFavAlias(id, alias) {
  saveFavs(loadFavs().map((f) => (f.id === id ? { ...f, alias } : f)));
}
