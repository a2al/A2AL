export function shortAid(aid) {
  if (!aid || aid.length < 14) return aid || '';
  return aid.slice(0, 7) + '…' + aid.slice(-4);
}

const ALIASES_KEY = 'a2al_aliases';
const ALIASES_MIGRATED_KEY = 'a2al_aliases_v1';
const FAV_KEY = 'a2al_favorites';
const OLD_ALIAS_PREFIX = 'a2al_alias_';

function aliasLangPrefix() {
  const lang = localStorage.getItem('a2al_lang') || 'en';
  if (lang === 'zh') return 'AI智能体 ';
  if (lang === 'ja') return 'AIエージェント ';
  return 'Agent ';
}

function loadAliasMapRaw() {
  try {
    const raw = localStorage.getItem(ALIASES_KEY);
    if (!raw) return {};
    const map = JSON.parse(raw);
    return map && typeof map === 'object' ? map : {};
  } catch {
    return {};
  }
}

function saveAliasMap(map) {
  localStorage.setItem(ALIASES_KEY, JSON.stringify(map));
}

function usedAliasValuesLower(map) {
  return new Set(Object.values(map).map((v) => String(v).toLowerCase()));
}

function isGeneratedDefaultAlias(alias) {
  return /^(Agent|AI智能体|AIエージェント) \d+$/i.test(String(alias || '').trim());
}

/** Next locale-aware default alias unique across all AIDs. */
export function nextUniqueDefaultAlias() {
  migrateAliasesOnce();
  const used = usedAliasValuesLower(loadAliasMapRaw());
  const prefix = aliasLangPrefix();
  let n = 1;
  while (used.has(`${prefix}${n}`.toLowerCase())) n++;
  return `${prefix}${n}`;
}

function migrateAliasesOnce() {
  if (localStorage.getItem(ALIASES_MIGRATED_KEY)) return;

  const map = { ...loadAliasMapRaw() };

  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i);
    if (!k || !k.startsWith(OLD_ALIAS_PREFIX)) continue;
    const aid = k.slice(OLD_ALIAS_PREFIX.length);
    const v = (localStorage.getItem(k) || '').trim();
    if (aid && v && !map[aid]) map[aid] = v;
  }

  let favsChanged = false;
  try {
    const favs = JSON.parse(localStorage.getItem(FAV_KEY) || '[]');
    if (Array.isArray(favs)) {
      const cleaned = favs.map((f) => {
        if (!f || !f.aid) return f;
        const a = String(f.alias || '').trim();
        if (a && !map[f.aid]) map[f.aid] = a;
        if ('alias' in f) {
          favsChanged = true;
          const { alias: _drop, ...rest } = f;
          return rest;
        }
        return f;
      });
      if (favsChanged) localStorage.setItem(FAV_KEY, JSON.stringify(cleaned));
    }
  } catch (_) {}

  const seen = new Map();
  for (const aid of Object.keys(map)) {
    const alias = map[aid];
    const low = String(alias).toLowerCase();
    if (seen.has(low)) {
      if (isGeneratedDefaultAlias(alias)) {
        delete map[aid];
        const used = usedAliasValuesLower(map);
        const prefix = aliasLangPrefix();
        let n = 1;
        while (used.has(`${prefix}${n}`.toLowerCase())) n++;
        map[aid] = `${prefix}${n}`;
        used.add(map[aid].toLowerCase());
      }
    } else {
      seen.set(low, aid);
    }
  }

  saveAliasMap(map);
  localStorage.setItem(ALIASES_MIGRATED_KEY, '1');
}

function loadAliasMap() {
  migrateAliasesOnce();
  return loadAliasMapRaw();
}

/** Returns the locally stored alias for this AID, or '' if none set. */
export function aliasOf(aid) {
  if (!aid) return '';
  return loadAliasMap()[aid] || '';
}

/** Persist an alias for an AID to localStorage. */
export function setAliasOf(aid, alias) {
  if (!aid) return;
  migrateAliasesOnce();
  const map = loadAliasMapRaw();
  const trimmed = String(alias || '').trim();
  if (trimmed) map[aid] = trimmed;
  else delete map[aid];
  saveAliasMap(map);
}

/** Ensure aid has an alias; assign a globally unique default if missing. */
export function ensureAlias(aid) {
  if (!aid) return '';
  const existing = aliasOf(aid);
  if (existing) return existing;
  const alias = nextUniqueDefaultAlias();
  setAliasOf(aid, alias);
  return alias;
}

/** @deprecated Use nextUniqueDefaultAlias() or ensureAlias(aid). */
export function generateDefaultAlias() {
  return nextUniqueDefaultAlias();
}

/** For dropdown labels: "Alias (shortAid)" when alias set, else shortAid. */
export function labelAid(aid) {
  const a = aliasOf(aid);
  return a ? `${a} (${shortAid(aid)})` : shortAid(aid);
}

/** Normalize a user-entered service_tcp value.
 *  Accepted formats (paths are stripped):
 *    https://host:port  → https://host:port  (TLS mode — scheme preserved)
 *    https://host       → https://host:443
 *    http://host:port   → host:port          (plain TCP, same as no scheme)
 *    http://host        → host:80
 *    host:port          → host:port          (pass-through)
 */
export function normalizeServiceTCP(input) {
  const s = (input || '').trim();
  if (!s) return '';
  if (s.startsWith('https://')) {
    try {
      const u = new URL(s);
      const port = u.port || '443';
      return `https://${u.hostname}:${port}`;
    } catch (_) {}
    return s;
  }
  if (s.startsWith('http://')) {
    try {
      const u = new URL(s);
      const port = u.port || '80';
      return `${u.hostname}:${port}`;
    } catch (_) {}
  }
  return s;
}
export function parseCardData(j) {
  if (!j || typeof j !== 'object') return null;
  const name = j.name || j.title || j.serverInfo?.name || '';
  const version = j.version || j.apiVersion || j.serverInfo?.version || '';
  let tools = [];
  if (Array.isArray(j.tools)) {
    tools = j.tools.map((x) => (typeof x === 'string' ? x : x.name || '')).filter(Boolean);
  } else if (j.tools && typeof j.tools === 'object') {
    tools = Object.keys(j.tools);
  }
  let caps = '';
  if (j.capabilities && typeof j.capabilities === 'object') {
    caps = Object.entries(j.capabilities).map(([k, v]) => `${k}: ${v}`).join(', ');
  }
  return { name, version, caps, tools };
}

export function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function setLoading(btn, on) {
  if (!btn) return;
  if (on) {
    btn._html = btn.innerHTML;
    btn.innerHTML = '<span class="spin"></span>';
    btn.disabled = true;
  } else {
    btn.innerHTML = btn._html || '';
    btn.disabled = false;
  }
}

export function parseTags(s) {
  if (!s || !String(s).trim()) return [];
  return String(s)
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

export function buildServiceName(cat, fn, qual) {
  const f = String(fn || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, '');
  const c = String(cat || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.-]/g, '');
  if (!c || !f) return '';
  if (qual && String(qual).trim()) {
    const q = String(qual)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9.-]/g, '');
    return `${c}.${f}-${q}`;
  }
  return `${c}.${f}`;
}

export const STANDARD_PROTOCOLS = ['mcp', 'a2a', 'http', 'grpc', 'websocket'];

/** Split stored protocols into checkbox values and custom tokens. */
export function partitionProtocols(protocols) {
  const std = new Set(STANDARD_PROTOCOLS);
  const checked = [];
  const custom = [];
  for (const p of (protocols || []).map((x) => String(x).toLowerCase())) {
    if (!p) continue;
    if (std.has(p)) {
      if (!checked.includes(p)) checked.push(p);
    } else {
      custom.push(p);
    }
  }
  return { checked, custom };
}

/** Read protocol checkboxes + custom input from publish modal. */
export function gatherProtocols(root) {
  const protos = [];
  for (const p of STANDARD_PROTOCOLS) {
    if (root.querySelector(`#svProto_${p}`)?.checked) protos.push(p);
  }
  protos.push(...parseTags(root.querySelector('#svProtoCustom')?.value || ''));
  return [...new Set(protos.map((x) => x.toLowerCase()))];
}

/** Build default Agent Card URL from service_tcp. */
export function agentCardUrlFromServiceTcp(tcp) {
  if (!tcp) return '';
  const base = tcp.startsWith('https://') || tcp.startsWith('http://')
    ? tcp.replace(/\/$/, '')
    : 'http://' + tcp;
  return `${base}/.well-known/agent.json`;
}

/** Fetch Agent Card JSON from a direct HTTP(S) URL. */
export async function fetchAgentCardFromUrl(url) {
  const r = await fetch(url, { mode: 'cors' });
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

/** Fetch Agent Card for a local agent: direct URL first, then daemon /fetch. */
export async function fetchAgentCardForAgent(api, aid, serviceTcp) {
  const url = agentCardUrlFromServiceTcp(serviceTcp);
  if (url) {
    try {
      const json = await fetchAgentCardFromUrl(url);
      return { json, url };
    } catch (_) {}
  }
  for (const path of ['/.well-known/agent.json', '/.well-known/mcp.json']) {
    try {
      const r = await api(`/fetch/${encodeURIComponent(aid)}`, {
        method: 'POST',
        body: JSON.stringify({ path }),
      });
      if (r.status >= 200 && r.status < 300) {
        return { json: JSON.parse(base64ToUtf8(r.body)), url: path };
      }
    } catch (_) {}
  }
  return null;
}

export function profileDraftFromAgent(agent) {
  const p = agent?.profile || {};
  return {
    name: p.name || '',
    brief: p.brief || '',
    protocols: Array.isArray(p.protocols) ? [...p.protocols] : [],
    modalities: Array.isArray(p.modalities) ? [...p.modalities] : [],
  };
}

export function profileDraftFromCardJson(j) {
  const m = mapCardJson(j);
  const modalities = Array.isArray(j?.modalities) ? j.modalities.map(String) : [];
  return {
    name: m.name || '',
    brief: m.brief || '',
    protocols: m.protocols || [],
    modalities,
  };
}

/** Merge profile draft fields; overwrite=true replaces all scalars/lists from incoming. */
export function mergeProfileDraft(current, incoming, { overwrite = false } = {}) {
  const out = {
    name: current.name || '',
    brief: current.brief || '',
    protocols: [...(current.protocols || [])],
    modalities: [...(current.modalities || [])],
  };
  if (overwrite || !out.name.trim()) out.name = incoming.name || '';
  if (overwrite || !out.brief.trim()) out.brief = incoming.brief || '';
  if (overwrite || !out.protocols.length) out.protocols = [...(incoming.protocols || [])];
  if (overwrite || !out.modalities.length) out.modalities = [...(incoming.modalities || [])];
  return out;
}

/** Best-effort map Agent Card / MCP JSON into publish form fields */
export function mapCardJson(j) {
  const out = { name: '', brief: '', url: '', protocols: [] };
  if (!j || typeof j !== 'object') return out;
  out.name = j.name || j.title || j.serverInfo?.name || j.server?.name || '';
  out.brief =
    j.description ||
    j.brief ||
    j.serverInfo?.description ||
    j.server?.description ||
    '';
  const u = j.url || j.serverUrl || j.server_url || j.mcpEndpoint || j.endpoint;
  if (typeof u === 'string') out.url = u;
  if (j.protocols && Array.isArray(j.protocols)) {
    out.protocols = j.protocols.map(String);
  } else {
    if (j.mcpServers || j.tools || j.capabilities?.mcp) out.protocols.push('mcp');
    if (j.skills) out.protocols.push('a2a');
  }
  return out;
}

export function base64ToUtf8(b64) {
  try {
    const bin = atob(b64 || '');
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch (_) {
    return '';
  }
}
