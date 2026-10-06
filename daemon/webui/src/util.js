import { getAliases, setAliasInBook } from './address-book.js';

export function shortAid(aid) {
  if (!aid || aid.length < 14) return aid || '';
  return aid.slice(0, 7) + '…' + aid.slice(-4);
}

function aidTone(aid) {
  let h = 2166136261;
  const s = String(aid || '');
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return h >>> 0;
}

/** Local avatar color from AID. Not stored; same AID always same color on this client. */
export function aidAvStyle(aid) {
  const hue = aidTone(aid) % 360;
  return `background:hsl(${hue},46%,44%);color:#fff`;
}

/** Short AID with a per-character hue sequence derived from the full AID. */
export function shortAidHTML(aid) {
  const s = shortAid(aid);
  const tone = aidTone(aid);
  const hue0 = tone % 360;
  const step = 19 + (tone % 27);
  let html = '<span class="aid-chroma">';
  for (const [i, ch] of [...s].entries()) {
    const h = (hue0 + i * step) % 360;
    html += `<span style="color:hsl(${h},70%,36%)">${esc(ch)}</span>`;
  }
  html += '</span>';
  return html;
}

/** Escape text, coloring `@shortAid` tokens when the AID is known. */
export function colorizeAtShortAids(text, aids) {
  const raw = String(text || '');
  const byShort = new Map();
  for (const aid of aids || []) {
    if (!aid) continue;
    byShort.set(shortAid(aid), aid);
  }
  const re = /@([^\s…]{7}…[^\s]{4})/g;
  let html = '';
  let last = 0;
  let m;
  while ((m = re.exec(raw))) {
    html += esc(raw.slice(last, m.index));
    const tok = m[1];
    const aid = byShort.get(tok);
    html += aid ? `@${shortAidHTML(aid)}` : `@${esc(tok)}`;
    last = m.index + m[0].length;
  }
  html += esc(raw.slice(last));
  return html;
}

/** Clickable short AID that toggles to the full string. */
export function aidExpandHTML(full) {
  if (!full) return '';
  return `<button type="button" class="aid-expand mono" data-full-aid="${esc(full)}">${esc(shortAid(full))}</button>`;
}

export function toggleAidExpand(el) {
  const full = el?.dataset?.fullAid;
  if (!full) return;
  el.textContent = el.textContent === full ? shortAid(full) : full;
}

function aliasLangPrefix() {
  const lang = localStorage.getItem('a2al_lang') || 'en';
  if (lang === 'zh') return 'AI智能体 ';
  if (lang === 'ja') return 'AIエージェント ';
  return 'Agent ';
}

function usedAliasValuesLower(map) {
  return new Set(Object.values(map).map((v) => String(v).toLowerCase()));
}

/** Next locale-aware default alias unique across all AIDs. */
export function nextUniqueDefaultAlias() {
  const used = usedAliasValuesLower(getAliases());
  const prefix = aliasLangPrefix();
  let n = 1;
  while (used.has(`${prefix}${n}`.toLowerCase())) n++;
  return `${prefix}${n}`;
}

/** Returns the stored alias for this AID, or '' if none set. */
export function aliasOf(aid) {
  if (!aid) return '';
  return getAliases()[aid] || '';
}

/** Persist an alias for an AID on the connected node. */
export function setAliasOf(aid, alias) {
  if (!aid) return;
  setAliasInBook(aid, alias);
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
