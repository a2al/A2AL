export function shortAid(aid) {
  if (!aid || aid.length < 14) return aid || '';
  return aid.slice(0, 7) + '…' + aid.slice(-4);
}

/** Returns the locally stored alias for this AID, or '' if none set. */
export function aliasOf(aid) {
  if (!aid) return '';
  return localStorage.getItem('a2al_alias_' + aid) || '';
}

/** Persist an alias for an AID to localStorage. */
export function setAliasOf(aid, alias) {
  if (!aid) return;
  if (alias) localStorage.setItem('a2al_alias_' + aid, alias);
  else localStorage.removeItem('a2al_alias_' + aid);
}

/** Generate a locale-aware default alias (e.g. "Agent 42", "AI智能体 42"). */
export function generateDefaultAlias() {
  const n = Math.floor(Math.random() * 90) + 10; // 10–99
  const lang = localStorage.getItem('a2al_lang') || 'en';
  if (lang === 'zh') return `AI智能体 ${n}`;
  if (lang === 'ja') return `AIエージェント ${n}`;
  return `Agent ${n}`;
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
