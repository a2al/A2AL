export function shortAid(aid) {
  if (!aid || aid.length < 14) return aid || '';
  return aid.slice(0, 7) + '…' + aid.slice(-4);
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
  if (j.protocols && Array.isArray(j.protocols)) out.protocols = j.protocols.map(String);
  else if (j.mcpServers || j.tools || j.capabilities?.mcp) out.protocols.push('mcp');
  if (j.capabilities || j.skills || j.tools) {
    if (!out.protocols.includes('a2a')) out.protocols.push('a2a');
  }
  return out;
}
