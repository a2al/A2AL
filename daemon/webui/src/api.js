// In-memory active token. Persistence is handled by vault.js.
let _token = '';

export function getToken() { return _token; }

export function setToken(tok) {
  _token = tok || '';
}

export async function api(path, opt = {}) {
  const method = opt.method || 'GET';
  const isRead = method === 'GET' || method === 'HEAD';
  const headers = { ...(opt.headers || {}) };
  if (_token) headers.Authorization = 'Bearer ' + _token;
  if (!isRead && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const resp = await fetch(path, { ...opt, headers });
  const txt = await resp.text();
  let body;
  try { body = JSON.parse(txt); } catch { body = txt; }
  if (!resp.ok) {
    const msg =
      body && typeof body === 'object' && body.error
        ? body.error
        : `${resp.status} ${String(txt).slice(0, 200)}`;
    const err = new Error(msg);
    err.status = resp.status;
    if (resp.status === 401) {
      window.dispatchEvent(new CustomEvent('a2al:unauthorized'));
    }
    throw err;
  }
  return body;
}
