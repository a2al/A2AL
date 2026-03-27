const TOKEN_KEY = 'a2al_token';

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || '';
  } catch (_) {
    return '';
  }
}

export function setToken(tok) {
  try {
    if (tok) sessionStorage.setItem(TOKEN_KEY, tok);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch (_) {}
}

export async function api(path, opt = {}) {
  const method = opt.method || 'GET';
  const isRead = method === 'GET' || method === 'HEAD';
  const headers = { ...(opt.headers || {}) };
  const tok = getToken();
  if (tok) headers.Authorization = 'Bearer ' + tok;
  if (!isRead && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const resp = await fetch(path, { ...opt, headers });
  const txt = await resp.text();
  let body;
  try {
    body = JSON.parse(txt);
  } catch (_) {
    body = txt;
  }
  if (!resp.ok) {
    const msg =
      body && typeof body === 'object' && body.error
        ? body.error
        : `${resp.status} ${String(txt).slice(0, 200)}`;
    const err = new Error(msg);
    err.status = resp.status;
    throw err;
  }
  return body;
}
