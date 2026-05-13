// PBKDF2-SHA256 + AES-256-GCM envelope — shared format with Go internal/envelope.
// Used by vault.js (token persistence) and future export/import flows.

const VERSION = 1;
const ITERATIONS = 600000;

const b64enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, hash: 'SHA-256', iterations: ITERATIONS },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Encrypt plaintext string with password → JSON envelope string. */
export async function encrypt(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const data = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext),
  );
  return JSON.stringify({ v: VERSION, kdf: 'pbkdf2-sha256', iter: ITERATIONS,
    salt: b64enc(salt), iv: b64enc(iv), data: b64enc(data) });
}

/** Decrypt JSON envelope string with password → plaintext. Throws on wrong password. */
export async function decrypt(envelope, password) {
  const e = JSON.parse(envelope);
  if (e.v !== VERSION) throw new Error('unsupported envelope version');
  const key  = await deriveKey(password, b64dec(e.salt));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64dec(e.iv) }, key, b64dec(e.data),
  );
  return new TextDecoder().decode(plain);
}

/** Returns true if s looks like an encryption envelope. */
export function isEnvelope(s) {
  if (!s || s[0] !== '{') return false;
  try { const e = JSON.parse(s); return e.v === VERSION && !!e.data; } catch { return false; }
}
