// vault.js — persists the API token in localStorage with optional password protection.
// Shadow: a separate key that stores an encrypted empty string; used as a Web UI
// login gate when there is no token to store in the vault.

import { encrypt, decrypt, isEnvelope } from './crypto.js';

const KEY        = 'a2al_token';
const SHADOW_KEY = 'a2al_pw_shadow';

const _get    = () => { try { return localStorage.getItem(KEY) || ''; } catch { return ''; } };
const _set    = (v) => { try { if (v) localStorage.setItem(KEY, v); else localStorage.removeItem(KEY); } catch {} };
const _getSh  = () => { try { return localStorage.getItem(SHADOW_KEY) || ''; } catch { return ''; } };
const _setSh  = (v) => { try { if (v) localStorage.setItem(SHADOW_KEY, v); else localStorage.removeItem(SHADOW_KEY); } catch {} };


/**
 * Load the vault.
 * Returns { token, encrypted }:
 *   encrypted = false → token is the plaintext API token (may be empty string).
 *   encrypted = true  → token is null; call vaultUnlock(password) to retrieve it.
 */
export function vaultLoad() {
  const stored = _get();
  if (isEnvelope(stored)) return { token: null, encrypted: true };
  return { token: stored, encrypted: false };
}

/**
 * Unlock an encrypted vault. Returns the plaintext token.
 * Throws if the password is wrong (AES-GCM authentication fails).
 */
export async function vaultUnlock(password) {
  const stored = _get();
  if (!isEnvelope(stored)) return stored;
  return decrypt(stored, password);
}

/**
 * Save token to localStorage.
 * password = '' → store plaintext.
 * password = non-empty → store as PBKDF2+AES-GCM envelope.
 */
export async function vaultSave(token, password) {
  if (!token) { _set(''); return; }
  _set(password ? await encrypt(token, password) : token);
}

/** Remove the stored token. */
export function vaultClear() { _set(''); }

/** Returns true if the stored value is a password-protected envelope. */
export function vaultIsLocked() { return isEnvelope(_get()); }

/** Returns true if any value (plaintext or encrypted) is stored. */
export function vaultHasStored() { return !!_get(); }

// ── Shadow (password gate without token) ────────────────────────────────────

/** Save a Web UI login password as an encrypted shadow marker (no token stored). */
export async function shadowSave(password) {
  if (!password) { _setSh(''); return; }
  _setSh(await encrypt('', password));
}

/** Returns true if the given password matches the stored shadow. */
export async function shadowVerify(password) {
  const stored = _getSh();
  if (!stored) return false;
  try { await decrypt(stored, password); return true; } catch { return false; }
}

/** Returns true if a shadow marker exists. */
export function shadowHas() { return !!_getSh(); }

/** Remove the shadow marker. */
export function shadowClear() { _setSh(''); }
