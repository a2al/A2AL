import './styles/main.css';
import { init, t, setLocale, getLocale, subscribe, relTime } from './i18n.js';
import { api, getToken, setToken } from './api.js';
import { vaultLoad, vaultUnlock, vaultClear, vaultSave, vaultIsLocked, vaultHasStored,
         shadowHas, shadowSave, shadowClear, shadowVerify } from './vault.js';
import { toast } from './toast.js';
import { shortAid, esc, setLoading } from './util.js';
import { renderAgents } from './views/agents.js';
import { renderDiscover } from './views/discover.js';
import { renderNode } from './views/node.js';

let tab = 'agents';
let _ver = ''; // cached version string, populated by refreshHeader()

/** Open a modal. onMount receives (modalEl, { close }). */
function openModal({ title, body, footer, wide, noBackdropClose, onMount }) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  const modal = document.createElement('div');
  modal.className = 'modal';
  if (wide) modal.style.maxWidth = '560px';

  const head = document.createElement('div');
  head.className = 'modal-h';
  head.innerHTML = `<span></span><button type="button" class="btn btn-ghost" data-x aria-label="Close">×</button>`;
  head.querySelector('span').textContent = title;

  const b = document.createElement('div');
  b.className = 'modal-b';
  b.innerHTML = body;

  modal.appendChild(head);
  modal.appendChild(b);
  if (footer) {
    const f = document.createElement('div');
    f.className = 'modal-f';
    f.textContent = footer;
    modal.appendChild(f);
  }
  backdrop.appendChild(modal);
  document.body.appendChild(backdrop);

  function close() {
    document.removeEventListener('keydown', onKey);
    backdrop.remove();
  }
  function onKey(e) {
    if (e.key === 'Escape') close();
  }
  document.addEventListener('keydown', onKey);

  head.querySelector('[data-x]').onclick = close;
  if (!noBackdropClose) {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) close();
    });
  }
  modal.addEventListener('click', (e) => {
    if (e.target.closest('[data-close]')) close();
  });

  onMount?.(modal, { close });
  return { close };
}

function copyText(s) {
  navigator.clipboard.writeText(s).then(() => toast(t('common.copied'), 'ok', 1200));
}

/** Refresh the sticky header status row. Uses IDs to update in-place. */
async function refreshHeader() {
  const dot = document.getElementById('statusDot');
  const meta = document.getElementById('headerMeta');
  const stLabel = document.getElementById('stLabel');
  if (!dot || !meta || !stLabel) return;
  try {
    const [host, stats, status] = await Promise.all([api('/debug/host'), api('/debug/stats'), api('/status')]);
    dot.className = 'status-dot ok';
    stLabel.textContent = t('status.online');
    meta.innerHTML = '';
    const add = (label, text) => {
      const d = document.createElement('div');
      d.className = 'meta-item';
      d.innerHTML = `<span class="meta-label">${esc(label)}</span> ${esc(text)}`;
      meta.appendChild(d);
    };
    add(t('node.aid'), shortAid(host.address));
    add('Tangled', host.dht_addr || '—');
    add('QUIC', host.quic_addr || '—');
    add(t('node.peers'), String(stats.total_peers ?? 0));
    // Update footer version — build display string once, reuse on language switch.
    if (status?.version) {
      const commit = status.commit && status.commit !== 'unknown' ? ` (${status.commit.slice(0, 7)})` : '';
      _ver = status.version + commit;
      const el = document.getElementById('footerVer');
      if (el) el.textContent = _ver;
    }
  } catch (e) {
    dot.className = 'status-dot err';
    stLabel.textContent = t('status.offline');
    meta.innerHTML = `<span class="muted">${esc(t('common.unavailable'))} — ${esc(e.message)}</span>`;
  }
}

/** Update only the active tab highlight — no DOM rebuild, no extra requests. */
function updateNavActive() {
  document.querySelectorAll('.nav-tabs button[data-tab]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
}

/** Open the login-password management popover. */
function openPasswordModal() {
  openModal({
    title: t('webui.access.title'),
    body: `
      <p class="muted" style="font-size:.85rem;margin:0 0 .75rem">${esc(t('webui.access.hint'))}</p>
      <div class="field">
        <label>${esc(t('webui.access.new_pw'))}</label>
        <input type="password" id="pwNew" autocomplete="new-password" style="width:100%" />
      </div>
      <div class="field">
        <label>${esc(t('webui.access.confirm_pw'))}</label>
        <input type="password" id="pwConfirm" autocomplete="new-password" style="width:100%" />
      </div>
      <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
        <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
        <button type="button" class="btn btn-primary" id="pwSave">${esc(t('common.save'))}</button>
      </div>`,
    onMount(root, { close }) {
      root.querySelector('#pwSave').onclick = async (ev) => {
        const nw = root.querySelector('#pwNew').value;
        const cf = root.querySelector('#pwConfirm').value;
        if (nw !== cf) { toast(t('webui.access.mismatch'), 'err'); return; }
        const btn = ev.currentTarget;
        setLoading(btn, true);
        try {
          const active = getToken();
          if (active) {
            // Has token: store/protect via vault; remove any shadow.
            await vaultSave(active, nw);
            shadowClear();
          } else {
            // No token: store/clear shadow as Web UI gate.
            if (nw) await shadowSave(nw); else shadowClear();
          }
          toast(t('webui.access.saved'), 'ok');
          close();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        } finally {
          setLoading(btn, false);
        }
      };
      root.querySelector('#pwNew').focus();
    },
  });
}

/** Full shell rebuild — called on init and language change. */
function renderShell() {
  const app = document.getElementById('app');
  if (!app) return;
  const loc = getLocale();

  app.innerHTML = `
    <header class="app-header">
      <h1><span class="status-dot" id="statusDot"></span> a2ald · <span id="stLabel" class="muted">${esc(t('status.connecting'))}</span></h1>
      <nav class="nav-tabs" id="navTabs"></nav>
      <div class="lang-btns" id="langBtns"></div>
      <button type="button" class="btn btn-ghost btn-sm" id="hdrPw" title="${esc(t('webui.access.title'))}">⚙</button>
      <button type="button" class="btn btn-ghost btn-sm" id="hdrRefresh" title="${esc(t('common.refresh'))}">${esc(t('common.refresh'))}</button>
      <div class="header-meta" id="headerMeta"></div>
    </header>
    <div id="secBanner" style="display:none"></div>
    <main class="main" id="mainPane"></main>
    <footer class="app-footer">
      <div class="footer-inner">
        <div class="footer-desc">
          <strong>A2AL</strong> — ${esc(t('about.a2al_desc'))}
        </div>
        <div class="footer-desc footer-tangled">
          <strong>Tangled Network</strong> — ${esc(t('about.tangled_desc'))}
        </div>
        <div class="footer-links">
          <a href="https://a2al.org" target="_blank" rel="noopener">a2al.org</a>
          <span class="footer-sep">·</span>
          <a href="https://tanglednet.org" target="_blank" rel="noopener">tanglednet.org</a>
          <span class="footer-sep">·</span>
          <a href="https://github.com/a2al/a2al" target="_blank" rel="noopener">GitHub</a>
        </div>
        <div class="footer-copy">a2ald <span id="footerVer" class="mono">${esc(_ver)}</span> · MPL 2.0 · ${esc(t('about.disclaimer'))}</div>
      </div>
    </footer>`;

  const nav = app.querySelector('#navTabs');
  for (const [id, key] of [
    ['agents', 'nav.agents'],
    ['discover', 'nav.discover'],
    ['node', 'nav.node'],
  ]) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = t(key);
    btn.className = tab === id ? 'active' : '';
    btn.dataset.tab = id;
    btn.onclick = () => {
      tab = id;
      updateNavActive();
      renderMain();
    };
    nav.appendChild(btn);
  }

  const langs = [
    ['en', 'EN'],
    ['zh-CN', '中文'],
    ['ja', '日本語'],
  ];
  const lb = app.querySelector('#langBtns');
  for (const [code, label] of langs) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    btn.className = loc === code ? 'on' : '';
    btn.onclick = () => setLocale(code);
    lb.appendChild(btn);
  }

  app.querySelector('#hdrPw').onclick = () => openPasswordModal();
  app.querySelector('#hdrRefresh').onclick = () => {
    refreshHeader();
    renderMain();
  };

  refreshHeader().then(() => maybeShowBanner());
  renderMain();
}

// Security nudge banner — only shown when a remembered token is stored without
// password protection (sensitive data at risk if other browser code reads localStorage).
const BANNER_NO_PW = 'a2al_banner_nopw';

function maybeShowBanner() {
  const el = document.getElementById('secBanner');
  if (!el) return;
  el.innerHTML = '';

  const show = !!getToken() && vaultHasStored() && !vaultIsLocked()
    && !localStorage.getItem(BANNER_NO_PW);
  if (!show) return;

  el.style.cssText = 'background:var(--warn-bg,#fff8e1);border-bottom:1px solid var(--warn-border,#ffe082);padding:.5rem 1rem;display:flex;justify-content:space-between;align-items:center;font-size:.85rem;gap:.5rem';
  el.innerHTML = `<span>⚠ ${esc(t('banner.no_pw'))}</span><button type="button" class="btn btn-ghost btn-sm" id="bannerDismiss" style="white-space:nowrap">${esc(t('banner.dismiss'))}</button>`;
  el.querySelector('#bannerDismiss').onclick = () => {
    localStorage.setItem(BANNER_NO_PW, '1');
    el.style.display = 'none';
  };
}

function renderMain() {
  const pane = document.getElementById('mainPane');
  if (!pane) return;
  pane.innerHTML = '';
  pane.dataset.renderTab = tab; // stamp: async probe callbacks check this to avoid writing stale tab
  const ctx = {
    t,
    api,
    toast,
    relTime,
    openModal,
    onRefresh: renderMain,
    copyText,
    isStale: () => pane.dataset.renderTab !== tab,
  };
  if (tab === 'agents') {
    renderAgents(pane, ctx);
  } else if (tab === 'discover') {
    renderDiscover(pane, ctx);
  } else {
    renderNode(pane, { ...ctx, setToken, shortAid, esc });
  }
}

init();
subscribe(() => renderShell());

// ── Startup password gate helpers ────────────────────────────────────────────

function _buildGateModal({ title, hint, onUnlock, onForgot, confirmKey, clearedKey }) {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.style.cssText = 'display:flex;align-items:center;justify-content:center';
    const box = document.createElement('div');
    box.className = 'modal';
    box.style.maxWidth = '360px';
    box.innerHTML = `
      <div class="modal-h"><span>${esc(title)}</span></div>
      <div class="modal-b">
        <p class="muted" style="margin:0 0 .75rem">${esc(hint)}</p>
        <input id="gatePw" type="password" style="width:100%" placeholder="${esc(t('vault.unlock.placeholder'))}" autocomplete="current-password" />
        <p id="gateErr" class="muted" style="color:var(--danger,#e53935);margin:.5rem 0 0;display:none">${esc(t('vault.unlock.wrong'))}</p>
      </div>
      <div class="modal-f" style="display:flex;justify-content:space-between;align-items:center">
        <button type="button" class="btn btn-ghost btn-sm" id="gateForgot" style="color:var(--muted,#888);font-size:.8rem">${esc(t('vault.unlock.forgot'))}</button>
        <button type="button" class="btn btn-primary" id="gateOk">${esc(t('vault.unlock.btn'))}</button>
      </div>`;
    backdrop.appendChild(box);
    document.getElementById('app').appendChild(backdrop);

    const pwEl  = box.querySelector('#gatePw');
    const errEl = box.querySelector('#gateErr');
    const btn   = box.querySelector('#gateOk');

    const tryUnlock = async () => {
      btn.disabled = true;
      errEl.style.display = 'none';
      try {
        await onUnlock(pwEl.value);
        backdrop.remove();
        resolve();
      } catch {
        errEl.style.display = '';
        pwEl.value = '';
        pwEl.focus();
      } finally {
        btn.disabled = false;
      }
    };

    btn.onclick = tryUnlock;
    pwEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
    box.querySelector('#gateForgot').onclick = () => {
      if (confirm(t(confirmKey || 'vault.unlock.clear_confirm'))) {
        onForgot();
        toast(t(clearedKey || 'vault.unlock.cleared'), 'ok');
        backdrop.remove();
        resolve();
      }
    };
    setTimeout(() => pwEl.focus(), 50);
  });
}

// Load persisted credentials before rendering.
// Possible states:
//   1. Vault encrypted (token+pw)  → show vault unlock gate
//   2. Vault plaintext             → setToken; then check shadow
//   3. No vault + shadow exists    → show shadow gate (Web UI password, no token)
//   4. Nothing                     → render directly
(async () => {
  const { token, encrypted } = vaultLoad();

  if (encrypted) {
    await _buildGateModal({
      title:    t('vault.unlock.title'),
      hint:     t('vault.unlock.hint'),
      onUnlock: async (pw) => { setToken(await vaultUnlock(pw)); },
      onForgot: () => { vaultClear(); },
    });
  } else {
    if (token) setToken(token);
    if (shadowHas()) {
      await _buildGateModal({
        title:      t('shadow.unlock.title'),
        hint:       t('shadow.unlock.hint'),
        confirmKey: 'shadow.unlock.clear_confirm',
        clearedKey: 'shadow.unlock.cleared',
        onUnlock:   async (pw) => {
          const ok = await shadowVerify(pw);
          if (!ok) throw new Error('wrong');
        },
        onForgot: () => { shadowClear(); },
      });
    }
  }

  renderShell();
})();

// Global 401 handler — show enter-token modal when daemon requires auth but browser has none.
let _unauthorizedModalOpen = false;
window.addEventListener('a2al:unauthorized', () => {
  if (_unauthorizedModalOpen || getToken()) return; // already handled or token was just set
  _unauthorizedModalOpen = true;
  openModal({
    noBackdropClose: true,
    title: t('token.required.title'),
    body: `
      <p class="muted" style="margin:0 0 .75rem">${esc(t('token.required.hint'))}</p>
      <input type="password" id="reqTok" style="width:100%" placeholder="${esc(t('token.required.placeholder'))}" autocomplete="off" />
      <label style="display:flex;align-items:center;gap:.5rem;margin-top:.6rem;cursor:pointer">
        <input type="checkbox" id="reqRemember" />
        <span style="font-size:.85rem">${esc(t('node.token.remember'))}</span>
      </label>
      <div style="margin-top:1rem;text-align:right">
        <button type="button" class="btn btn-primary" id="reqApply">${esc(t('token.required.btn'))}</button>
      </div>`,
    onMount(root, { close }) {
      const apply = async () => {
        const v = root.querySelector('#reqTok').value.trim();
        if (!v) return;
        setToken(v);
        if (root.querySelector('#reqRemember').checked) {
          await vaultSave(v, '');
        }
        _unauthorizedModalOpen = false;
        close();
        renderMain();
      };
      root.querySelector('#reqApply').onclick = apply;
      root.querySelector('#reqTok').addEventListener('keydown', (e) => { if (e.key === 'Enter') apply(); });
      setTimeout(() => root.querySelector('#reqTok').focus(), 50);
    },
  });
});
