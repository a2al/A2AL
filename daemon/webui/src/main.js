import './styles/main.css';
import { init, t, setLocale, getLocale, subscribe, relTime } from './i18n.js';
import { api, setToken } from './api.js';
import { toast } from './toast.js';
import { shortAid, esc } from './util.js';
import { renderAgents } from './views/agents.js';
import { renderDiscover } from './views/discover.js';
import { renderNode } from './views/node.js';

let tab = 'agents';

/** Open a modal. onMount receives (modalEl, { close }). */
function openModal({ title, body, footer, wide, onMount }) {
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
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) close();
  });
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
    const [host, stats] = await Promise.all([api('/debug/host'), api('/debug/stats')]);
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
      <button type="button" class="btn btn-ghost btn-sm" id="hdrRefresh" title="${esc(t('common.refresh'))}">${esc(t('common.refresh'))}</button>
      <div class="header-meta" id="headerMeta"></div>
    </header>
    <main class="main" id="mainPane"></main>`;

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

  app.querySelector('#hdrRefresh').onclick = () => {
    refreshHeader();
    renderMain();
  };

  refreshHeader();
  renderMain();
}

function renderMain() {
  const pane = document.getElementById('mainPane');
  if (!pane) return;
  pane.innerHTML = '';
  const ctx = {
    t,
    api,
    toast,
    relTime,
    openModal,
    onRefresh: renderMain,
    copyText,
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
renderShell();
