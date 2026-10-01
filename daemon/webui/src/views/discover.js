import { esc, shortAid, aidExpandHTML, toggleAidExpand, setLoading, base64ToUtf8, aliasOf, setAliasOf, ensureAlias, nextUniqueDefaultAlias } from '../util.js';
import { loadFavs, addFav, removeFav, isFaved } from './favorites.js';

const NAT_TYPE_KEYS = {
  0: 'node.nat.unknown',
  1: 'node.nat.full_cone',
  2: 'node.nat.restricted',
  3: 'node.nat.port_restricted',
  4: 'node.nat.symmetric',
};
function natLabel(t, n) {
  if (n == null) return '—';
  return t(NAT_TYPE_KEYS[n] ?? 'node.nat.unknown');
}

function isAccessDenied(e) {
  return e && (e.status === 403 || /access denied/i.test(e.message || ''));
}

function accessRetryHTML(t, requesterAid) {
  const hint = t('connect.access_denied_hint', { aid: '\u0001' }).split('\u0001').map(esc).join(aidExpandHTML(requesterAid));
  return `<p style="color:var(--error);margin:0">${esc(t('connect.access_denied'))}</p><p class="muted" style="margin:.2rem 0 0;font-size:.83rem">${hint}</p>
      <div class="acl-join-retry">
        <input type="password" data-join-secret autocomplete="off" placeholder="${esc(t('discover.access_token'))}" />
        <button type="button" class="btn btn-secondary btn-sm" data-join-retry>${esc(t('discover.access_retry'))}</button>
      </div>`;
}

function isPortInUse(e) {
  return e && e.status === 409 && e.message === 'port_in_use';
}

function actionFailHTML(e, t, requesterAid, opts) {
  if (isPortInUse(e)) {
    return `<p style="color:var(--error);margin:0">${esc(t('discover.tunnel.port_in_use', { port: opts && opts.port }))}</p>
      <button type="button" class="btn btn-ghost btn-sm" data-port-random style="margin-top:.35rem">${esc(t('discover.tunnel.port_use_random'))}</button>`;
  }
  if (isAccessDenied(e)) {
    return accessRetryHTML(t, requesterAid);
  }
  const is412 = e.status === 412;
  return `<p style="color:var(--error);margin:0">${esc(is412 ? t('connect.no_direct_path') : t('connect.peer_offline'))}</p><p class="muted" style="margin:.2rem 0 0;font-size:.83rem">${esc(is412 ? t('connect.relay_required_hint') : t('connect.unreachable_hint'))}</p>`;
}

function bindAccessRetry(root, e, onRetry) {
  if (!isAccessDenied(e)) return;
  const btn = root.querySelector('[data-join-retry]');
  const inp = root.querySelector('[data-join-secret]');
  if (!btn) return;
  btn.onclick = () => onRetry((inp?.value || '').trim());
  inp?.focus();
}

function utf8ToBase64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

function fmtShortDT(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const mo = String(d.getMonth() + 1).padStart(2, '0');
  const dy = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${mo}-${dy} ${hh}:${mm}`;
}

function parseCard(j) {
  if (!j || typeof j !== 'object') return null;
  const name = j.name || j.title || j.serverInfo?.name || '';
  const version = j.version || j.apiVersion || j.serverInfo?.version || '';
  let tools = [];
  if (Array.isArray(j.tools)) {
    tools = j.tools.map((x) => (typeof x === 'string' ? x : x.name || x.id || '')).filter(Boolean);
  } else if (j.tools && typeof j.tools === 'object') {
    tools = Object.keys(j.tools);
  }
  let caps = '';
  if (j.capabilities && typeof j.capabilities === 'object') {
    caps = Object.entries(j.capabilities).map(([k, v]) => `${k}: ${v}`).join(', ');
  }
  const url = j.url || j.serverUrl || j.mcpEndpoint || '';
  return { name, version, caps, tools, url, raw: j };
}

async function fetchAgentCard(api, aid) {
  const paths = ['/.well-known/agent.json', '/.well-known/mcp.json'];
  for (const path of paths) {
    try {
      const r = await api(`/fetch/${encodeURIComponent(aid)}`, {
        method: 'POST',
        body: JSON.stringify({ path }),
      });
      if (r.status >= 200 && r.status < 300) {
        const j = JSON.parse(base64ToUtf8(r.body));
        return { json: j, path };
      }
    } catch (_) {}
  }
  return null;
}

const QUICK = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];
const SP = 'padding:.7rem .95rem';
const SP_SM = 'padding:.55rem .95rem';
const SVC_CARD_STYLE = 'margin-bottom:.4rem;padding:.38rem .5rem;background:var(--bg-subtle,#f9fafb);border:1px solid var(--border,#e5e7eb);border-radius:.35rem';

function svcCardHtml(svc) {
  const topic  = svc.topic || svc.Topic || svc.service || '';
  const protos = (svc.protocols || []).map((p) => `<span class="badge b-blue" style="font-size:.78rem">${esc(p)}</span>`).join('');
  const tags   = (svc.tags || []).map((x) => `<span style="font-size:.77rem;color:var(--muted)">#${esc(x)}</span>`).join(' ');
  return `
    <div style="display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:${svc.name || svc.brief || tags ? '.1rem' : '0'}">
      <span class="svc-name">${esc(topic)}</span>${protos}
    </div>
    ${svc.name  ? `<div style="font-size:.87rem;font-weight:500;color:var(--fg)">${esc(svc.name)}</div>` : ''}
    ${tags       ? `<div style="margin-top:.1rem">${tags}</div>` : ''}
    ${svc.brief  ? `<div class="muted" style="font-size:.83rem;line-height:1.45;margin-top:.12rem">${esc(svc.brief)}</div>` : ''}`;
}

// metaSummary renders a small, safe "key: value" preview of a freeform profile.meta map.
function metaSummary(meta) {
  if (!meta || typeof meta !== 'object') return '';
  const parts = Object.entries(meta).slice(0, 6).map(([k, v]) => {
    let val = v && typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (val.length > 40) val = val.slice(0, 40) + '\u2026';
    return `${esc(k)}: ${esc(val)}`;
  });
  return parts.join(' &middot; ');
}

export async function renderDiscover(mount, ctx) {
  const { t, api, toast, copyText, isStale } = ctx;
  let agents = [];
  let nodeAid = '';
  try {
    const r = await api('/agents');
    agents = r.agents || [];
  } catch (_) {}
  try {
    const st = await api('/status');
    nodeAid = st.node_aid || '';
  } catch (_) {}

  const agentOpts = agents.length === 0
    ? `<option value="">${esc(t('discover.myagent.empty'))}</option>`
    : `<option value="">${esc(t('discover.myagent.pick'))}</option>${agents.map((a) =>
        `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}`;

  const msgFormHtml = agents.length === 0
    ? `<p class="muted" style="margin:0;font-size:.87rem">${esc(t('discover.msg.need_agent'))}</p>`
    : `<div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:flex-end">
        <div style="flex:0 0 auto">
          <label style="display:block;font-size:.79rem;color:var(--muted);margin-bottom:.2rem">${esc(t('discover.msg.from'))}</label>
          <select id="dMsgFrom">${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}</select>
        </div>
        <div style="flex:1;min-width:10rem">
          <label style="display:block;font-size:.79rem;color:var(--muted);margin-bottom:.2rem">${esc(t('discover.msg.body'))}</label>
          <input type="text" id="dMsgTxt" style="width:100%" />
        </div>
        <button type="button" class="btn btn-secondary" id="dMsgGo">${esc(t('discover.msg.submit'))}</button>
      </div>`;

  const SEP = `<div style="height:1px;background:var(--border,#e5e7eb)"></div>`;
  const LBL = `display:block;font-size:.79rem;color:var(--muted);margin-bottom:.18rem`;

  const wrap = document.createElement('div');
  wrap.innerHTML = `
    <div class="discover-tabs" role="tablist">
      <button type="button" class="active" data-tab="aid">${esc(t('discover.tab.aid'))}</button>
      <button type="button" data-tab="svc">${esc(t('discover.tab.service'))}</button>
      <button type="button" data-tab="fav">${esc(t('discover.tab.favorites'))}</button>
    </div>

    <!-- Tab: AID query -->
    <div id="tabAid" class="discover-tab-panel">
      <div class="discover-search" style="margin-top:1rem">
        <input type="text" id="dAid" placeholder="${esc(t('discover.aid.placeholder'))}" class="mono" />
        <select id="dMyAg">${agentOpts}</select>
        <button type="button" class="btn btn-primary" id="dQuery">${esc(t('discover.query'))}</button>
      </div>
      <p class="muted aid-err hidden" id="dAidErr"></p>
    </div>

    <!-- Tab: service search -->
    <div id="tabSvc" class="discover-tab-panel hidden">
      <p class="muted" style="margin:1rem 0 .5rem">${esc(t('discover.subtitle'))}</p>
      <div class="discover-search">
        <input type="text" id="dq" placeholder="${esc(t('discover.placeholder'))}" />
        <button type="button" class="btn btn-primary" id="ds">${esc(t('discover.search'))}</button>
      </div>
      <div class="cat-btns" style="margin-bottom:1rem" id="dqCat"></div>
      <div id="dSvcOut"></div>
    </div>

    <!-- Tab: favorites -->
    <div id="tabFav" class="discover-tab-panel hidden">
      <div class="card" style="margin-top:1rem">
        <!-- Control bar: toggle-add (left) + sort (right) -->
        <div class="fav-toolbar" style="display:flex;justify-content:space-between;align-items:center;padding:.5rem .85rem;flex-wrap:wrap;gap:.35rem">
          <button type="button" class="btn btn-secondary btn-sm" id="dFavAddToggle">+ ${esc(t('discover.fav.add_btn'))}</button>
          <div style="display:flex;gap:.2rem;align-items:center">
            <span class="muted" style="font-size:.79rem;margin-right:.15rem">${esc(t('discover.fav.sort'))}</span>
            <button type="button" class="btn btn-ghost btn-xs" data-fav-sort="alias" id="dFavSortAlias">${esc(t('discover.fav.sort.alias'))}</button>
            <button type="button" class="btn btn-ghost btn-xs" data-fav-sort="skill" id="dFavSortSkill">${esc(t('discover.fav.sort.skill'))}</button>
            <button type="button" class="btn btn-ghost btn-xs active" data-fav-sort="addedAt" id="dFavSortTime">${esc(t('discover.fav.sort.time'))} ↓</button>
          </div>
        </div>
        <!-- Collapsible add form -->
        <div id="dFavAddForm" class="fav-add-form" style="display:none;border-top:1px solid var(--border,#e5e7eb);padding:.6rem .85rem .7rem">
          <div class="fav-add-grid">
            <div class="field form-grid-wide" style="margin-bottom:0">
              <label style="${LBL}">AID <span class="muted" style="font-size:.73rem">(${esc(t('common.required'))})</span></label>
              <input type="text" id="dFavAid" placeholder="${esc(t('discover.fav.aid_ph'))}" class="mono" style="width:100%" />
            </div>
            <div class="field" style="margin-bottom:0">
              <label style="${LBL}">${esc(t('discover.fav.alias_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavAlias" maxlength="24" placeholder="${esc(t('agent.alias.placeholder'))}" style="width:100%" />
              <div class="hint">${esc(t('agent.alias.local_hint'))}</div>
            </div>
            <div class="field" style="margin-bottom:0">
              <label style="${LBL}">${esc(t('discover.fav.skill_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavSkill" style="width:100%" />
            </div>
            <div class="field" style="margin-bottom:0">
              <label style="${LBL}">${esc(t('discover.fav.protocols_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavProtos" placeholder="http, mcp" style="width:100%" />
            </div>
            <div class="fav-add-actions form-grid-wide">
              <button type="button" class="btn btn-ghost btn-sm" id="dFavFetch">${esc(t('discover.fav.fetch'))}</button>
              <button type="button" class="btn btn-primary btn-sm" id="dFavAdd">${esc(t('discover.fav.add'))}</button>
            </div>
          </div>
        </div>
      </div>
      <!-- List -->
      <div id="dFavList" style="margin-top:.6rem"></div>
    </div>

    <!-- Result card (AID query results, hidden when on favorites tab) -->
    <div id="dOp" class="card hidden" style="margin-top:1.25rem">

      <div style="${SP}">
        <!-- Target row -->
        <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:.75rem;margin-bottom:.75rem">
          <div style="min-width:0;flex:1">
            <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap">
              <span style="font-size:.82rem;font-weight:700;color:var(--muted);letter-spacing:.05em;text-transform:uppercase">${esc(t('discover.target'))}</span>
              <span id="dOpAlias" class="hidden" style="font-size:1.05rem;font-weight:700"></span>
              <button type="button" class="btn btn-ghost btn-sm" id="dOpStar" style="font-size:.85rem;padding:.1rem .4rem"></button>
            </div>
            <div style="display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;margin-top:.12rem">
              <span class="mono muted" id="dOpAid" style="font-size:.9rem"></span>
              <button type="button" class="btn btn-ghost btn-sm" id="dOpCp" style="padding:.1rem .3rem;font-size:.85rem">\u29c9</button>
            </div>
            <div id="dTargetProfile" class="hidden" style="margin-top:.5rem"></div>
          </div>
          <div id="dStatusBadge" class="hidden" style="display:flex;flex-direction:column;align-items:flex-end;gap:.18rem;font-size:.83rem;min-width:9rem;text-align:right"></div>
        </div>

        <div id="dQueryStrip" class="discover-query-strip hidden" aria-hidden="true"></div>

        <div style="display:flex;flex-wrap:wrap;gap:.4rem;align-items:center">
          <button type="button" class="btn btn-secondary btn-sm" id="dTunnel">${esc(t('discover.tunnel.btn2'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" id="dOneshot">${esc(t('discover.oneshot.btn'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" id="dShowReq">${esc(t('discover.req.title'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" id="dAidProxy">${esc(t('discover.aidproxy.btn'))}</button>
        </div>
        <div id="dActionOut" class="disc-op-block hidden" style="margin-top:.65rem"></div>
      </div>

      ${SEP}

      <div style="${SP}">
        <div style="font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:.5rem">${esc(t('discover.capabilities'))}</div>
        <div id="dProfile"></div>
        <div style="display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.55rem;padding-top:.5rem;border-top:1px solid var(--border,#e5e7eb)">
          <button type="button" class="btn btn-ghost btn-sm" id="dCacheBtn" style="font-size:.81rem">
            ${esc(t('discover.cache_btn'))} <span id="dCacheChevron" style="font-size:.68rem;opacity:.55">\u25be</span>
          </button>
          <button type="button" class="btn btn-ghost btn-sm" id="dCard" style="font-size:.81rem">
            ${esc(t('discover.card'))} <span id="dCardChevron" style="font-size:.68rem;opacity:.55">\u25be</span>
          </button>
        </div>
        <div id="dLocalSvc" class="hidden" style="margin-top:.5rem"></div>
        <div id="dCardOut" class="hidden" style="margin-top:.5rem"></div>
      </div>

      ${SEP}

      <div style="${SP};background:var(--bg-subtle,#f9fafb)">
        <button type="button" class="btn btn-ghost btn-sm" id="dNetworkBtn" style="font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);padding:0">
          <span id="dNetworkChevron" style="font-size:.68rem;opacity:.55">\u25be</span> ${esc(t('discover.network'))}
        </button>
        <div id="dResolve" class="hidden" style="font-size:.86rem;color:var(--muted);margin-top:.55rem">${esc(t('discover.resolve.idle'))}</div>
      </div>

      ${SEP}

      <div style="${SP_SM}">
        <div style="display:flex;flex-wrap:wrap;gap:.4rem;align-items:center">
          <button type="button" class="btn btn-secondary btn-sm" id="dActMsg">${esc(t('discover.msg.send'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" id="dPing">${esc(t('discover.ping'))}</button>
          <span id="dPingOut" class="muted" style="font-size:.85rem"></span>
        </div>
        <div id="dMsgPanel" class="hidden" style="margin-top:.5rem;padding-top:.5rem;border-top:1px solid var(--border,#e5e7eb)">
          ${msgFormHtml}
        </div>
      </div>

    </div>`;

  if (isStale?.()) return;
  mount.appendChild(wrap);

  /* ── Element refs ──────────────────────────────────────── */
  const tabAid      = wrap.querySelector('#tabAid');
  const tabSvc      = wrap.querySelector('#tabSvc');
  const tabFavEl    = wrap.querySelector('#tabFav');
  const aidInput    = wrap.querySelector('#dAid');
  const myAg        = wrap.querySelector('#dMyAg');
  const opArea      = wrap.querySelector('#dOp');
  const opAidEl     = wrap.querySelector('#dOpAid');
  const opAliasEl   = wrap.querySelector('#dOpAlias');
  const targetProfileBox = wrap.querySelector('#dTargetProfile');
  const statusBadge = wrap.querySelector('#dStatusBadge');
  const resolveBox  = wrap.querySelector('#dResolve');
  const profileBox  = wrap.querySelector('#dProfile');
  const localSvcBox = wrap.querySelector('#dLocalSvc');
  const queryStrip  = wrap.querySelector('#dQueryStrip');
  const dCardOut    = wrap.querySelector('#dCardOut');
  const actionOut   = wrap.querySelector('#dActionOut');
  const cacheBtn    = wrap.querySelector('#dCacheBtn');
  const cacheChev   = wrap.querySelector('#dCacheChevron');
  const cardChev    = wrap.querySelector('#dCardChevron');
  const networkBtn  = wrap.querySelector('#dNetworkBtn');
  const networkChev = wrap.querySelector('#dNetworkChevron');
  const tunnelBtn   = wrap.querySelector('#dTunnel');
  const oneshotBtn  = wrap.querySelector('#dOneshot');
  const reqBtn      = wrap.querySelector('#dShowReq');
  const aidproxyBtn = wrap.querySelector('#dAidProxy');
  const aidErr      = wrap.querySelector('#dAidErr');
  const svcOut      = wrap.querySelector('#dSvcOut');
  const q           = wrap.querySelector('#dq');
  const cat         = wrap.querySelector('#dqCat');

  let currentAid      = '';
  let queryGen        = 0;
  let currentTunnelId = null;
  let oneshotTimer    = null;
  let cardFetched     = false;
  let activeActionBtn = null;
  let msgBtnActive    = false;
  let lastServices    = [];
  let lastProfile     = null;
  const favTunnels    = new Map();

  wrap.addEventListener('click', (ev) => {
    const el = ev.target.closest('.aid-expand');
    if (el) toggleAidExpand(el);
  });

  function queryStale(gen) {
    return gen !== queryGen || isStale?.();
  }

  function setQuerying(on) {
    queryStrip.classList.toggle('hidden', !on);
  }

  let favSortBy  = 'addedAt';
  let favSortAsc = false;

  const msgFromEl = wrap.querySelector('#dMsgFrom');
  if (agents.length === 1 && msgFromEl) msgFromEl.value = agents[0].aid;

  /* ── Category quick-fill ───────────────────────────────── */
  for (const c of QUICK) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-secondary btn-sm';
    b.textContent = c + '.';
    b.onclick = () => {
      q.value = (q.value || '').trim() ? `${c}.${q.value.replace(/^\w+\./, '')}` : `${c}.`;
      q.focus();
    };
    cat.appendChild(b);
  }

  /* ── Tab switching ─────────────────────────────────────── */
  function switchTab(which) {
    wrap.querySelectorAll('.discover-tabs button').forEach((btn) => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === which);
    });
    tabAid.classList.toggle('hidden', which !== 'aid');
    tabSvc.classList.toggle('hidden', which !== 'svc');
    tabFavEl.classList.toggle('hidden', which !== 'fav');
    // Hide AID query results when on favorites tab, restore when switching back
    if (which === 'fav') {
      opArea.classList.add('hidden');
    } else if (currentAid) {
      opArea.classList.remove('hidden');
    }
    if (which === 'fav') renderFavList();
  }
  wrap.querySelectorAll('.discover-tabs button').forEach((btn) => {
    btn.onclick = () => switchTab(btn.getAttribute('data-tab'));
  });

  myAg.onchange = () => { if (myAg.value) aidInput.value = myAg.value; };

  /* ── Action button state ───────────────────────────────── */
  const allActionBtns = [tunnelBtn, oneshotBtn, reqBtn, aidproxyBtn];

  function deactivateActions() {
    allActionBtns.forEach((b) => { b.classList.remove('btn-primary'); b.classList.add('btn-secondary'); });
    activeActionBtn = null;
    actionOut.classList.add('hidden');
    actionOut.innerHTML = '';
  }

  function activateAction(btn) {
    if (activeActionBtn === btn) { deactivateActions(); return false; }
    allActionBtns.forEach((b) => { b.classList.remove('btn-primary'); b.classList.add('btn-secondary'); });
    btn.classList.remove('btn-secondary');
    btn.classList.add('btn-primary');
    activeActionBtn = btn;
    actionOut.classList.remove('hidden');
    actionOut.innerHTML = '';
    return true;
  }

  /* ── Helpers ───────────────────────────────────────────── */
  const TUNNEL_PORT_KEY = 'a2al.tunnelLocalPort';

  function aidKey(aid) {
    return String(aid || '').toLowerCase();
  }

  function loadPortMap() {
    try {
      const raw = localStorage.getItem(TUNNEL_PORT_KEY);
      if (!raw || raw[0] !== '{') {
        if (raw) localStorage.removeItem(TUNNEL_PORT_KEY);
        return {};
      }
      const obj = JSON.parse(raw);
      return obj && typeof obj === 'object' ? obj : {};
    } catch (_) {
      return {};
    }
  }

  function savedTunnelPort(remoteAid) {
    const n = Number(loadPortMap()[aidKey(remoteAid)]);
    return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : 0;
  }

  function setSavedTunnelPort(remoteAid, port) {
    const m = loadPortMap();
    const k = aidKey(remoteAid);
    if (!port) delete m[k];
    else m[k] = port;
    if (Object.keys(m).length === 0) localStorage.removeItem(TUNNEL_PORT_KEY);
    else localStorage.setItem(TUNNEL_PORT_KEY, JSON.stringify(m));
  }

  function listenPortOf(listen) {
    const i = String(listen || '').lastIndexOf(':');
    if (i < 0) return 0;
    const n = Number(listen.slice(i + 1));
    return Number.isInteger(n) ? n : 0;
  }

  function tunnelPortControls(btnClass, remoteAid) {
    const saved = savedTunnelPort(remoteAid);
    const label = saved ? t('discover.tunnel.port_edit') : t('discover.tunnel.port_modify');
    return `<input type="text" inputmode="numeric" data-tunnel-port class="${saved ? '' : 'hidden'}" placeholder="${esc(t('discover.tunnel.port_ph'))}" value="${saved ? esc(String(saved)) : ''}" disabled style="width:6.5rem" />
      <button type="button" class="btn btn-ghost ${btnClass}" data-tunnel-port-btn>${esc(label)}</button>`;
  }

  function bindTunnelPortEditor(root, remoteAid) {
    const input = root.querySelector('[data-tunnel-port]');
    const btn = root.querySelector('[data-tunnel-port-btn]');
    if (!input || !btn) return;
    let editing = false;
    const showIdle = () => {
      editing = false;
      const saved = savedTunnelPort(remoteAid);
      input.disabled = true;
      if (!saved) {
        input.value = '';
        input.classList.add('hidden');
        btn.textContent = t('discover.tunnel.port_modify');
        return;
      }
      input.value = String(saved);
      input.classList.remove('hidden');
      btn.textContent = t('discover.tunnel.port_edit');
    };
    btn.onclick = () => {
      if (!editing) {
        editing = true;
        input.classList.remove('hidden');
        input.disabled = false;
        btn.textContent = t('discover.tunnel.port_save');
        input.focus();
        return;
      }
      const raw = input.value.trim();
      if (raw === '') {
        setSavedTunnelPort(remoteAid, 0);
        toast(t('discover.tunnel.port_cleared'), 'ok');
        showIdle();
        return;
      }
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 1 || n > 65535) {
        toast(t('discover.tunnel.port_invalid'), 'warn');
        return;
      }
      setSavedTunnelPort(remoteAid, n);
      toast(t('discover.tunnel.port_saved'), 'ok');
      showIdle();
    };
  }

  function bindPortRandom(root, remoteAid, retry) {
    const btn = root.querySelector('[data-port-random]');
    if (!btn) return;
    btn.onclick = () => {
      setSavedTunnelPort(remoteAid, 0);
      retry();
    };
  }

  async function findOrOpenTunnel(remoteAid, token) {
    let port = savedTunnelPort(remoteAid);
    if (!port) {
      try {
        const aidNorm = remoteAid.toLowerCase();
        const { tunnels = [] } = await api('/tunnel');
        const existing = tunnels.find((t) => (t.remote_aid || '').toLowerCase() === aidNorm);
        const n = listenPortOf(existing && existing.listen);
        if (n) port = n;
      } catch (_) {}
    }
    const body = {};
    if (token) body.access_token = token;
    if (port) body.local_port = port;
    try {
      return await api(`/tunnel/${encodeURIComponent(remoteAid)}`, { method: 'POST', body: JSON.stringify(body) });
    } catch (e) {
      if (port) e.localPort = port;
      throw e;
    }
  }

  function fmtEndpoints(ep) {
    if (ep == null) return '—';
    if (Array.isArray(ep)) return esc(ep.map(String).join(', ')) || '—';
    return esc(String(ep));
  }

  function dot(color) {
    return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${color};flex-shrink:0"></span>`;
  }

  function setStatus(pingOk, ttlValid, lastSeenStr, noteTitle = '', noteHint = '') {
    statusBadge.classList.remove('hidden');
    let dotColor, label, labelColor;
    if (pingOk === null) {
      dotColor = '#d1d5db'; label = t('discover.status.checking'); labelColor = 'var(--muted)';
    } else if (!pingOk) {
      dotColor = '#9ca3af'; label = t('discover.status.offline'); labelColor = 'var(--muted)';
    } else if (ttlValid) {
      dotColor = 'var(--success,#16a34a)'; label = t('discover.status.online'); labelColor = 'var(--success,#16a34a)';
    } else {
      dotColor = '#d97706'; label = t('discover.status.expired'); labelColor = '#d97706';
    }
    const onlineHtml = `<span style="display:inline-flex;align-items:center;gap:.28rem">${dot(dotColor)}<span style="color:${labelColor}">${esc(label)}</span></span>`;
    const seenHtml = lastSeenStr
      ? `<span class="muted" style="border-left:1px solid var(--border,#e5e7eb);padding-left:.55rem">${esc(t('discover.last_seen'))} ${esc(lastSeenStr)}</span>`
      : '';
    const noteHtml = noteTitle
      ? `<div style="font-size:.8rem;line-height:1.35"><div style="color:var(--error,#dc2626)">${esc(noteTitle)}</div>${noteHint ? `<div class="muted">${esc(noteHint)}</div>` : ''}</div>`
      : '';
    statusBadge.innerHTML = `<div style="display:flex;align-items:center;justify-content:flex-end;gap:.55rem;flex-wrap:wrap">${onlineHtml}${seenHtml}</div>${noteHtml}`;
  }

  function renderTargetIdentity(aid, profile) {
    const faved = isFaved(aid);
    const alias = faved ? (aliasOf(aid) || ensureAlias(aid)) : '';
    opAliasEl.classList.toggle('hidden', !alias);
    opAliasEl.textContent = alias;
    opAidEl.textContent = shortAid(aid);

    const name = profile?.name || '';
    const brief = profile?.brief || '';
    if (!name && !brief) {
      targetProfileBox.classList.add('hidden');
      targetProfileBox.innerHTML = '';
      return;
    }
    targetProfileBox.classList.remove('hidden');
    targetProfileBox.innerHTML = `
      ${name ? `<div style="font-weight:600;font-size:.94rem">${esc(name)}</div>` : ''}
      ${brief ? `<div class="muted" style="font-size:.86rem;line-height:1.5;margin-top:.12rem">${esc(brief)}</div>` : ''}`;
  }

  /* ── Star button ───────────────────────────────────────── */
  function updateStar(aid) {
    const btn = wrap.querySelector('#dOpStar');
    if (!btn) return;
    const faved = isFaved(aid);
    btn.innerHTML = faved ? `\u2605 ${esc(t('discover.fav.starred'))}` : `\u2606 ${esc(t('discover.fav.star'))}`;
    btn.style.color = faved ? '#d97706' : '';
    btn.onclick = () => {
      if (isFaved(aid)) return;
      const skill = (lastProfile?.skills || [])[0] || lastServices[0]?.topic || '';
      const protocols = lastProfile?.protocols || lastServices[0]?.protocols || [];
      addFav(aid, null, skill, protocols);
      updateStar(aid);
      renderTargetIdentity(aid, lastProfile);
      renderFavList();
      toast(t('discover.fav.toast_added'), 'ok');
    };
  }

  /* ── Capability rendering ──────────────────────────────── */
  // services: full detail from local registry (own agents only).
  // profile: the resolved AgentProfilePayload (works for any AID, self-declared preview).
  function renderCapabilities(services, profile) {
    if (services && services.length) {
      profileBox.innerHTML = services.map((svc) => `<div style="${SVC_CARD_STYLE}">${svcCardHtml(svc)}</div>`).join('');
      return;
    }
    const skills = profile?.skills || [];
    if (!skills.length) {
      profileBox.innerHTML = `<p class="muted" style="margin:.1rem 0;font-size:.87rem">${esc(t('discover.profile.none'))}</p>`;
      return;
    }
    const protocols  = profile?.protocols || [];
    const modalities = profile?.modalities || [];
    const meta       = metaSummary(profile?.meta);
    profileBox.innerHTML = `
      <div style="display:flex;flex-wrap:wrap;gap:.3rem .5rem;align-items:center">
        ${skills.map((s) => `<span class="svc-name">${esc(s)}</span>`).join('')}
      </div>
      ${protocols.length ? `<div style="margin-top:.4rem;display:flex;flex-wrap:wrap;gap:.3rem;align-items:center">
        <span class="muted" style="font-size:.78rem">${esc(t('discover.profile.protocols'))}</span>
        ${protocols.map((p) => `<span class="badge b-blue" style="font-size:.78rem">${esc(p)}</span>`).join('')}
      </div>` : ''}
      ${modalities.length ? `<div style="margin-top:.3rem;display:flex;flex-wrap:wrap;gap:.3rem;align-items:center">
        <span class="muted" style="font-size:.78rem">${esc(t('discover.profile.modalities'))}</span>
        ${modalities.map((m) => `<span class="badge b-gray" style="font-size:.78rem">${esc(m)}</span>`).join('')}
      </div>` : ''}
      ${meta ? `<div class="muted" style="font-size:.78rem;margin-top:.35rem">${meta}</div>` : ''}
      <button type="button" class="btn btn-secondary btn-sm" id="dCapDetailBtn" style="margin-top:.55rem">${esc(t('discover.capabilities.detail_btn'))}</button>
      <div id="dCapDetailOut" style="margin-top:.5rem"></div>`;
    const detailBtn = profileBox.querySelector('#dCapDetailBtn');
    const detailOut = profileBox.querySelector('#dCapDetailOut');
    detailBtn.onclick = () => fetchCapabilityDetail(skills, detailBtn, detailOut);
  }

  async function fetchCapabilityDetail(skills, btn, out) {
    setLoading(btn, true);
    out.innerHTML = `<p class="muted" style="font-size:.85rem">${esc(t('common.loading'))}</p>`;
    try {
      // One /discover call per skill: passing multiple services at once triggers an
      // AND-intersection search (host.SearchTopics), not a per-topic detail batch fetch,
      // and only keeps the first topic's fields. Querying individually preserves each
      // topic's own brief/tags/protocols.
      const results = await Promise.allSettled(
        skills.map((s) => api('/discover', { method: 'POST', body: JSON.stringify({ services: [s] }) })),
      );
      const target = currentAid.toLowerCase();
      const entries = [];
      for (const r of results) {
        if (r.status !== 'fulfilled') continue;
        for (const e of r.value.entries || []) {
          if ((e.aid || '').toLowerCase() === target) entries.push(e);
        }
      }
      out.innerHTML = entries.length
        ? entries.map((e) => `<div style="${SVC_CARD_STYLE}">${svcCardHtml(e)}</div>`).join('')
        : `<p class="muted" style="font-size:.85rem;margin:0">${esc(t('discover.capabilities.detail_empty'))}</p>`;
    } catch (_) {
      out.innerHTML = `<p style="color:var(--error);font-size:.85rem;margin:0">${esc(t('discover.capabilities.detail_failed'))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  }

  function renderLocalServices(list) {
    if (!list || !list.length) {
      localSvcBox.innerHTML = `<p class="muted" style="margin:0;font-size:.86rem">${esc(t('discover.cache_empty'))}</p>`;
      return;
    }
    localSvcBox.innerHTML = list.map((svc) => `<div style="${SVC_CARD_STYLE}">${svcCardHtml(svc)}</div>`).join('');
  }

  /* ── 本机缓存 / Agent Card mutual exclusion ───────────── */
  networkBtn.onclick = () => {
    const willOpen = resolveBox.classList.contains('hidden');
    resolveBox.classList.toggle('hidden', !willOpen);
    networkChev.textContent = willOpen ? '\u25b4' : '\u25be';
  };

  cacheBtn.onclick = () => {
    const willOpen = localSvcBox.classList.contains('hidden');
    if (willOpen) { dCardOut.classList.add('hidden'); cardChev.textContent = '\u25be'; }
    localSvcBox.classList.toggle('hidden', !willOpen);
    cacheChev.textContent = willOpen ? '\u25b4' : '\u25be';
  };

  wrap.querySelector('#dCard').onclick = async (ev) => {
    if (!currentAid) return;
    const willOpen = dCardOut.classList.contains('hidden');
    if (willOpen) { localSvcBox.classList.add('hidden'); cacheChev.textContent = '\u25be'; }
    dCardOut.classList.toggle('hidden', !willOpen);
    cardChev.textContent = willOpen ? '\u25b4' : '\u25be';
    if (!willOpen || cardFetched) return;
    const b = ev.currentTarget;
    setLoading(b, true);
    dCardOut.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('discover.card.fetching'))}</p>`;
    try {
      const got = await fetchAgentCard(api, currentAid);
      cardFetched = true;
      if (!got) { dCardOut.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('discover.card_failed'))}</p>`; return; }
      const p = parseCard(got.json);
      dCardOut.innerHTML = `
        <div style="font-size:.77rem;color:var(--muted);margin-bottom:.3rem">${esc(got.path)}</div>
        <div style="font-size:.86rem;display:grid;grid-template-columns:auto 1fr;gap:.2rem .65rem;align-items:baseline">
          <span class="muted">${esc(t('discover.detail.card.name'))}</span><span>${esc(p.name)}</span>
          <span class="muted">${esc(t('discover.detail.card.ver'))}</span><span>${esc(p.version)}</span>
          ${p.caps   ? `<span class="muted">${esc(t('discover.detail.card.caps'))}</span><span>${esc(p.caps)}</span>` : ''}
          ${p.tools.length ? `<span class="muted">${esc(t('discover.detail.card.tools'))}</span><span>${esc(p.tools.join(', '))}</span>` : ''}
        </div>
        ${p.url ? `<div style="margin-top:.35rem"><a href="${esc(p.url)}" target="_blank" rel="noopener" style="font-size:.85rem">${esc(p.url)}</a></div>` : ''}`;
    } catch (e) {
      dCardOut.innerHTML = `<p style="color:var(--error);margin:0;font-size:.86rem">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(b, false);
    }
  };

  /* ── Profile / services (async, does not block network info) ── */
  async function loadProfileAndServices(aid, gen) {
    try {
      const [profRes, agRes] = await Promise.allSettled([
        api(`/resolve/${encodeURIComponent(aid)}/records?type=2`),
        api(`/agents/${encodeURIComponent(aid)}`),
      ]);
      if (queryStale(gen)) return;

      lastServices = agRes.status === 'fulfilled' ? (agRes.value.services || []) : [];
      renderLocalServices(lastServices);

      const records = profRes.status === 'fulfilled' ? (profRes.value.records || []) : [];
      const profRecord = Array.isArray(records) ? records.find((r) => r.profile) : null;
      lastProfile = profRecord ? profRecord.profile : null;
      renderTargetIdentity(currentAid, lastProfile);
      renderCapabilities(lastServices, lastProfile);
      updateStar(currentAid);
    } catch (_) {
      if (queryStale(gen)) return;
      lastServices = [];
      lastProfile = null;
      renderTargetIdentity(currentAid, null);
      renderCapabilities([]);
    }
  }

  /* ── runQuery ──────────────────────────────────────────── */
  async function runQuery() {
    const raw = aidInput.value.trim();
    aidErr.classList.add('hidden');
    if (!raw) { aidErr.textContent = t('discover.aid.required'); aidErr.classList.remove('hidden'); return; }
    const gen = ++queryGen;
    currentAid = raw;
    lastServices = [];
    lastProfile = null;
    opArea.classList.remove('hidden');
    renderTargetIdentity(currentAid, null);
    wrap.querySelector('#dOpCp').onclick = () => copyText(currentAid);
    updateStar(currentAid);

    setQuerying(true);
    setStatus(null, false, null);
    profileBox.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('common.loading'))}</p>`;
    localSvcBox.innerHTML = '';
    localSvcBox.classList.add('hidden');
    cacheChev.textContent = '\u25be';
    dCardOut.innerHTML = '';
    dCardOut.classList.add('hidden');
    cardChev.textContent = '\u25be';
    cardFetched = false;
    resolveBox.style.color = 'var(--muted)';
    resolveBox.textContent = t('common.loading');
    resolveBox.classList.add('hidden');
    networkChev.textContent = '\u25be';
    wrap.querySelector('#dPingOut').textContent = '';
    if (oneshotTimer) { clearInterval(oneshotTimer); oneshotTimer = null; }
    if (currentTunnelId) {
      api(`/tunnel/${encodeURIComponent(currentTunnelId)}`, { method: 'DELETE' }).catch(() => {});
      currentTunnelId = null;
    }
    deactivateActions();
    wrap.querySelector('#dMsgPanel').classList.add('hidden');
    msgBtnActive = false;

    let resRes;
    try {
      resRes = { status: 'fulfilled', value: await api(`/resolve/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' }) };
    } catch (reason) {
      resRes = { status: 'rejected', reason };
    }
    if (queryStale(gen)) return;

    let ttlValid = false;
    let lastSeenStr = null;
    if (resRes.status === 'fulfilled') {
      setQuerying(false);
      const r = resRes.value;
      const nowS = Math.floor(Date.now() / 1000);
      ttlValid = !!(r.timestamp && r.ttl && (r.timestamp + r.ttl > nowS));
      lastSeenStr = fmtShortDT(r.timestamp);
      resolveBox.style.color = '';
      resolveBox.innerHTML = `
        <div style="display:grid;grid-template-columns:auto 1fr;gap:.2rem .8rem;align-items:baseline">
          <span class="muted">${esc(t('discover.resolve.net_addr'))}</span>
          <span>${fmtEndpoints(r.endpoints)}</span>
          <span class="muted">${esc(t('discover.resolve.net_type'))}</span>
          <span>${esc(natLabel(t, r.nat_type))}</span>
          <span class="muted">${esc(t('discover.resolve.revision'))} / ${esc(t('discover.resolve.ttl'))}</span>
          <span>${esc(String(r.seq ?? '—'))} / ${esc(String(r.ttl ?? '—'))} s</span>
          <span class="muted">${esc(t('discover.last_seen'))}</span>
          <span>${esc(lastSeenStr)}</span>
        </div>`;
      setStatus(null, ttlValid, lastSeenStr);
      api(`/connect/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' })
        .then(() => { if (!queryStale(gen)) setStatus(true, ttlValid, lastSeenStr); })
        .catch((e) => { if (!queryStale(gen)) setStatus(e.status === 412 || isAccessDenied(e) ? true : false, ttlValid, lastSeenStr); });
      loadProfileAndServices(currentAid, gen);
    } else {
      setQuerying(false);
      resolveBox.style.color = 'var(--error)';
      resolveBox.innerHTML = `<p style="margin:0">${esc(t('discover.resolve.unavailable'))}</p><p class="muted" style="margin:.2rem 0 0;font-size:.83rem">${esc(t('discover.resolve.unavailable_hint'))}</p>`;
      setStatus(false, false, null, t('discover.resolve.unavailable'), t('discover.resolve.unavailable_hint'));
      renderTargetIdentity(currentAid, null);
      renderCapabilities([]);
    }
  }

  wrap.querySelector('#dQuery').onclick = runQuery;
  aidInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runQuery(); });

  /* ── Tools: message ────────────────────────────────────── */
  wrap.querySelector('#dActMsg').onclick = () => {
    msgBtnActive = !msgBtnActive;
    wrap.querySelector('#dMsgPanel').classList.toggle('hidden', !msgBtnActive);
    const b = wrap.querySelector('#dActMsg');
    b.classList.toggle('btn-primary', msgBtnActive);
    b.classList.toggle('btn-secondary', !msgBtnActive);
  };

  const dMsgGo = wrap.querySelector('#dMsgGo');
  if (dMsgGo) {
    dMsgGo.onclick = async (ev) => {
      if (!currentAid) return;
      const from = wrap.querySelector('#dMsgFrom')?.value;
      if (!from) { toast(t('discover.msg.need_from'), 'warn'); return; }
      const txt = wrap.querySelector('#dMsgTxt')?.value;
      if (!txt) return;
      setLoading(ev.currentTarget, true);
      try {
        await api(`/agents/${encodeURIComponent(from)}/mailbox/send`, {
          method: 'POST',
          body: JSON.stringify({ recipient: currentAid, msg_type: 3, body_base64: utf8ToBase64(txt) }),
        });
        toast(t('common.sent'), 'ok');
        const inp = wrap.querySelector('#dMsgTxt');
        if (inp) inp.value = '';
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(ev.currentTarget, false);
      }
    };
  }

  /* ── Tools: ping ───────────────────────────────────────── */
  wrap.querySelector('#dPing').onclick = async (ev) => {
    if (!currentAid) return;
    const btn = ev.currentTarget;
    const el = wrap.querySelector('#dPingOut');
    setLoading(btn, true);
    el.style.color = '';
    el.textContent = t('common.loading');
    const t0 = performance.now();
    try {
      await api(`/connect/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' });
      el.textContent = t('discover.ping.ok', { ms: Math.round(performance.now() - t0) });
      el.style.color = 'var(--success)';
    } catch (e) {
      if (isAccessDenied(e)) {
        el.textContent = t('discover.ping.ok', { ms: Math.round(performance.now() - t0) });
        el.style.color = 'var(--success)';
      } else {
        el.textContent = e.status === 412 ? t('connect.no_direct_path') : t('connect.peer_offline');
        el.style.color = 'var(--error)';
      }
    } finally {
      setLoading(btn, false);
    }
  };

  function paintMainTunnel(tr, onDeniedRetry) {
    if (tr.allowed === false) {
      currentTunnelId = null;
      actionOut.innerHTML = `
      <p style="color:var(--success);margin:0 0 .35rem;font-size:.9rem">${esc(t('discover.tunnel.connected'))}</p>
      ${accessRetryHTML(t, nodeAid)}`;
      bindAccessRetry(actionOut, { status: 403 }, onDeniedRetry);
      return;
    }
    currentTunnelId = tr.id;
    const relayBadge = tr.is_relayed ? `<span class="badge b-yellow" style="font-size:.75rem">${esc(t('tunnel.relayed'))}</span>` : '';
    actionOut.innerHTML = `
      <p style="color:var(--success);margin:0 0 .35rem;font-size:.9rem">${esc(t('discover.tunnel.ok'))} ${relayBadge}</p>
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.4rem">
        <code class="mono" style="font-size:.87rem">${esc(tr.listen)}</code>
        <button type="button" class="btn btn-ghost btn-sm" id="dTunnelCp">\u29c9</button>
        ${tunnelPortControls('btn-sm', currentAid)}
        <button type="button" class="btn btn-ghost btn-sm" id="dTunnelClose">${esc(t('discover.tunnel.close'))}</button>
        <button type="button" class="btn btn-ghost btn-sm" id="dTunnelReset">${esc(t('discover.tunnel.reset'))}</button>
      </div>
      <div style="display:flex;gap:.4rem;flex-wrap:wrap;align-items:center">
        <button type="button" class="btn btn-secondary btn-sm" id="dTunnelOpen">${esc(t('discover.tunnel.open'))}</button>
        ${tr.https_url ? `<button type="button" class="btn btn-ghost btn-sm" id="dTunnelOpenHttps">${esc(t('discover.tunnel.open_https'))}</button><span class="muted" style="font-size:.79rem">${esc(t('discover.tunnel.open_hint'))}</span>` : ''}
      </div>`;
    actionOut.querySelector('#dTunnelCp').onclick = () => copyText(tr.listen);
    bindTunnelPortEditor(actionOut, currentAid);
    actionOut.querySelector('#dTunnelOpen').onclick = () => window.open('http://' + tr.listen, '_blank', 'noopener');
    if (tr.https_url) actionOut.querySelector('#dTunnelOpenHttps').onclick = () => window.open(tr.https_url, '_blank', 'noopener');
    actionOut.querySelector('#dTunnelClose').onclick = async () => {
      if (!currentTunnelId) return;
      try { await api(`/tunnel/${encodeURIComponent(currentTunnelId)}`, { method: 'DELETE' }); } catch (_) {}
      currentTunnelId = null;
      actionOut.innerHTML = `<p class="muted" style="margin:0">${esc(t('discover.tunnel.closed'))}</p>`;
      deactivateActions();
    };
    actionOut.querySelector('#dTunnelReset').onclick = async () => {
      if (!currentTunnelId) return;
      try {
        await api(`/tunnel/${encodeURIComponent(currentTunnelId)}/reset`, { method: 'POST', body: '{}' });
        currentTunnelId = null;
        actionOut.innerHTML = `<p class="muted" style="margin:0">${esc(t('discover.tunnel.reset_ok'))}</p>`;
        deactivateActions();
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      }
    };
  }

  async function runMainTunnel(btn, token) {
    setLoading(btn, true);
    actionOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    try {
      paintMainTunnel(await findOrOpenTunnel(currentAid, token), (tok) => runMainTunnel(btn, tok));
    } catch (e) {
      actionOut.innerHTML = actionFailHTML(e, t, nodeAid, { port: e.localPort || savedTunnelPort(currentAid) });
      bindAccessRetry(actionOut, e, (tok) => runMainTunnel(btn, tok));
      bindPortRandom(actionOut, currentAid, () => runMainTunnel(btn));
    } finally {
      setLoading(btn, false);
    }
  }

  /* ── Business: tunnel ──────────────────────────────────── */
  tunnelBtn.onclick = async (ev) => {
    if (!currentAid) return;
    if (!activateAction(tunnelBtn)) return;
    await runMainTunnel(ev.currentTarget);
  };

  async function runOneshot(btn, token) {
    setLoading(btn, true);
    actionOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    if (oneshotTimer) { clearInterval(oneshotTimer); oneshotTimer = null; }
    try {
      const cr = await api(`/connect/${encodeURIComponent(currentAid)}`, { method: 'POST', body: JSON.stringify(token ? { access_token: token } : {}) });
      if (cr.allowed === false) {
        actionOut.innerHTML = `
        <p style="color:var(--success);margin:0 0 .35rem;font-size:.9rem">${esc(t('discover.tunnel.connected'))}</p>
        ${accessRetryHTML(t, nodeAid)}`;
        bindAccessRetry(actionOut, { status: 403 }, (tok) => runOneshot(btn, tok));
        return;
      }
      let remaining = 30;
      actionOut.innerHTML = `
        <p style="color:var(--success);margin:0 0 .2rem;font-size:.9rem">${esc(t('discover.oneshot.ok'))}</p>
        <p class="muted" style="margin:0 0 .4rem;font-size:.82rem">${esc(t('discover.oneshot.hint'))}</p>
        <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.25rem">
          <code class="mono" style="font-size:.87rem">${esc(cr.tunnel)}</code>
          <button type="button" class="btn btn-ghost btn-sm" id="dOneshotCp">\u29c9</button>
        </div>
        <p class="muted" style="font-size:.79rem;margin:0" id="dOneshotCountdown">${esc(t('discover.oneshot.countdown', { n: remaining }))}</p>`;
      actionOut.querySelector('#dOneshotCp').onclick = () => copyText(cr.tunnel);
      oneshotTimer = setInterval(() => {
        remaining--;
        const cd = actionOut.querySelector('#dOneshotCountdown');
        if (remaining <= 0) {
          clearInterval(oneshotTimer); oneshotTimer = null;
          actionOut.innerHTML = `<p class="muted" style="margin:0">${esc(t('discover.oneshot.expired'))}</p>`;
          deactivateActions(); return;
        }
        if (cd) cd.textContent = t('discover.oneshot.countdown', { n: remaining });
      }, 1000);
    } catch (e) {
      actionOut.innerHTML = actionFailHTML(e, t, nodeAid);
      bindAccessRetry(actionOut, e, (tok) => runOneshot(btn, tok));
    } finally {
      setLoading(btn, false);
    }
  }
  oneshotBtn.onclick = async (ev) => {
    if (!currentAid) return;
    if (!activateAction(oneshotBtn)) return;
    await runOneshot(ev.currentTarget);
  };

  /* ── Business: AID direct ──────────────────────────────── */
  aidproxyBtn.onclick = () => {
    if (!currentAid) return;
    if (!activateAction(aidproxyBtn)) return;
    const url = `${window.location.origin}/aid/${encodeURIComponent(currentAid)}/`;
    actionOut.innerHTML = `
      <div class="muted" style="font-size:.79rem;margin-bottom:.25rem">${esc(t('discover.aidproxy.label'))}</div>
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.2rem">
        <a class="mono" href="${esc(url)}" target="_blank" rel="noopener" style="font-size:.86rem">${esc(url)}</a>
        <button type="button" class="btn btn-ghost btn-sm" id="dAidProxyCp">\u29c9</button>
      </div>
      <p class="muted" style="font-size:.79rem;margin:0">${esc(t('discover.aidproxy.hint'))}</p>`;
    actionOut.querySelector('#dAidProxyCp').onclick = () => copyText(url);
  };

  /* ── Business: request ─────────────────────────────────── */
  function mountReq() {
    actionOut.innerHTML = `
      <div style="font-size:.9rem;font-weight:600;margin-bottom:.2rem">${esc(t('discover.req.title'))}</div>
      <p class="muted" style="font-size:.79rem;margin:0 0 .5rem">&#128274; ${esc(t('discover.req.encrypted'))}</p>
      <div class="field">
        <label>${esc(t('discover.req.identity'))}</label>
        <select id="rqAid"><option value="">${esc(t('discover.req.node_identity'))}</option>${agents.map((a) =>
          `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}</select>
      </div>
      <div class="field" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
        <select id="rqM"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select>
        <input type="text" id="rqP" style="flex:1;min-width:8rem" placeholder="/" value="/" />
        <button type="button" class="btn btn-primary" id="rqGo">${esc(t('discover.req.send'))}</button>
      </div>
      <div class="muted" style="font-size:.78rem;margin-top:-.1rem;margin-bottom:.35rem" id="rqProxyUrl"></div>
      <div class="field hidden" id="rqBodyW">
        <label>${esc(t('discover.req.body'))}</label>
        <textarea id="rqB" rows="3" style="width:100%" class="mono"></textarea>
      </div>
      <div style="font-size:.87rem;font-weight:600;margin-bottom:.2rem">${esc(t('discover.req.response'))}</div>
      <pre class="resp" id="rqOut"></pre>
      <div class="muted" id="rqMeta"></div>`;
    const m = actionOut.querySelector('#rqM');
    const bw = actionOut.querySelector('#rqBodyW');
    const proxyHintEl = actionOut.querySelector('#rqProxyUrl');
    const updateProxyHint = () => {
      const path = actionOut.querySelector('#rqP').value || '/';
      const url = `${window.location.origin}/aid/${encodeURIComponent(currentAid)}${path.startsWith('/') ? '' : '/'}${path}`;
      proxyHintEl.innerHTML = `${esc(t('discover.req.proxy_hint'))} <a href="${esc(url)}" target="_blank" rel="noopener" class="mono" style="font-size:.83em">${esc(url)}</a>`;
    };
    actionOut.querySelector('#rqP').addEventListener('input', updateProxyHint);
    updateProxyHint();
    m.onchange = () => bw.classList.toggle('hidden', !['POST', 'PUT', 'PATCH'].includes(m.value));
    async function sendReq(token) {
      if (!currentAid) return;
      const btn = actionOut.querySelector('#rqGo');
      setLoading(btn, true);
      const path = actionOut.querySelector('#rqP').value.trim() || '/';
      const method = m.value;
      const localAid = actionOut.querySelector('#rqAid').value;
      const t0 = performance.now();
      try {
        const fetchBody = { method, path };
        if (localAid) fetchBody.local_aid = localAid;
        if (token) fetchBody.access_token = token;
        if (['POST', 'PUT', 'PATCH'].includes(method)) {
          fetchBody.body_base64 = utf8ToBase64(actionOut.querySelector('#rqB').value || '{}');
          fetchBody.headers = { 'Content-Type': ['application/json'] };
        }
        const r = await api(`/fetch/${encodeURIComponent(currentAid)}`, {
          method: 'POST', body: JSON.stringify(fetchBody),
        });
        const text = base64ToUtf8(r.body);
        let disp = text;
        try { disp = JSON.stringify(JSON.parse(text), null, 2); } catch (_) {}
        actionOut.querySelector('#rqOut').textContent = disp || '(empty)';
        const statusColor = r.status < 300 ? 'var(--success)' : r.status < 500 ? 'var(--warn,#c07800)' : 'var(--error)';
        const truncNote = r.truncated ? `  \u26a0 ${esc(t('discover.req.truncated'))}` : '';
        actionOut.querySelector('#rqMeta').innerHTML =
          `<span style="color:${statusColor};font-weight:600">${r.status}</span>  &bull;  ${Math.round(performance.now() - t0)} ms${truncNote}`;
      } catch (e) {
        actionOut.querySelector('#rqOut').textContent = isAccessDenied(e) ? t('connect.access_denied') : e.message;
        if (isAccessDenied(e)) {
          actionOut.querySelector('#rqMeta').innerHTML = actionFailHTML(e, t, localAid || nodeAid);
          bindAccessRetry(actionOut, e, (tok) => sendReq(tok));
        } else {
          actionOut.querySelector('#rqMeta').textContent = '';
        }
      } finally {
        setLoading(btn, false);
      }
    }
    actionOut.querySelector('#rqGo').onclick = () => sendReq();
  }
  reqBtn.onclick = () => { if (!currentAid) return; if (!activateAction(reqBtn)) return; mountReq(); };

  /* ── Favorites: sort controls ──────────────────────────── */
  const favSortAlias = wrap.querySelector('#dFavSortAlias');
  const favSortSkill = wrap.querySelector('#dFavSortSkill');
  const favSortTime  = wrap.querySelector('#dFavSortTime');
  const sortBtnMap   = { alias: favSortAlias, skill: favSortSkill, addedAt: favSortTime };
  const sortKeyNames = { alias: t('discover.fav.sort.alias'), skill: t('discover.fav.sort.skill'), addedAt: t('discover.fav.sort.time') };

  function updateSortBtns() {
    Object.entries(sortBtnMap).forEach(([key, btn]) => {
      const active = key === favSortBy;
      btn.classList.toggle('active', active);
      btn.textContent = sortKeyNames[key] + (active ? (favSortAsc ? ' \u2191' : ' \u2193') : '');
    });
  }

  Object.entries(sortBtnMap).forEach(([key, btn]) => {
    btn.onclick = () => {
      if (favSortBy === key) { favSortAsc = !favSortAsc; } else { favSortBy = key; favSortAsc = true; }
      updateSortBtns();
      renderFavList();
    };
  });

  /* ── Favorites: add form toggle ────────────────────────── */
  const dFavAddToggle = wrap.querySelector('#dFavAddToggle');
  const dFavAddForm   = wrap.querySelector('#dFavAddForm');
  const dFavAid       = wrap.querySelector('#dFavAid');
  const dFavAlias     = wrap.querySelector('#dFavAlias');
  const dFavSkill     = wrap.querySelector('#dFavSkill');
  const dFavProtos    = wrap.querySelector('#dFavProtos');
  const dFavFetch     = wrap.querySelector('#dFavFetch');
  const dFavAdd       = wrap.querySelector('#dFavAdd');

  dFavAddToggle.onclick = () => {
    const open = dFavAddForm.style.display !== 'none';
    dFavAddForm.style.display = open ? 'none' : '';
    dFavAddToggle.textContent = open ? `+ ${t('discover.fav.add_btn')}` : `\u2715 ${t('common.cancel')}`;
    dFavAddToggle.classList.toggle('btn-secondary', open);
    dFavAddToggle.classList.toggle('btn-ghost', !open);
    if (!open) dFavAid.focus();
  };

  dFavAid.addEventListener('input', () => {
    if (dFavAid.value.trim() && !dFavAlias.value.trim()) {
      dFavAlias.value = nextUniqueDefaultAlias();
    }
  });

  dFavFetch.onclick = async () => {
    const aid = dFavAid.value.trim();
    if (!aid) { dFavAid.focus(); return; }
    setLoading(dFavFetch, true);
    try {
      const [profRes, agRes] = await Promise.allSettled([
        api(`/resolve/${encodeURIComponent(aid)}/records?type=2`),
        api(`/agents/${encodeURIComponent(aid)}`),
      ]);
      let skill = '', protos = '';
      if (profRes.status === 'fulfilled') {
        const records = profRes.value.records || [];
        const prof = records.find((r) => r.profile)?.profile;
        if (prof) {
          skill = (prof.skills || [])[0] || '';
          protos = (prof.protocols || []).join(', ');
        }
      }
      if (!skill && agRes.status === 'fulfilled') {
        const svcs = agRes.value.services || [];
        if (svcs.length) { skill = svcs[0].topic || ''; protos = (svcs[0].protocols || []).join(', '); }
      }
      if (skill) dFavSkill.value = skill;
      if (protos) dFavProtos.value = protos;
      if (!skill && !protos) toast(t('discover.fav.fetch_empty'), 'warn');
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    } finally {
      setLoading(dFavFetch, false);
    }
  };

  dFavAdd.onclick = () => {
    const aid = dFavAid.value.trim();
    if (!aid) { dFavAid.focus(); return; }
    const alias = dFavAlias.value.trim() || nextUniqueDefaultAlias();
    const skill = dFavSkill.value.trim();
    const protocols = dFavProtos.value.split(',').map((s) => s.trim()).filter(Boolean);
    const result = addFav(aid, alias, skill, protocols);
    if (!result.added) { toast(t('discover.fav.dup'), 'warn'); return; }
    dFavAid.value = ''; dFavAlias.value = ''; dFavSkill.value = ''; dFavProtos.value = '';
    // Close the add form
    dFavAddForm.style.display = 'none';
    dFavAddToggle.textContent = `+ ${t('discover.fav.add_btn')}`;
    dFavAddToggle.classList.add('btn-secondary');
    dFavAddToggle.classList.remove('btn-ghost');
    renderFavList();
    updateStar(currentAid);
  };
  dFavAid.addEventListener('keydown', (e) => { if (e.key === 'Enter') dFavAdd.click(); });

  /* ── Favorites: list rendering ─────────────────────────── */
  function renderFavList() {
    const container = wrap.querySelector('#dFavList');
    if (!container) return;
    const list = loadFavs();
    container.innerHTML = '';
    if (list.length === 0) {
      container.innerHTML = `<p class="muted" style="font-size:.87rem;margin-top:.25rem">${esc(t('discover.fav.empty'))}</p>`;
      return;
    }
    list.sort((a, b) => {
      let av, bv;
      if (favSortBy === 'alias') { av = (aliasOf(a.aid) || '').toLowerCase(); bv = (aliasOf(b.aid) || '').toLowerCase(); }
      else if (favSortBy === 'skill') { av = (a.skill || '').toLowerCase(); bv = (b.skill || '').toLowerCase(); }
      else { av = a.addedAt || 0; bv = b.addedAt || 0; }
      if (av < bv) return favSortAsc ? -1 : 1;
      if (av > bv) return favSortAsc ? 1 : -1;
      return 0;
    });
    const card = document.createElement('div');
    card.className = 'card';
    card.style.overflow = 'hidden';
    list.forEach((fav, index) => card.appendChild(buildFavRow(fav, index)));
    container.appendChild(card);
  }

  /* Truncate text for compact badge display */
  function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max - 1) + '\u2026' : str;
  }

  function buildFavRow(fav, index) {
    const rowWrap = document.createElement('div');
    if (index > 0) rowWrap.style.borderTop = '1px solid var(--border,#e5e7eb)';
    if (index % 2 !== 0) rowWrap.style.background = 'var(--bg-subtle,#f9fafb)';

    const favAlias = aliasOf(fav.aid) || ensureAlias(fav.aid);
    const protos = (fav.protocols || []);
    const shownProtos = protos.slice(0, 2).map((p) =>
      `<span class="badge b-blue" style="font-size:.75rem;padding:.1rem .35rem">${esc(truncate(p, 10))}</span>`).join('');
    const moreProtos = protos.length > 2
      ? `<span class="muted" style="font-size:.75rem">+${protos.length - 2}</span>` : '';
    const skillBadge = fav.skill
      ? `<span class="badge b-gray" style="font-size:.75rem;padding:.1rem .35rem;max-width:9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle" title="${esc(fav.skill)}">${esc(truncate(fav.skill, 18))}</span>`
      : '';

    rowWrap.innerHTML = `
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;padding:.5rem .85rem">
        <div style="display:flex;align-items:center;gap:.22rem;min-width:5.5rem;flex-shrink:0">
          <span class="fav-alias-val" style="font-size:.9rem;font-weight:500">${esc(favAlias)}</span>
          <button type="button" class="btn btn-ghost btn-xs" data-alias-edit title="${esc(t('agent.alias.set'))}">&#9998;</button>
        </div>
        <span class="mono muted" style="font-size:.83rem;flex-shrink:0">${esc(shortAid(fav.aid))}</span>
        <button type="button" class="btn btn-ghost btn-xs" data-cp title="Copy AID">\u29c9</button>
        <div style="flex:1;min-width:0;display:flex;gap:.25rem;align-items:center;flex-wrap:wrap;overflow:hidden">
          ${skillBadge}${shownProtos}${moreProtos}
        </div>
        <div style="display:flex;gap:.3rem;flex-wrap:wrap;flex-shrink:0">
          <button class="btn btn-secondary btn-xs" data-act="tunnel">${esc(t('discover.tunnel.btn2'))}</button>
          <button class="btn btn-ghost btn-xs" data-act="aidproxy">${esc(t('discover.aidproxy.btn'))}</button>
          <button class="btn btn-ghost btn-xs" data-act="msg">${esc(t('discover.msg.send'))}</button>
          <button class="btn btn-ghost btn-xs" data-act="detail">${esc(t('discover.fav.detail'))}</button>
          <button class="btn btn-ghost btn-xs" data-act="del" style="color:var(--error)">${esc(t('discover.fav.del'))}</button>
        </div>
      </div>
      <div class="fav-alias-form field" style="display:none;padding:.35rem .85rem .5rem;margin:0;max-width:16rem">
        <label>${esc(t('agent.alias.local_label'))}</label>
        <div style="display:flex;gap:.4rem;align-items:center">
          <input type="text" class="fav-alias-input" maxlength="24" value="${esc(favAlias)}" style="max-width:14rem" />
          <button type="button" class="btn btn-ghost btn-xs" data-alias-cancel>&#10005;</button>
        </div>
        <div class="hint">${esc(t('agent.alias.local_hint'))}</div>
      </div>
      <div class="fav-panel" style="display:none;padding:.5rem .85rem .6rem;border-top:1px solid var(--border,#e5e7eb)"></div>`;

    rowWrap.querySelector('[data-cp]').onclick = () => copyText(fav.aid);

    const aliasForm  = rowWrap.querySelector('.fav-alias-form');
    const aliasInput = rowWrap.querySelector('.fav-alias-input');
    const aliasVal   = rowWrap.querySelector('.fav-alias-val');
    rowWrap.querySelector('[data-alias-edit]').onclick = () => {
      const open = aliasForm.style.display !== 'none';
      aliasForm.style.display = open ? 'none' : '';
      if (!open) aliasInput.focus();
    };
    rowWrap.querySelector('[data-alias-cancel]').onclick = () => { aliasForm.style.display = 'none'; };
    const saveAlias = () => {
      const v = aliasInput.value.trim() || favAlias;
      setAliasOf(fav.aid, v);
      aliasVal.textContent = v; aliasInput.value = v;
      aliasForm.style.display = 'none';
    };
    aliasInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') saveAlias(); if (e.key === 'Escape') aliasForm.style.display = 'none'; });
    aliasInput.addEventListener('blur', saveAlias);

    const panel = rowWrap.querySelector('.fav-panel');
    const actBtns = rowWrap.querySelectorAll('[data-act]');
    const DEFAULT_CLS = { tunnel: 'btn-secondary', aidproxy: 'btn-ghost', msg: 'btn-ghost', detail: 'btn-ghost', del: 'btn-ghost' };

    function deactivateFavBtns() {
      actBtns.forEach((b) => { b.classList.remove('btn-primary'); b.classList.add(DEFAULT_CLS[b.getAttribute('data-act')] || 'btn-ghost'); });
      panel.style.display = 'none';
      panel.innerHTML = '';
      delete rowWrap.dataset.activeAction;
    }

    actBtns.forEach((btn) => {
      btn.onclick = async () => {
        const action = btn.getAttribute('data-act');
        if (action === 'detail') { aidInput.value = fav.aid; switchTab('aid'); runQuery(); return; }
        const isActive = rowWrap.dataset.activeAction === action;
        deactivateFavBtns();
        if (isActive) return;
        rowWrap.dataset.activeAction = action;
        if (action !== 'del') { btn.classList.remove(DEFAULT_CLS[action] || 'btn-ghost'); btn.classList.add('btn-primary'); }
        panel.style.display = '';
        if (action === 'tunnel')   await setupFavTunnel(fav, panel, deactivateFavBtns);
        else if (action === 'aidproxy') setupFavAidproxy(fav, panel);
        else if (action === 'msg')      setupFavMsg(fav, panel);
        else if (action === 'del')      setupFavDel(fav, panel, deactivateFavBtns);
      };
    });

    return rowWrap;
  }

  async function setupFavTunnel(fav, panel, deactivateFavBtns, token) {
    panel.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('common.loading'))}</p>`;
    try {
      const tr = await findOrOpenTunnel(fav.aid, token);
      if (tr.allowed === false) {
        panel.innerHTML = `
        <p style="color:var(--success);margin:0 0 .3rem;font-size:.88rem">${esc(t('discover.tunnel.connected'))}</p>
        ${accessRetryHTML(t, nodeAid)}`;
        bindAccessRetry(panel, { status: 403 }, (tok) => setupFavTunnel(fav, panel, deactivateFavBtns, tok));
        return;
      }
      favTunnels.set(fav.id, tr.id);
      const relayBadge = tr.is_relayed ? `<span class="badge b-yellow" style="font-size:.72rem">${esc(t('tunnel.relayed'))}</span>` : '';
      panel.innerHTML = `
        <p style="color:var(--success);margin:0 0 .3rem;font-size:.88rem">${esc(t('discover.tunnel.ok'))} ${relayBadge}</p>
        <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.35rem">
          <code class="mono" style="font-size:.84rem">${esc(tr.listen)}</code>
          <button type="button" class="btn btn-ghost btn-xs" data-tcp>\u29c9</button>
          ${tunnelPortControls('btn-xs', fav.aid)}
          <button type="button" class="btn btn-ghost btn-xs" data-tclose>${esc(t('discover.tunnel.close'))}</button>
          <button type="button" class="btn btn-ghost btn-xs" data-treset>${esc(t('discover.tunnel.reset'))}</button>
        </div>
        <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap">
          <button type="button" class="btn btn-secondary btn-sm" data-topen>${esc(t('discover.tunnel.open'))}</button>
          ${tr.https_url ? `<button type="button" class="btn btn-ghost btn-sm" data-topen-https>${esc(t('discover.tunnel.open_https'))}</button><span class="muted" style="font-size:.78rem">${esc(t('discover.tunnel.open_hint'))}</span>` : ''}
        </div>`;
      panel.querySelector('[data-tcp]').onclick = () => copyText(tr.listen);
      bindTunnelPortEditor(panel, fav.aid);
      panel.querySelector('[data-topen]').onclick = () => window.open('http://' + tr.listen, '_blank', 'noopener');
      if (tr.https_url) panel.querySelector('[data-topen-https]').onclick = () => window.open(tr.https_url, '_blank', 'noopener');
      panel.querySelector('[data-tclose]').onclick = async () => {
        const tid = favTunnels.get(fav.id);
        if (tid) { try { await api(`/tunnel/${encodeURIComponent(tid)}`, { method: 'DELETE' }); } catch (_) {} favTunnels.delete(fav.id); }
        deactivateFavBtns();
      };
      panel.querySelector('[data-treset]').onclick = async () => {
        const tid = favTunnels.get(fav.id);
        if (!tid) return;
        try {
          await api(`/tunnel/${encodeURIComponent(tid)}/reset`, { method: 'POST', body: '{}' });
          favTunnels.delete(fav.id);
          panel.innerHTML = `<p class="muted" style="margin:0;font-size:.86rem">${esc(t('discover.tunnel.reset_ok'))}</p>`;
          deactivateFavBtns();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      };
    } catch (e) {
      panel.innerHTML = actionFailHTML(e, t, nodeAid, { port: e.localPort || savedTunnelPort(fav.aid) });
      bindAccessRetry(panel, e, (tok) => setupFavTunnel(fav, panel, deactivateFavBtns, tok));
      bindPortRandom(panel, fav.aid, () => setupFavTunnel(fav, panel, deactivateFavBtns));
    }
  }

  function setupFavAidproxy(fav, panel) {
    const url = `${window.location.origin}/aid/${encodeURIComponent(fav.aid)}/`;
    panel.innerHTML = `
      <div class="muted" style="font-size:.79rem;margin-bottom:.25rem">${esc(t('discover.aidproxy.label'))}</div>
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.2rem">
        <a class="mono" href="${esc(url)}" target="_blank" rel="noopener" style="font-size:.84rem">${esc(url)}</a>
        <button type="button" class="btn btn-ghost btn-xs" data-ap-cp>\u29c9</button>
      </div>
      <p class="muted" style="font-size:.78rem;margin:0">${esc(t('discover.aidproxy.hint'))}</p>`;
    panel.querySelector('[data-ap-cp]').onclick = () => copyText(url);
  }

  function setupFavMsg(fav, panel) {
    if (agents.length === 0) {
      panel.innerHTML = `<p class="muted" style="margin:0;font-size:.86rem">${esc(t('discover.msg.need_agent'))}</p>`;
      return;
    }
    panel.innerHTML = `
      <div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:flex-end">
        <div style="flex:0 0 auto">
          <label style="display:block;font-size:.79rem;color:var(--muted);margin-bottom:.18rem">${esc(t('discover.msg.from'))}</label>
          <select data-msg-from>${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}</select>
        </div>
        <div style="flex:1;min-width:10rem">
          <label style="display:block;font-size:.79rem;color:var(--muted);margin-bottom:.18rem">${esc(t('discover.msg.body'))}</label>
          <input type="text" data-msg-txt style="width:100%" />
        </div>
        <button type="button" class="btn btn-secondary" data-msg-go>${esc(t('discover.msg.submit'))}</button>
      </div>`;
    if (agents.length === 1) panel.querySelector('[data-msg-from]').value = agents[0].aid;
    panel.querySelector('[data-msg-go]').onclick = async (ev) => {
      const from = panel.querySelector('[data-msg-from]').value;
      if (!from) { toast(t('discover.msg.need_from'), 'warn'); return; }
      const txt = panel.querySelector('[data-msg-txt]').value;
      if (!txt) return;
      const btn = ev.currentTarget;
      setLoading(btn, true);
      try {
        await api(`/agents/${encodeURIComponent(from)}/mailbox/send`, {
          method: 'POST',
          body: JSON.stringify({ recipient: fav.aid, msg_type: 3, body_base64: utf8ToBase64(txt) }),
        });
        toast(t('common.sent'), 'ok');
        panel.querySelector('[data-msg-txt]').value = '';
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(btn, false);
      }
    };
  }

  function setupFavDel(fav, panel, deactivateFn) {
    panel.innerHTML = `
      <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">
        <span style="font-size:.87rem">${esc(t('discover.fav.del_confirm'))} <strong>${esc(aliasOf(fav.aid) || ensureAlias(fav.aid))}</strong>？</span>
        <button type="button" class="btn btn-secondary btn-sm" data-del-ok>${esc(t('discover.fav.del_ok'))}</button>
        <button type="button" class="btn btn-ghost btn-sm" data-del-cancel>${esc(t('common.cancel'))}</button>
      </div>`;
    panel.querySelector('[data-del-ok]').onclick = () => {
      const tid = favTunnels.get(fav.id);
      if (tid) { api(`/tunnel/${encodeURIComponent(tid)}`, { method: 'DELETE' }).catch(() => {}); favTunnels.delete(fav.id); }
      removeFav(fav.id);
      renderFavList();
      if (currentAid === fav.aid) updateStar(currentAid);
    };
    panel.querySelector('[data-del-cancel]').onclick = () => deactivateFn();
  }

  /* ── Service search ────────────────────────────────────── */
  function searchResultIdentityHtml(aid, e) {
    const faved = isFaved(aid);
    if (faved) {
      const alias = aliasOf(aid) || ensureAlias(aid);
      const sub = e.name ? `${shortAid(aid)} · ${e.name}` : shortAid(aid);
      return `
        <div data-identity>
          <div style="font-weight:600;font-size:.92rem">${esc(alias)}</div>
          <div class="muted" style="font-size:.85rem;margin-top:.12rem">
            ${esc(sub)}
            <button type="button" class="btn btn-ghost btn-sm" data-cp>\u29c9</button>
          </div>
        </div>`;
    }
    return `
      <div data-identity>
        <div>${esc(e.name || '')}${e.name ? ' · ' : ''}${esc(shortAid(aid))}
          <button type="button" class="btn btn-ghost btn-sm" data-cp>\u29c9</button>
        </div>
      </div>`;
  }

  function wireSearchResultRow(row, aid, e) {
    row.querySelector('[data-cp]')?.remove();
    const block = row.querySelector('[data-identity]');
    if (block) block.outerHTML = searchResultIdentityHtml(aid, e);
    row.querySelector('[data-cp]').onclick = () => copyText(aid);
  }

  async function search() {
    const term = q.value.trim();
    if (!term) return;
    const btn = wrap.querySelector('#ds');
    setLoading(btn, true);
    svcOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    try {
      const r = await api('/discover', { method: 'POST', body: JSON.stringify({ services: [term] }) });
      const entries = r.entries || [];
      svcOut.innerHTML = '';
      const count = document.createElement('p');
      count.className = 'muted';
      count.textContent = t('discover.results.count', { n: entries.length });
      svcOut.appendChild(count);
      if (!entries.length) {
        svcOut.appendChild(Object.assign(document.createElement('p'), { className: 'muted', textContent: t('discover.results.empty') }));
        return;
      }
      for (const e of entries) {
        const row = document.createElement('div');
        row.className = 'result-row';
        const aid = e.aid || '';
        const svc = e.service || '';
        const protos = (e.protocols || []).map((p) => `<span class="badge b-gray">${esc(p)}</span>`).join(' ');
        const tags = (e.tags || []).map((x) => `<span class="muted">#${esc(x)}</span>`).join(' ');
        row.innerHTML = `
          <div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:center">
            <span class="svc-name">${esc(svc)}</span>${protos}
            <span style="flex:1"></span>
            <button type="button" class="btn btn-ghost btn-sm" data-star style="font-size:.9rem">\u2606</button>
            <button type="button" class="btn btn-primary btn-sm" data-use>${esc(t('discover.result.use'))}</button>
          </div>
          ${searchResultIdentityHtml(aid, e)}
          ${e.brief ? `<div class="muted" style="margin-top:.35rem">${esc(e.brief)}</div>` : ''}`;
        row.querySelector('[data-cp]').onclick = () => copyText(aid);
        const starBtn = row.querySelector('[data-star]');
        if (isFaved(aid)) { starBtn.innerHTML = '\u2605'; starBtn.style.color = '#d97706'; }
        starBtn.onclick = () => {
          if (isFaved(aid)) return;
          addFav(aid, null, e.service, e.protocols || []);
          starBtn.innerHTML = '\u2605';
          starBtn.style.color = '#d97706';
          wireSearchResultRow(row, aid, e);
          toast(t('discover.fav.toast_added'), 'ok');
          updateStar(currentAid);
          renderFavList();
        };
        row.querySelector('[data-use]').onclick = () => { aidInput.value = aid; switchTab('aid'); runQuery(); };
        svcOut.appendChild(row);
      }
    } catch (e) {
      svcOut.innerHTML = `<p style="color:var(--error)">${esc(t('discover.search.failed'))}</p><p class="muted" style="font-size:.85rem;margin:.15rem 0 0">${esc(t('discover.search.failed_hint'))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  }
  wrap.querySelector('#ds').onclick = search;
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
}
