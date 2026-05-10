import { esc, shortAid, setLoading, base64ToUtf8 } from '../util.js';
import { loadFavs, addFav, removeFav, updateFavAlias, isFaved, nextDefaultAlias } from './favorites.js';

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

export async function renderDiscover(mount, ctx) {
  const { t, api, toast, copyText, isStale } = ctx;
  let agents = [];
  try {
    const r = await api('/agents');
    agents = r.agents || [];
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
        <div style="display:flex;justify-content:space-between;align-items:center;padding:.5rem .85rem;flex-wrap:wrap;gap:.35rem">
          <button type="button" class="btn btn-secondary btn-sm" id="dFavAddToggle">+ ${esc(t('discover.fav.add_btn'))}</button>
          <div style="display:flex;gap:.2rem;align-items:center">
            <span class="muted" style="font-size:.79rem;margin-right:.15rem">${esc(t('discover.fav.sort'))}</span>
            <button type="button" class="btn btn-ghost btn-xs" data-fav-sort="alias" id="dFavSortAlias">${esc(t('discover.fav.sort.alias'))}</button>
            <button type="button" class="btn btn-ghost btn-xs" data-fav-sort="skill" id="dFavSortSkill">${esc(t('discover.fav.sort.skill'))}</button>
            <button type="button" class="btn btn-ghost btn-xs active" data-fav-sort="addedAt" id="dFavSortTime">${esc(t('discover.fav.sort.time'))} ↓</button>
          </div>
        </div>
        <!-- Collapsible add form -->
        <div id="dFavAddForm" style="display:none;border-top:1px solid var(--border,#e5e7eb);padding:.6rem .85rem .7rem">
          <div style="display:flex;gap:.45rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:.4rem">
            <div style="flex:3;min-width:11rem">
              <label style="${LBL}">AID <span class="muted" style="font-size:.73rem">(${esc(t('common.required'))})</span></label>
              <input type="text" id="dFavAid" placeholder="${esc(t('discover.fav.aid_ph'))}" class="mono" style="width:100%" />
            </div>
            <div style="flex:1;min-width:6rem">
              <label style="${LBL}">${esc(t('discover.fav.alias_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavAlias" maxlength="24" style="width:100%" />
            </div>
          </div>
          <div style="display:flex;gap:.45rem;flex-wrap:wrap;align-items:flex-end">
            <div style="flex:1;min-width:8rem">
              <label style="${LBL}">${esc(t('discover.fav.skill_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavSkill" style="width:100%" />
            </div>
            <div style="flex:1;min-width:8rem">
              <label style="${LBL}">${esc(t('discover.fav.protocols_lbl'))} <span class="muted" style="font-size:.73rem">(${esc(t('common.optional'))})</span></label>
              <input type="text" id="dFavProtos" placeholder="http, mcp" style="width:100%" />
            </div>
            <button type="button" class="btn btn-ghost btn-sm" id="dFavFetch">${esc(t('discover.fav.fetch'))}</button>
            <button type="button" class="btn btn-primary btn-sm" id="dFavAdd">${esc(t('discover.fav.add'))}</button>
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
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.45rem;margin-bottom:.75rem">
          <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap">
            <span style="font-size:1.05rem;font-weight:700;color:var(--muted);letter-spacing:.01em">${esc(t('discover.target'))}</span>
            <span style="width:.55rem;display:inline-block"></span>
            <span class="mono" id="dOpAid" style="font-size:1.05rem;font-weight:700"></span>
            <button type="button" class="btn btn-ghost btn-sm" id="dOpCp" style="padding:.1rem .3rem;font-size:.85rem">\u29c9</button>
            <button type="button" class="btn btn-ghost btn-sm" id="dOpStar" style="font-size:.85rem;padding:.1rem .4rem"></button>
          </div>
          <div id="dStatusBadge" class="hidden" style="display:flex;align-items:center;gap:.6rem;font-size:.83rem"></div>
        </div>

        <div style="display:flex;flex-wrap:wrap;gap:.4rem">
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
        <div style="font-size:.82rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:.45rem">${esc(t('discover.network'))}</div>
        <div id="dResolve" style="font-size:.86rem;color:var(--muted)">${esc(t('discover.resolve.idle'))}</div>
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
  const statusBadge = wrap.querySelector('#dStatusBadge');
  const resolveBox  = wrap.querySelector('#dResolve');
  const profileBox  = wrap.querySelector('#dProfile');
  const localSvcBox = wrap.querySelector('#dLocalSvc');
  const dCardOut    = wrap.querySelector('#dCardOut');
  const actionOut   = wrap.querySelector('#dActionOut');
  const cacheBtn    = wrap.querySelector('#dCacheBtn');
  const cacheChev   = wrap.querySelector('#dCacheChevron');
  const cardChev    = wrap.querySelector('#dCardChevron');
  const tunnelBtn   = wrap.querySelector('#dTunnel');
  const oneshotBtn  = wrap.querySelector('#dOneshot');
  const reqBtn      = wrap.querySelector('#dShowReq');
  const aidproxyBtn = wrap.querySelector('#dAidProxy');
  const aidErr      = wrap.querySelector('#dAidErr');
  const svcOut      = wrap.querySelector('#dSvcOut');
  const q           = wrap.querySelector('#dq');
  const cat         = wrap.querySelector('#dqCat');

  let currentAid      = '';
  let currentTunnelId = null;
  let oneshotTimer    = null;
  let cardFetched     = false;
  let activeActionBtn = null;
  let msgBtnActive    = false;
  let lastServices    = [];
  let lastProfile     = null;
  const favTunnels    = new Map();

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
  function fmtEndpoints(ep) {
    if (ep == null) return '—';
    if (Array.isArray(ep)) return esc(ep.map(String).join(', ')) || '—';
    return esc(String(ep));
  }

  function dot(color) {
    return `<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${color};flex-shrink:0"></span>`;
  }

  function setStatus(pingOk, ttlValid, lastSeenStr) {
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
    statusBadge.innerHTML = onlineHtml + seenHtml;
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
      renderFavList();
      toast(t('discover.fav.toast_added'), 'ok');
    };
  }

  /* ── Capability rendering ──────────────────────────────── */
  function renderCapabilities(profile, services) {
    profileBox.innerHTML = '';
    const frag = document.createDocumentFragment();
    if (profile) {
      if (profile.name) {
        const d = document.createElement('div');
        d.style.cssText = 'font-weight:600;font-size:.95rem;margin-bottom:.18rem';
        d.textContent = profile.name;
        frag.appendChild(d);
      }
      if (profile.brief) {
        const d = document.createElement('div');
        d.className = 'muted';
        d.style.cssText = 'font-size:.87rem;line-height:1.5;margin-bottom:.4rem';
        d.textContent = profile.brief;
        frag.appendChild(d);
      }
      if (profile.modalities && profile.modalities.length) {
        const d = document.createElement('div');
        d.style.cssText = 'display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:.35rem';
        d.innerHTML = `<span class="muted" style="font-size:.78rem;white-space:nowrap">${esc(t('discover.profile.modalities'))}</span>` +
          profile.modalities.map((m) => `<span class="badge b-gray">${esc(m)}</span>`).join('');
        frag.appendChild(d);
      }
    }
    if (services && services.length) {
      for (const svc of services) {
        const topic  = svc.topic || svc.Topic || '';
        const protos = (svc.protocols || []).map((p) => `<span class="badge b-blue" style="font-size:.78rem">${esc(p)}</span>`).join('');
        const tags   = (svc.tags || []).map((x) => `<span style="font-size:.77rem;color:var(--muted)">#${esc(x)}</span>`).join(' ');
        const row = document.createElement('div');
        row.style.cssText = 'margin-bottom:.4rem;padding:.38rem .5rem;background:var(--bg-subtle,#f9fafb);border:1px solid var(--border,#e5e7eb);border-radius:.35rem';
        row.innerHTML = `
          <div style="display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:${svc.name || svc.brief || tags ? '.1rem' : '0'}">
            <span class="svc-name">${esc(topic)}</span>${protos}
          </div>
          ${svc.name  ? `<div style="font-size:.87rem;font-weight:500;color:var(--fg)">${esc(svc.name)}</div>` : ''}
          ${tags       ? `<div style="margin-top:.1rem">${tags}</div>` : ''}
          ${svc.brief  ? `<div class="muted" style="font-size:.83rem;line-height:1.45;margin-top:.12rem">${esc(svc.brief)}</div>` : ''}`;
        frag.appendChild(row);
      }
    } else if (profile) {
      if (profile.skills && profile.skills.length) {
        const d = document.createElement('div');
        d.style.cssText = 'display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:.3rem';
        d.innerHTML = `<span class="muted" style="font-size:.78rem;white-space:nowrap">${esc(t('discover.profile.skills'))}</span>` +
          profile.skills.map((s) => `<span class="badge b-gray">${esc(s)}</span>`).join('');
        frag.appendChild(d);
      }
      if (profile.protocols && profile.protocols.length) {
        const d = document.createElement('div');
        d.style.cssText = 'display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:.3rem';
        d.innerHTML = `<span class="muted" style="font-size:.78rem;white-space:nowrap">${esc(t('discover.profile.protocols'))}</span>` +
          profile.protocols.map((p) => `<span class="badge b-blue">${esc(p)}</span>`).join('');
        frag.appendChild(d);
      }
    }
    if (frag.childNodes.length === 0) {
      profileBox.innerHTML = `<p class="muted" style="margin:.1rem 0;font-size:.87rem">${esc(t('discover.profile.none'))}</p>`;
    } else {
      profileBox.appendChild(frag);
    }
  }

  function renderLocalServices(list) {
    localSvcBox.innerHTML = '';
    if (!list || !list.length) {
      localSvcBox.innerHTML = `<p class="muted" style="margin:0;font-size:.86rem">${esc(t('discover.cache_empty'))}</p>`;
      return;
    }
    for (const svc of list) {
      const topic  = svc.topic || svc.Topic || '';
      const protos = (svc.protocols || []).map((p) => `<span class="badge b-blue" style="font-size:.78rem">${esc(p)}</span>`).join('');
      const tags   = (svc.tags || []).map((x) => `<span style="font-size:.77rem;color:var(--muted)">#${esc(x)}</span>`).join(' ');
      const row = document.createElement('div');
      row.style.cssText = 'margin-bottom:.4rem;padding:.38rem .5rem;background:var(--bg-subtle,#f9fafb);border:1px solid var(--border,#e5e7eb);border-radius:.35rem';
      row.innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:.3rem;align-items:center;margin-bottom:${svc.name || svc.brief || tags ? '.1rem' : '0'}">
          <span class="svc-name">${esc(topic)}</span>${protos}
        </div>
        ${svc.name  ? `<div style="font-size:.87rem;font-weight:500;color:var(--fg)">${esc(svc.name)}</div>` : ''}
        ${tags       ? `<div style="margin-top:.1rem">${tags}</div>` : ''}
        ${svc.brief  ? `<div class="muted" style="font-size:.83rem;line-height:1.45;margin-top:.12rem">${esc(svc.brief)}</div>` : ''}`;
      localSvcBox.appendChild(row);
    }
  }

  /* ── 本机缓存 / Agent Card mutual exclusion ───────────── */
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

  /* ── runQuery ──────────────────────────────────────────── */
  async function runQuery() {
    const raw = aidInput.value.trim();
    aidErr.classList.add('hidden');
    if (!raw) { aidErr.textContent = t('discover.aid.required'); aidErr.classList.remove('hidden'); return; }
    currentAid = raw;
    lastServices = [];
    lastProfile = null;
    opArea.classList.remove('hidden');
    opAidEl.textContent = shortAid(currentAid);
    wrap.querySelector('#dOpCp').onclick = () => copyText(currentAid);
    updateStar(currentAid);

    statusBadge.classList.add('hidden');
    statusBadge.innerHTML = '';
    profileBox.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('discover.profile.loading'))}</p>`;
    localSvcBox.innerHTML = '';
    localSvcBox.classList.add('hidden');
    cacheChev.textContent = '\u25be';
    dCardOut.innerHTML = '';
    dCardOut.classList.add('hidden');
    cardChev.textContent = '\u25be';
    cardFetched = false;
    resolveBox.style.color = 'var(--muted)';
    resolveBox.textContent = t('common.loading');
    wrap.querySelector('#dPingOut').textContent = '';
    if (oneshotTimer) { clearInterval(oneshotTimer); oneshotTimer = null; }
    if (currentTunnelId) {
      api(`/tunnel/${encodeURIComponent(currentTunnelId)}`, { method: 'DELETE' }).catch(() => {});
      currentTunnelId = null;
    }
    deactivateActions();
    wrap.querySelector('#dMsgPanel').classList.add('hidden');
    msgBtnActive = false;

    const [resRes, agRes, profRes] = await Promise.allSettled([
      api(`/resolve/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' }),
      api(`/agents/${encodeURIComponent(currentAid)}`),
      api(`/resolve/${encodeURIComponent(currentAid)}/records?type=2`),
    ]);

    let ttlValid = false;
    let lastSeenStr = null;
    if (resRes.status === 'fulfilled') {
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
        .then(() => setStatus(true, ttlValid, lastSeenStr))
        .catch(() => setStatus(false, ttlValid, lastSeenStr));
    } else {
      resolveBox.style.color = 'var(--error)';
      resolveBox.innerHTML = `<p style="margin:0">${esc(t('common.error', { msg: resRes.reason?.message ?? '' }))}</p>`;
      setStatus(false, false, null);
    }

    lastServices = agRes.status === 'fulfilled' ? (agRes.value.services || []) : [];
    renderLocalServices(lastServices);

    const records = profRes.status === 'fulfilled' ? (profRes.value.records || []) : [];
    const profRecord = Array.isArray(records) ? records.find((r) => r.profile) : null;
    lastProfile = profRecord ? profRecord.profile : null;
    renderCapabilities(lastProfile, lastServices);
    updateStar(currentAid); // refresh star with populated lastServices/lastProfile
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
      el.textContent = t('discover.ping.fail') + ': ' + e.message;
      el.style.color = 'var(--error)';
    } finally {
      setLoading(btn, false);
    }
  };

  /* ── Business: tunnel ──────────────────────────────────── */
  tunnelBtn.onclick = async (ev) => {
    if (!currentAid) return;
    if (!activateAction(tunnelBtn)) return;
    const btn = ev.currentTarget;
    setLoading(btn, true);
    actionOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    if (currentTunnelId) {
      api(`/tunnel/${encodeURIComponent(currentTunnelId)}`, { method: 'DELETE' }).catch(() => {});
      currentTunnelId = null;
    }
    try {
      const tr = await api(`/tunnel/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' });
      currentTunnelId = tr.id;
      actionOut.innerHTML = `
        <p style="color:var(--success);margin:0 0 .35rem;font-size:.9rem">${esc(t('discover.tunnel.ok'))}</p>
        <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.4rem">
          <code class="mono" style="font-size:.87rem">${esc(tr.listen)}</code>
          <button type="button" class="btn btn-ghost btn-sm" id="dTunnelCp">\u29c9</button>
          <button type="button" class="btn btn-ghost btn-sm" id="dTunnelClose">${esc(t('discover.tunnel.close'))}</button>
        </div>
        <div style="display:flex;gap:.4rem;flex-wrap:wrap;align-items:center">
          <button type="button" class="btn btn-secondary btn-sm" id="dTunnelOpen">${esc(t('discover.tunnel.open'))}</button>
          ${tr.https_url ? `<button type="button" class="btn btn-ghost btn-sm" id="dTunnelOpenHttps">${esc(t('discover.tunnel.open_https'))}</button><span class="muted" style="font-size:.79rem">${esc(t('discover.tunnel.open_hint'))}</span>` : ''}
        </div>`;
      actionOut.querySelector('#dTunnelCp').onclick = () => copyText(tr.listen);
      actionOut.querySelector('#dTunnelOpen').onclick = () => window.open('http://' + tr.listen, '_blank', 'noopener');
      if (tr.https_url) actionOut.querySelector('#dTunnelOpenHttps').onclick = () => window.open(tr.https_url, '_blank', 'noopener');
      actionOut.querySelector('#dTunnelClose').onclick = async () => {
        if (!currentTunnelId) return;
        try { await api(`/tunnel/${encodeURIComponent(currentTunnelId)}`, { method: 'DELETE' }); } catch (_) {}
        currentTunnelId = null;
        actionOut.innerHTML = `<p class="muted" style="margin:0">${esc(t('discover.tunnel.closed'))}</p>`;
        deactivateActions();
      };
    } catch (e) {
      actionOut.innerHTML = `<p style="color:var(--error);margin:0">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  };

  /* ── Business: oneshot ─────────────────────────────────── */
  oneshotBtn.onclick = async (ev) => {
    if (!currentAid) return;
    if (!activateAction(oneshotBtn)) return;
    const btn = ev.currentTarget;
    setLoading(btn, true);
    actionOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    if (oneshotTimer) { clearInterval(oneshotTimer); oneshotTimer = null; }
    try {
      const cr = await api(`/connect/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' });
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
      actionOut.innerHTML = `<p style="color:var(--error);margin:0">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  };

  /* ── Business: AID direct ──────────────────────────────── */
  aidproxyBtn.onclick = () => {
    if (!currentAid) return;
    if (!activateAction(aidproxyBtn)) return;
    const url = `${window.location.origin}/aid/${encodeURIComponent(currentAid)}/`;
    actionOut.innerHTML = `
      <div class="muted" style="font-size:.79rem;margin-bottom:.25rem">${esc(t('discover.aidproxy.label'))}</div>
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.2rem">
        <code class="mono" style="font-size:.86rem">${esc(url)}</code>
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
    actionOut.querySelector('#rqGo').onclick = async (ev) => {
      if (!currentAid) return;
      const btn = ev.currentTarget;
      setLoading(btn, true);
      const path = actionOut.querySelector('#rqP').value.trim() || '/';
      const method = m.value;
      const localAid = actionOut.querySelector('#rqAid').value;
      const t0 = performance.now();
      try {
        const fetchBody = { method, path };
        if (localAid) fetchBody.local_aid = localAid;
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
        actionOut.querySelector('#rqOut').textContent = e.message;
        actionOut.querySelector('#rqMeta').textContent = '';
      } finally {
        setLoading(btn, false);
      }
    };
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
      dFavAlias.value = nextDefaultAlias(loadFavs());
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
    const alias = dFavAlias.value.trim() || nextDefaultAlias(loadFavs());
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
      if (favSortBy === 'alias') { av = (a.alias || '').toLowerCase(); bv = (b.alias || '').toLowerCase(); }
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
          <span class="fav-alias-val" style="font-size:.9rem;font-weight:500">${esc(fav.alias)}</span>
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
      <div class="fav-alias-form" style="display:none;padding:.25rem .85rem .45rem">
        <div style="display:flex;gap:.4rem;align-items:center">
          <input type="text" class="fav-alias-input" maxlength="24" value="${esc(fav.alias)}" style="max-width:14rem" />
          <button type="button" class="btn btn-ghost btn-xs" data-alias-cancel>&#10005;</button>
        </div>
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
      const v = aliasInput.value.trim() || fav.alias;
      updateFavAlias(fav.id, v);
      fav.alias = v; aliasVal.textContent = v; aliasInput.value = v;
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

  async function setupFavTunnel(fav, panel, deactivateFavBtns) {
    panel.innerHTML = `<p class="muted" style="font-size:.87rem">${esc(t('common.loading'))}</p>`;
    const prevId = favTunnels.get(fav.id);
    if (prevId) { api(`/tunnel/${encodeURIComponent(prevId)}`, { method: 'DELETE' }).catch(() => {}); favTunnels.delete(fav.id); }
    try {
      const tr = await api(`/tunnel/${encodeURIComponent(fav.aid)}`, { method: 'POST', body: '{}' });
      favTunnels.set(fav.id, tr.id);
      panel.innerHTML = `
        <p style="color:var(--success);margin:0 0 .3rem;font-size:.88rem">${esc(t('discover.tunnel.ok'))}</p>
        <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.35rem">
          <code class="mono" style="font-size:.84rem">${esc(tr.listen)}</code>
          <button type="button" class="btn btn-ghost btn-xs" data-tcp>\u29c9</button>
          <button type="button" class="btn btn-ghost btn-xs" data-tclose>${esc(t('discover.tunnel.close'))}</button>
        </div>
        <div style="display:flex;gap:.35rem;align-items:center;flex-wrap:wrap">
          <button type="button" class="btn btn-secondary btn-sm" data-topen>${esc(t('discover.tunnel.open'))}</button>
          ${tr.https_url ? `<button type="button" class="btn btn-ghost btn-sm" data-topen-https>${esc(t('discover.tunnel.open_https'))}</button><span class="muted" style="font-size:.78rem">${esc(t('discover.tunnel.open_hint'))}</span>` : ''}
        </div>`;
      panel.querySelector('[data-tcp]').onclick = () => copyText(tr.listen);
      panel.querySelector('[data-topen]').onclick = () => window.open('http://' + tr.listen, '_blank', 'noopener');
      if (tr.https_url) panel.querySelector('[data-topen-https]').onclick = () => window.open(tr.https_url, '_blank', 'noopener');
      panel.querySelector('[data-tclose]').onclick = async () => {
        const tid = favTunnels.get(fav.id);
        if (tid) { try { await api(`/tunnel/${encodeURIComponent(tid)}`, { method: 'DELETE' }); } catch (_) {} favTunnels.delete(fav.id); }
        deactivateFavBtns();
      };
    } catch (e) {
      panel.innerHTML = `<p style="color:var(--error);margin:0;font-size:.86rem">${esc(t('common.error', { msg: e.message }))}</p>`;
    }
  }

  function setupFavAidproxy(fav, panel) {
    const url = `${window.location.origin}/aid/${encodeURIComponent(fav.aid)}/`;
    panel.innerHTML = `
      <div class="muted" style="font-size:.79rem;margin-bottom:.25rem">${esc(t('discover.aidproxy.label'))}</div>
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-bottom:.2rem">
        <code class="mono" style="font-size:.84rem">${esc(url)}</code>
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
        <span style="font-size:.87rem">${esc(t('discover.fav.del_confirm'))} <strong>${esc(fav.alias)}</strong>？</span>
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
          <div>${esc(e.name || '')} · ${esc(shortAid(aid))} <button type="button" class="btn btn-ghost btn-sm" data-cp>\u29c9</button></div>
          ${e.brief ? `<div class="muted" style="margin-top:.35rem">${esc(e.brief)}</div>` : ''}`;
        row.querySelector('[data-cp]').onclick = () => copyText(aid);
        const starBtn = row.querySelector('[data-star]');
        if (isFaved(aid)) { starBtn.innerHTML = '\u2605'; starBtn.style.color = '#d97706'; }
        starBtn.onclick = () => {
          if (isFaved(aid)) return;
          addFav(aid, null, e.service, e.protocols || []);
          starBtn.innerHTML = '\u2605';
          starBtn.style.color = '#d97706';
          toast(t('discover.fav.toast_added'), 'ok');
          updateStar(currentAid);
        };
        row.querySelector('[data-use]').onclick = () => { aidInput.value = aid; switchTab('aid'); runQuery(); };
        svcOut.appendChild(row);
      }
    } catch (e) {
      svcOut.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  }
  wrap.querySelector('#ds').onclick = search;
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
}
