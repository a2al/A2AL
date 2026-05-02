import {
  esc,
  shortAid,
  aliasOf,
  setAliasOf,
  generateDefaultAlias,
  labelAid,
  setLoading,
  parseTags,
  buildServiceName,
  mapCardJson,
  parseCardData,
  normalizeServiceTCP,
} from '../util.js';

const CATS = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];

// Map numeric NAT type (from published_nat_type) to an i18n key
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

function agentKind(aid) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(aid)) ? 'Ethereum' : 'Ed25519';
}

function agentStatus(ag) {
  if (!ag.published_to_dht) return { key: 'agent.status.unpublished', cls: 'b-gray' };
  if (ag.next_republish_estimate) {
    const overdueSec = (Date.now() - new Date(ag.next_republish_estimate).getTime()) / 1000;
    if (overdueSec > 600) return { key: 'agent.status.refresh_failed', cls: 'b-yellow' };
  }
  return { key: 'agent.status.published', cls: 'b-green' };
}

function fmtTtl(sec) {
  if (!sec) return '—';
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  if (sec < 86400) return `${Math.round(sec / 3600)}h`;
  return `${Math.round(sec / 86400)}d`;
}

function tcpDot(ag, t) {
  if (!ag.service_tcp) return `<span class="tcp-dot tcp-none">—</span> <span class="muted">${esc(t('agent.tcp.none'))}</span>`;
  if (ag.service_tcp_ok === true)
    return `<span class="tcp-dot tcp-ok">●</span> <span class="tcp-ok">${esc(t('agent.tcp.ok'))}</span>`;
  if (ag.service_tcp_ok === false)
    return `<span class="tcp-dot tcp-fail">●</span> <span class="tcp-fail">${esc(t('agent.tcp.fail'))}</span>`;
  return `<span class="tcp-dot tcp-unk">●</span> <span class="muted">${esc(t('agent.tcp.unknown'))}</span>`;
}

export async function renderAgents(mount, ctx) {
  const { t, api, toast, relTime, openModal, onRefresh, copyText } = ctx;
  let agents = [];
  let demoStatus = { running: false, aid: '', port: 0 };
  try {
    const [agentsRes, demoRes] = await Promise.allSettled([
      api('/agents'),
      api('/demo/status'),
    ]);
    if (agentsRes.status === 'fulfilled') agents = agentsRes.value.agents || [];
    else { mount.innerHTML = `<p class="muted">${esc(t('common.error', { msg: agentsRes.reason?.message }))}</p>`; return; }
    if (demoRes.status === 'fulfilled') demoStatus = demoRes.value;
  } catch (e) {
    mount.innerHTML = `<p class="muted">${esc(t('common.error', { msg: e.message }))}</p>`;
    return;
  }

  // Top action bar — always visible
  const topBar = document.createElement('div');
  topBar.className = 'ag-topbar';
  topBar.innerHTML = `
    <button type="button" class="btn btn-secondary btn-sm" id="tb-create">+ ${esc(t('agent.action.create'))}</button>
    <button type="button" class="btn btn-ghost btn-sm" id="tb-import">${esc(t('agent.action.import'))}</button>
    <button type="button" class="btn btn-ghost btn-sm" id="tb-eth">${esc(t('agent.action.eth'))}</button>
    <div class="ag-sortbar" id="tb-sortbar"></div>`;
  topBar.querySelector('#tb-create').onclick = () => openCreateModal();
  topBar.querySelector('#tb-import').onclick = () => openImportModal();
  topBar.querySelector('#tb-eth').onclick = () => openEthModal();
  mount.appendChild(topBar);

  if (!agents.length) {
    const guide = document.createElement('div');
    guide.className = 'card';
    guide.innerHTML = `<div class="card-b"><div class="guide-box">
      <h2>${esc(t('agent.empty.title'))}</h2>
      <div class="body">${esc(t('agent.empty.body')).replace(/\n/g, '<br/>')}</div>
      <div class="guide-actions">
        <button type="button" class="btn btn-primary" id="ge-create">${esc(t('agent.action.create'))}</button>
        <button type="button" class="btn btn-secondary" id="ge-import">${esc(t('agent.action.import'))}</button>
        <button type="button" class="btn btn-secondary" id="ge-eth">${esc(t('agent.action.eth'))}</button>
      </div>
    </div></div>`;
    guide.querySelector('#ge-create').onclick = () => openCreateModal();
    guide.querySelector('#ge-import').onclick = () => openImportModal();
    guide.querySelector('#ge-eth').onclick = () => openEthModal();
    mount.appendChild(guide);
    return;
  }

  // Sort controls — rendered inside the topbar (right side via CSS margin-left:auto).
  // Clicking the active button toggles asc/desc; clicking another button switches
  // field and resets to ascending.
  let sortBy  = localStorage.getItem('agentSortBy')  || 'aid';
  let sortDir = localStorage.getItem('agentSortDir') || 'asc';
  const sortBar = topBar.querySelector('#tb-sortbar');
  const renderSortBar = () => {
    const arrow = sortDir === 'asc' ? ' ↑' : ' ↓';
    sortBar.innerHTML = `
      <span class="muted" style="font-size:.85rem">${esc(t('agent.sort.label'))}</span>
      <button type="button" class="btn btn-ghost btn-sm${sortBy === 'aid' ? ' active' : ''}" data-sort="aid">${esc(t('agent.sort.aid'))}${sortBy === 'aid' ? arrow : ''}</button>
      <button type="button" class="btn btn-ghost btn-sm${sortBy === 'alias' ? ' active' : ''}" data-sort="alias">${esc(t('agent.sort.alias'))}${sortBy === 'alias' ? arrow : ''}</button>`;
    sortBar.querySelectorAll('[data-sort]').forEach(btn => {
      btn.onclick = () => {
        if (btn.dataset.sort === sortBy) {
          sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          sortBy  = btn.dataset.sort;
          sortDir = 'asc';
        }
        localStorage.setItem('agentSortBy',  sortBy);
        localStorage.setItem('agentSortDir', sortDir);
        renderList();
        renderSortBar();
      };
    });
  };
  renderSortBar();

  const listContainer = document.createElement('div');
  mount.appendChild(listContainer);

  const sortedAgents = () => {
    const copy = [...agents];
    const dir  = sortDir === 'asc' ? 1 : -1;
    if (sortBy === 'alias') {
      copy.sort((a, b) => {
        const la = (aliasOf(a.aid) || a.aid).toLowerCase();
        const lb = (aliasOf(b.aid) || b.aid).toLowerCase();
        return (la < lb ? -1 : la > lb ? 1 : 0) * dir;
      });
    } else {
      copy.sort((a, b) => (a.aid < b.aid ? -1 : a.aid > b.aid ? 1 : 0) * dir);
    }
    return copy;
  };

  const renderList = () => {
    listContainer.innerHTML = '';
    const sorted = sortedAgents();
    for (let idx = 0; idx < sorted.length; idx++) {
      listContainer.appendChild(buildAgentCard(sorted[idx], idx === 0, sorted, idx, demoStatus));
    }
  };
  renderList();

  // ── Agent card builder ──────────────────────────────────────────────────
  function buildAgentCard(ag, svcExpanded, allAgents, idx, demoStatus) {
    const st = agentStatus(ag);
    // Auto-assign a default alias if none is stored yet
    if (!aliasOf(ag.aid)) setAliasOf(ag.aid, generateDefaultAlias());
    const alias = aliasOf(ag.aid);
    const isDemoActive = demoStatus.running && demoStatus.aid === ag.aid;
    const card = document.createElement('div');
    card.className = 'card ag2-card';
    card.dataset.status = st.cls;

    // ── § Basic info ──
    const infoDiv = document.createElement('div');
    infoDiv.className = 'ag2-info';
    infoDiv.innerHTML = `
      <div class="ag2-info-top">
        <div class="ag2-aid-col">
          <div class="ag2-aid-row">
            <span class="ag2-alias" id="ag-alias-${idx}">${esc(alias)}</span>
            <button type="button" class="btn btn-ghost btn-xs" data-alias title="${esc(t('agent.alias.set'))}">✏</button>
            <span class="aid-short mono">${esc(shortAid(ag.aid))}</span>
            <button type="button" class="btn btn-ghost btn-xs" data-copy title="Copy AID">\u29c9</button>
          </div>
          <div id="ag-alias-form-${idx}" style="display:none;margin:.25rem 0 .4rem">
            <input type="text" class="ag2-alias-input" maxlength="24"
              value="${esc(alias)}" placeholder="${esc(t('agent.alias.placeholder'))}"
              style="width:100%;max-width:16rem" />
          </div>
          <div class="ag2-tcp-row">
            ${tcpDot(ag, t)}
            ${ag.service_tcp ? `<span class="mono ag2-tcp-addr">${esc(ag.service_tcp)}</span>` : ''}
            ${isDemoActive ? `<span class="badge b-blue demo-badge">${esc(t('demo.badge'))}</span>` : ''}
            <button type="button" class="btn btn-ghost btn-xs" data-edit-tcp>${esc(t('agent.tcp.edit'))}</button>
            ${isDemoActive
              ? `<button type="button" class="btn btn-ghost btn-xs" data-demo-stop-tcp>${esc(t('demo.stop'))}</button>`
              : !ag.service_tcp
                ? `<button type="button" class="btn btn-ghost btn-xs" data-demo-start>${esc(t('demo.btn'))}</button>`
                : ''}
          </div>
          <div id="ag-tcp-form-${idx}" style="display:none;margin:.25rem 0 .4rem">
            <div style="display:flex;gap:.35rem;flex-wrap:wrap">
              <input type="text" class="ag2-tcp-input" value="${esc(ag.service_tcp || '')}"
                placeholder="http://127.0.0.1:8080" style="flex:1;min-width:10rem" />
              <button type="button" class="btn btn-primary btn-sm" data-tcp-save>${esc(t('agent.tcp.save'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-tcp-cancel>${esc(t('common.cancel'))}</button>
            </div>
          </div>
        </div>
        <div class="ag2-badges">
          <span class="badge ${esc(st.cls)}">● ${esc(t(st.key))}</span>
          <span class="badge b-blue">${esc(agentKind(ag.aid))}</span>
        </div>
      </div>
      <div class="ag2-info-bottom">
        <span class="muted ag2-meta">
          ${esc(t('agent.last_refresh', { ago: ag.last_publish_at ? relTime(ag.last_publish_at) : '—' }))}
          &nbsp;·&nbsp;
          ${esc(t('agent.next_refresh', { eta: ag.next_republish_estimate ? relTime(ag.next_republish_estimate) : '—' }))}
          ${ag.dht_local_replicas != null ? `&nbsp;·&nbsp;${esc(t('agent.dht_replicas', { n: ag.dht_local_replicas, target: 8 }))}` : ''}
        </span>
        <div class="ag2-actions">
          ${!ag.published_to_dht ? `<button type="button" class="btn btn-primary btn-sm" data-pub-now>${esc(t('agent.action.republish'))}</button>` : ''}
          <button type="button" class="btn btn-secondary btn-sm" data-pub>${esc(t('agent.action.republish'))}</button>
          <button type="button" class="btn btn-danger btn-sm" data-del>${esc(t('agent.action.delete'))}</button>
        </div>
      </div>`;

    // copy AID
    infoDiv.querySelector('[data-copy]').onclick = () => copyText(ag.aid);

    // alias edit
    const aliasForm = infoDiv.querySelector(`#ag-alias-form-${idx}`);
    infoDiv.querySelector('[data-alias]').onclick = () => {
      aliasForm.style.display = aliasForm.style.display === 'none' ? '' : 'none';
      if (aliasForm.style.display !== 'none') aliasForm.querySelector('input').focus();
    };
    const saveAlias = () => {
      const v = aliasForm.querySelector('input').value.trim();
      // If cleared, regenerate a default alias instead of leaving blank
      const finalAlias = v || generateDefaultAlias();
      setAliasOf(ag.aid, finalAlias);
      const existing = infoDiv.querySelector(`#ag-alias-${idx}`);
      const aidRow = infoDiv.querySelector('.ag2-aid-row');
      if (existing) {
        existing.textContent = finalAlias;
      } else {
        const sp = document.createElement('span');
        sp.className = 'ag2-alias';
        sp.id = `ag-alias-${idx}`;
        sp.textContent = finalAlias;
        aidRow.insertBefore(sp, aidRow.firstChild);
      }
      aliasForm.style.display = 'none';
    };
    aliasForm.querySelector('input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') saveAlias();
      if (e.key === 'Escape') { aliasForm.style.display = 'none'; }
    });
    aliasForm.querySelector('input').addEventListener('blur', saveAlias);

    // service_tcp edit
    const tcpForm = infoDiv.querySelector(`#ag-tcp-form-${idx}`);
    infoDiv.querySelector('[data-edit-tcp]').onclick = () => {
      tcpForm.style.display = tcpForm.style.display === 'none' ? '' : 'none';
    };
    infoDiv.querySelector('[data-tcp-cancel]').onclick = () => { tcpForm.style.display = 'none'; };
    infoDiv.querySelector('[data-tcp-save]').onclick = async (ev) => {
      const val = normalizeServiceTCP(tcpForm.querySelector('.ag2-tcp-input').value);
      const b = ev.currentTarget;
      setLoading(b, true);
      try {
        await api(`/agents/${encodeURIComponent(ag.aid)}`, {
          method: 'PATCH',
          body: JSON.stringify({ service_tcp: val }),
        });
        toast(t('common.sent'), 'ok');
        onRefresh();
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(b, false);
      }
    };

    // demo mode — start / stop buttons on TCP row
    const demoStartBtn = infoDiv.querySelector('[data-demo-start]');
    const demoStopTcpBtn = infoDiv.querySelector('[data-demo-stop-tcp]');
    const demoAction = async (start, btn) => {
      setLoading(btn, true);
      try {
        if (start) {
          if (ag.service_tcp && !confirm(t('demo.confirm_overwrite', { addr: ag.service_tcp }))) return;
          await api('/demo/start', { method: 'POST', body: JSON.stringify({ aid: ag.aid }) });
          toast(t('demo.started'), 'ok');
        } else {
          await api('/demo/stop', { method: 'POST', body: JSON.stringify({ aid: ag.aid }) });
          toast(t('demo.stopped'), 'ok');
        }
        onRefresh();
      } catch (e) { toast(t('common.error', { msg: e.message }), 'err'); }
      finally { setLoading(btn, false); }
    };
    if (demoStartBtn) demoStartBtn.onclick = (ev) => demoAction(true, ev.currentTarget);
    if (demoStopTcpBtn) demoStopTcpBtn.onclick = (ev) => demoAction(false, ev.currentTarget);

    // publish
    const doPublish = async (btn) => {
      setLoading(btn, true);
      try {
        const p = await api(`/agents/${encodeURIComponent(ag.aid)}/publish`, { method: 'POST', body: '{}' });
        toast(t('agent.published', { seq: p.seq }), 'ok');
        onRefresh();
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(btn, false);
      }
    };
    infoDiv.querySelector('[data-pub]').onclick = (ev) => doPublish(ev.currentTarget);
    const pubNow = infoDiv.querySelector('[data-pub-now]');
    if (pubNow) pubNow.onclick = (ev) => doPublish(ev.currentTarget);

    // delete
    infoDiv.querySelector('[data-del]').onclick = async () => {
      if (!confirm(t('agent.delete.confirm'))) return;
      try {
        await api(`/agents/${encodeURIComponent(ag.aid)}`, { method: 'DELETE', body: '{}' });
        toast(t('common.sent'), 'ok');
        onRefresh();
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      }
    };

    card.appendChild(infoDiv);

    // ── § Services ──
    const svcHeader = document.createElement('div');
    svcHeader.className = 'ag2-svc-header';
    const svcCount = (ag.services || []).length;
    svcHeader.innerHTML = `
      <button type="button" class="ag2-svc-toggle">
        <span class="ag2-toggle-arrow">${svcExpanded ? '▼' : '▶'}</span>
        <span>${esc(t('agent.svc.title', { n: svcCount }))}</span>
      </button>
      <button type="button" class="btn btn-secondary btn-sm ag2-pub-svc-hdr">${esc(t('service.action.publish'))}</button>`;
    card.appendChild(svcHeader);

    const svcBody = document.createElement('div');
    svcBody.className = 'ag2-svc-body';
    if (!svcExpanded) svcBody.style.display = 'none';

    if (!svcCount) {
      svcBody.innerHTML = `
        <p class="ag2-svc-empty-title">${esc(t('service.empty.title'))}</p>
        <p class="muted" style="font-size:.9rem;margin:.4rem 0 1rem">${esc(t('service.empty.body')).replace(/\n/g, '<br/>')}</p>
        <button type="button" class="btn btn-primary btn-sm ag2-pub-svc-empty">${esc(t('service.action.publish'))}</button>`;
      svcBody.querySelector('.ag2-pub-svc-empty').onclick = () => openServiceModal(allAgents, ag.aid);
    } else {
      for (const svc of ag.services) {
        const row = document.createElement('div');
        row.className = 'ag2-svc-row';
        const isDemo = svc.topic === 'demo.echo';
        const protos = (svc.protocols || []).map((p) => `<span class="badge b-gray">${esc(p)}</span>`).join(' ');
        const tags = (svc.tags || []).map((x) => `<span class="muted">#${esc(x)}</span>`).join(' ');
        const ttlStr = fmtTtl(svc.ttl);
        row.innerHTML = `
          <div class="ag2-svc-top">
            <span class="svc-name">${esc(svc.topic || '')}</span>
            ${isDemo ? `<span class="badge b-blue demo-badge">${esc(t('demo.badge'))}</span>` : ''}
            ${protos}
            <span class="muted ag2-svc-ttl">${esc(t('agent.svc.ttl', { v: ttlStr }))}</span>
            <span class="ag2-svc-actions">
              ${isDemo
                ? `<button type="button" class="btn btn-ghost btn-xs" data-demo-stop>${esc(t('demo.stop'))}</button>`
                : `<button type="button" class="btn btn-ghost btn-xs" data-ed>${esc(t('service.action.edit'))}</button>
                   <button type="button" class="btn btn-ghost btn-xs" data-un>${esc(t('service.action.unpublish'))}</button>`}
            </span>
          </div>
          ${svc.name || svc.brief || tags ? `<div class="ag2-svc-detail">
            ${svc.name ? `<strong>${esc(svc.name)}</strong> ` : ''}${tags}
            ${svc.brief ? `<span class="muted" style="margin-left:.25rem">${esc(svc.brief)}</span>` : ''}
          </div>` : ''}`;
        if (isDemo) {
          row.querySelector('[data-demo-stop]').onclick = async (ev) => {
            const b = ev.currentTarget;
            setLoading(b, true);
            try {
              await api('/demo/stop', { method: 'POST', body: JSON.stringify({ aid: ag.aid }) });
              toast(t('demo.stopped'), 'ok');
              onRefresh();
            } catch (e) { toast(t('common.error', { msg: e.message }), 'err'); }
            finally { setLoading(b, false); }
          };
        } else {
          row.querySelector('[data-ed]').onclick = () => openServiceModal(allAgents, ag.aid, svc);
          row.querySelector('[data-un]').onclick = async () => {
            if (!confirm(t('service.action.unpublish') + '?')) return;
            try {
              await api(`/agents/${encodeURIComponent(ag.aid)}/services/${encodeURIComponent(svc.topic)}`, {
                method: 'DELETE', body: '{}',
              });
              toast(t('service.unpublish.notice'), 'warn');
              onRefresh();
            } catch (e) { toast(t('common.error', { msg: e.message }), 'err'); }
          };
        }
        svcBody.appendChild(row);
      }
    }
    card.appendChild(svcBody);

    // toggle services
    svcHeader.querySelector('.ag2-svc-toggle').onclick = () => {
      const open = svcBody.style.display !== 'none';
      svcBody.style.display = open ? 'none' : '';
      svcHeader.querySelector('.ag2-toggle-arrow').textContent = open ? '▶' : '▼';
    };
    svcHeader.querySelector('.ag2-pub-svc-hdr').onclick = () => openServiceModal(allAgents, ag.aid);

    // ── § Function area ──
    const fnBar = document.createElement('div');
    fnBar.className = 'ag2-fn-bar';
    const FNS = [
      { key: 'card',       label: t('agent.fn.card') },
      { key: 'network',    label: t('agent.fn.network') },
      { key: 'recv',       label: t('agent.fn.recv_notes') },
      { key: 'send',       label: t('agent.fn.send_note') },
      { key: 'ping',       label: t('agent.fn.ping') },
    ];
    FNS.forEach(({ key, label }) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-ghost btn-sm ag2-fn-btn';
      btn.dataset.fn = key;
      btn.textContent = label;
      fnBar.appendChild(btn);
    });
    card.appendChild(fnBar);

    const fnPanel = document.createElement('div');
    fnPanel.className = 'ag2-fn-panel';
    fnPanel.style.display = 'none';
    card.appendChild(fnPanel);

    let activeFn = null;
    fnBar.querySelectorAll('.ag2-fn-btn').forEach((btn) => {
      btn.onclick = () => {
        const fn = btn.dataset.fn;
        if (activeFn === fn) {
          activeFn = null;
          fnPanel.style.display = 'none';
          fnPanel.innerHTML = '';
          fnBar.querySelectorAll('.ag2-fn-btn').forEach((b) => b.classList.remove('active'));
          return;
        }
        activeFn = fn;
        fnBar.querySelectorAll('.ag2-fn-btn').forEach((b) => b.classList.toggle('active', b.dataset.fn === fn));
        fnPanel.style.display = '';
        fnPanel.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
        renderFnPanel(fn, ag, fnPanel, allAgents);
      };
    });

    return card;
  }

  // ── Function panel content ───────────────────────────────────────────────
  async function renderFnPanel(fn, ag, panel, allAgents) {
    switch (fn) {
      case 'card': {
        if (!ag.service_tcp) {
          panel.innerHTML = `<p class="muted">${esc(t('agent.fn.card.no_tcp'))}</p>`;
          return;
        }
        panel.innerHTML = `<p class="muted">${esc(t('discover.card.fetching'))}</p>`;
        try {
          let got = null;
          for (const path of ['/.well-known/agent.json', '/.well-known/mcp.json']) {
            try {
              const cr = await api(`/connect/${encodeURIComponent(ag.aid)}`, { method: 'POST', body: '{}' });
              const res = await fetch('http://' + cr.tunnel + path, { mode: 'cors' });
              if (res.ok) { got = { json: await res.json(), path }; break; }
            } catch (_) {}
          }
          if (!got) { panel.innerHTML = `<p class="muted">${esc(t('discover.card_failed'))}</p>`; return; }
          const p = parseCardData(got.json);
          if (!p) { panel.innerHTML = `<p class="muted">${esc(t('discover.card_failed'))}</p>`; return; }
          panel.innerHTML = `
            <div class="muted" style="font-size:.8rem;margin-bottom:.5rem">${esc(got.path)}</div>
            <div><strong>${esc(t('discover.detail.card.name'))}</strong> ${esc(p.name)}</div>
            <div><strong>${esc(t('discover.detail.card.ver'))}</strong> ${esc(p.version)}</div>
            ${p.caps ? `<div><strong>${esc(t('discover.detail.card.caps'))}</strong> ${esc(p.caps)}</div>` : ''}
            ${p.tools.length ? `<div><strong>${esc(t('discover.detail.card.tools'))}</strong> ${esc(p.tools.join(', '))}</div>` : ''}`;
        } catch (e) {
          panel.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
        }
        break;
      }
      case 'network': {
        panel.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
        try {
          const r = await api(`/agents/${encodeURIComponent(ag.aid)}`);
          const eps = Array.isArray(r.published_endpoints) && r.published_endpoints.length
            ? r.published_endpoints.map((e) => `<span class="mono" style="font-size:.83rem">${esc(e)}</span>`).join('<br/>')
            : '—';
          const nat = r.published_nat_type != null ? natLabel(t, r.published_nat_type) : '—';
          panel.innerHTML = `
            <div style="margin-bottom:.35rem"><strong>${esc(t('agent.fn.network.endpoints'))}</strong><br/>${eps}</div>
            <div><strong>${esc(t('agent.fn.network.nat'))}</strong> ${esc(nat)}</div>`;
        } catch (e) {
          panel.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
        }
        break;
      }
      case 'recv': {
        panel.innerHTML = `
          <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.6rem">
            <button type="button" class="btn btn-secondary btn-sm" id="fn-poll">${esc(t('agent.note.poll'))}</button>
            <span id="fn-poll-status" class="muted" style="font-size:.85rem"></span>
          </div>
          <div id="fn-notes"></div>`;
        const doPoll = async () => {
          const b = panel.querySelector('#fn-poll');
          const noteList = panel.querySelector('#fn-notes');
          const status = panel.querySelector('#fn-poll-status');
          setLoading(b, true);
          noteList.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
          status.textContent = '';
          try {
            const r = await api(`/agents/${encodeURIComponent(ag.aid)}/mailbox/poll`, { method: 'POST', body: '{}' });
            const msgs = r.messages || [];
            if (!msgs.length) { noteList.innerHTML = `<p class="muted">${esc(t('agent.note.empty'))}</p>`; return; }
            noteList.innerHTML = '';
            for (const m of msgs) {
              let bodyText = m.body_base64 || '';
              if (Number(m.msg_type) === 3 && bodyText) {
                try {
                  const bin = atob(bodyText);
                  const bytes = new Uint8Array(bin.length);
                  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
                  bodyText = new TextDecoder().decode(bytes);
                } catch (_) {}
              }
              const row = document.createElement('div');
              row.className = 'ag2-note-row';
              row.innerHTML = `
                <div class="muted" style="font-size:.82rem">${esc(t('agent.note.from'))} ${esc(shortAid(m.sender || ''))} · type ${esc(String(m.msg_type))}</div>
                <div style="margin-top:.25rem;white-space:pre-wrap">${esc(bodyText)}</div>`;
              noteList.appendChild(row);
            }
          } catch (e) {
            noteList.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
          } finally {
            setLoading(b, false);
          }
        };
        panel.querySelector('#fn-poll').onclick = doPoll;
        // Auto-execute on open
        doPoll();
        break;
      }
      case 'send': {
        const others = allAgents.filter((a) => a.aid !== ag.aid);
        const optsHtml =
          `<option value="">${esc(t('agent.note.send.manual'))}</option>` +
          others.map((a) => `<option value="${esc(a.aid)}">${esc(labelAid(a.aid))}</option>`).join('');
        panel.innerHTML = `
          <strong style="font-size:.9rem;display:block;margin-bottom:.6rem">${esc(t('agent.fn.send_note'))}</strong>
          <div class="field" style="margin-bottom:.5rem">
            <label style="font-size:.85rem;display:block;margin-bottom:.25rem">${esc(t('agent.note.send.recipient'))}</label>
            <select id="fn-sel" style="margin-bottom:.35rem;width:100%">${optsHtml}</select>
            <input type="text" id="fn-aid" placeholder="${esc(t('agent.note.send.manual'))}" class="mono" style="width:100%" />
          </div>
          <div class="field">
            <label style="font-size:.85rem;display:block;margin-bottom:.25rem">${esc(t('agent.note.send.body'))}</label>
            <div style="display:flex;gap:.35rem;flex-wrap:wrap;align-items:flex-start">
              <input type="text" id="fn-txt" style="flex:1;min-width:10rem" />
              <button type="button" class="btn btn-primary btn-sm" id="fn-go">${esc(t('agent.note.send.btn'))}</button>
            </div>
          </div>`;
        const sel = panel.querySelector('#fn-sel');
        const aidIn = panel.querySelector('#fn-aid');
        sel.onchange = () => { if (sel.value) { aidIn.value = sel.value; } };
        aidIn.oninput = () => { if (aidIn.value.trim()) sel.value = ''; };
        panel.querySelector('#fn-go').onclick = async (ev) => {
          const recipient = aidIn.value.trim() || sel.value;
          if (!recipient) { toast(t('discover.msg.need_from'), 'warn'); return; }
          const txt = panel.querySelector('#fn-txt').value;
          if (!txt) return;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const bytes = new TextEncoder().encode(txt);
            let bin = '';
            bytes.forEach((byte) => { bin += String.fromCharCode(byte); });
            await api(`/agents/${encodeURIComponent(ag.aid)}/mailbox/send`, {
              method: 'POST',
              body: JSON.stringify({ recipient, msg_type: 3, body_base64: btoa(bin) }),
            });
            toast(t('common.sent'), 'ok');
            panel.querySelector('#fn-txt').value = '';
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
        break;
      }
      case 'ping': {
        panel.innerHTML = `
          <div style="display:flex;gap:.75rem;align-items:center;flex-wrap:wrap">
            <button type="button" class="btn btn-secondary btn-sm" id="fn-ping-btn">${esc(t('discover.ping'))}</button>
            <span id="fn-ping-out" class="muted" style="font-size:.9rem"></span>
          </div>`;
        const doPing = async () => {
          const b = panel.querySelector('#fn-ping-btn');
          const el = panel.querySelector('#fn-ping-out');
          setLoading(b, true);
          el.style.color = '';
          el.textContent = t('common.loading');
          const t0 = performance.now();
          try {
            await api(`/connect/${encodeURIComponent(ag.aid)}`, { method: 'POST', body: '{}' });
            el.textContent = t('discover.ping.ok', { ms: Math.round(performance.now() - t0) });
            el.style.color = 'var(--success)';
          } catch (e) {
            el.textContent = t('discover.ping.fail') + ': ' + e.message;
            el.style.color = 'var(--error)';
          } finally {
            setLoading(b, false);
          }
        };
        panel.querySelector('#fn-ping-btn').onclick = doPing;
        // Auto-execute on open
        doPing();
        break;
      }    }
  }

  // ── Modal functions (unchanged) ─────────────────────────────────────────

  function openCreateModal() {
    let step = 1;
    let gen = null;
    openModal({
      title: t('agent.modal.create.title'),
      body: `<div id="cmBody"></div>`,
      onMount(root, { close }) {
        const body = root.querySelector('#cmBody');
        function render() {
          if (step === 1) {
            body.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
            api('/identity/generate', { method: 'POST', body: '{}' })
              .then((r) => {
                gen = r;
                step = 2;
                render();
              })
              .catch((e) => {
                body.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
              });
            return;
          }
          if (step === 2 && gen) {
            body.innerHTML = `
              <div class="field">
                <label>AID</label>
                <input readonly class="mono" value="${esc(gen.aid)}" style="width:100%" />
              </div>
              <div class="warn-box">${esc(t('agent.modal.masterkey.warning')).replace(/\n/g, '<br/>')}</div>
              <div class="field">
                <label>${esc(t('agent.modal.masterkey.key_label'))}</label>
                <textarea readonly rows="3" class="mono" style="width:100%;font-size:.78rem">${esc(gen.master_private_key_hex)}</textarea>
                <button type="button" class="btn btn-primary btn-sm" style="margin-top:.5rem;width:100%" id="cmCopy">\u29c9 ${esc(t('agent.modal.masterkey.copy_btn'))}</button>
              </div>
              <label class="chk" style="margin-bottom:.5rem"><input type="checkbox" id="cmOk" /> <span>${esc(t('agent.modal.masterkey.confirm'))}</span></label>
              <details style="margin-top:1rem">
                <summary>${esc(t('agent.modal.advanced'))}</summary>
                <div class="field" style="margin-top:.75rem">
                  <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
                  <input type="text" id="cmTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
                  <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
                </div>
              </details>
              <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
                <button type="button" class="btn btn-secondary" id="cmReg">${esc(t('agent.modal.submit'))}</button>
              </div>`;
            body.querySelector('#cmCopy').onclick = () =>
              navigator.clipboard.writeText(gen.master_private_key_hex)
                .then(() => toast(t('common.copied'), 'ok', 1200));
            // Enable Register only after confirming key is saved
            const cmOk = body.querySelector('#cmOk');
            const cmReg = body.querySelector('#cmReg');
            cmOk.addEventListener('change', () => {
              cmReg.className = cmOk.checked ? 'btn btn-primary' : 'btn btn-secondary';
            });
            body.querySelector('#cmReg').onclick = async (ev) => {
              if (!body.querySelector('#cmOk').checked) {
                toast(t('agent.modal.masterkey.confirm'), 'warn');
                return;
              }
              const b = ev.currentTarget;
              setLoading(b, true);
              try {
                const tcp = normalizeServiceTCP(body.querySelector('#cmTcp').value);
                const r = await api('/agents', {
                  method: 'POST',
                  body: JSON.stringify({
                    operational_private_key_hex: gen.operational_private_key_hex,
                    delegation_proof_hex: gen.delegation_proof_hex,
                    service_tcp: tcp,
                  }),
                });
                toast(r.aid, 'ok');
                try {
                  await api(`/agents/${encodeURIComponent(r.aid)}/publish`, {
                    method: 'POST',
                    body: '{}',
                  });
                } catch (_) {}
                close();
                onRefresh();
              } catch (e) {
                toast(t('common.error', { msg: e.message }), 'err');
              } finally {
                setLoading(b, false);
              }
            };
          }
        }
        render();
      },
    });
  }

  function openImportModal() {
    openModal({
      title: t('agent.modal.import.title'),
      body: `
        <div class="field">
          <label>${esc(t('agent.modal.import.op_key.label'))}</label>
          <textarea id="imOp" rows="2" class="mono" style="width:100%"></textarea>
        </div>
        <div class="field">
          <label>${esc(t('agent.modal.import.del_proof.label'))}</label>
          <textarea id="imDel" rows="3" class="mono" style="width:100%"></textarea>
        </div>
        <div class="field">
          <label>${esc(t('agent.modal.import.or_file'))}</label>
          <input type="file" id="imFile" accept=".json,application/json" />
        </div>
        <details style="margin-top:.5rem">
          <summary>${esc(t('agent.modal.advanced'))}</summary>
          <div class="field" style="margin-top:.75rem">
            <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
            <input type="text" id="imTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
            <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
          </div>
        </details>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="imGo">${esc(t('agent.modal.submit'))}</button>
        </div>`,
      onMount(root, { close }) {
        root.querySelector('#imFile').onchange = (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const rd = new FileReader();
          rd.onload = () => {
            try {
              const j = JSON.parse(String(rd.result));
              if (j.operational_private_key_hex)
                root.querySelector('#imOp').value = j.operational_private_key_hex;
              if (j.delegation_proof_hex) root.querySelector('#imDel').value = j.delegation_proof_hex;
            } catch (_) {
              toast(t('common.error', { msg: 'JSON' }), 'err');
            }
          };
          rd.readAsText(f);
        };
        root.querySelector('#imGo').onclick = async (ev) => {
          const op = root.querySelector('#imOp').value.trim();
          const del = root.querySelector('#imDel').value.trim();
          const tcp = normalizeServiceTCP(root.querySelector('#imTcp').value);
          if (!op || !del) return;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const r = await api('/agents', {
              method: 'POST',
              body: JSON.stringify({
                operational_private_key_hex: op,
                delegation_proof_hex: del,
                service_tcp: tcp,
              }),
            });
            toast(r.aid, 'ok');
            try {
              await api(`/agents/${encodeURIComponent(r.aid)}/publish`, {
                method: 'POST',
                body: '{}',
              });
            } catch (_) {}
            close();
            onRefresh();
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
      },
    });
  }

  function openEthModal() {
    let ethOpSeedHex = '';
    let ethDelMessage = '';
    let ethSigHex = '';
    let ethIssuedUsed = 0;
    let ethExpiresUsed = 0;
    const ethScopeUsed = 1;
    openModal({
      title: t('agent.modal.eth.title'),
      footer: t('agent.modal.eth.footer'),
      wide: true,
      body: `
        <p class="muted" style="margin-bottom:1rem">${esc(t('agent.modal.eth.intro')).replace(/\n/g, '<br/>')}</p>
        <div class="field"><label>Ethereum address <span class="badge b-red req-badge" style="font-size:.72rem;vertical-align:middle">*</span></label><input type="text" id="ethAgent" readonly class="mono" style="width:100%" placeholder="${esc(t('agent.modal.eth.addr_placeholder'))}" /></div>
        <button type="button" class="btn btn-secondary" id="eth1">1 · MetaMask · delegation message</button>
        <div class="field" style="margin-top:.75rem"><label>Message <span class="badge b-red req-badge" style="font-size:.72rem;vertical-align:middle">*</span></label><textarea id="ethMsg" rows="2" readonly class="mono" style="width:100%"></textarea></div>
        <button type="button" class="btn btn-secondary" id="eth2" disabled>2 · Sign in MetaMask</button>
        <div class="field" style="margin-top:.75rem">
          <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
          <input type="text" id="ethTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
          <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
        </div>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-secondary" id="eth3">3 · ${esc(t('agent.modal.submit'))}</button>
        </div>`,
      onMount(root, { close }) {
        const eth = window.ethereum;
        root.querySelector('#eth1').onclick = async (ev) => {
          if (!eth) {
            toast(t('agent.eth.metamask'), 'err');
            return;
          }
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            // wallet_requestPermissions forces account-chooser popup every time,
            // so users can switch addresses without revoking site access in MetaMask.
            try {
              await eth.request({ method: 'wallet_requestPermissions', params: [{ eth_accounts: {} }] });
            } catch (_) {
              // wallet not supporting requestPermissions — fall through to eth_requestAccounts
            }
            const accs = await eth.request({ method: 'eth_requestAccounts' });
            const agent = (accs[0] || '').toLowerCase();
            if (!/^0x[0-9a-fA-F]{40}$/.test(agent)) throw new Error('address');
            root.querySelector('#ethAgent').value = agent;
            // Mark address field as valid
            const addrBadge = root.querySelector('#ethAgent').closest('.field').querySelector('.req-badge');
            if (addrBadge) { addrBadge.className = 'badge b-green req-badge'; addrBadge.textContent = '✓'; addrBadge.style.fontSize = '.72rem'; addrBadge.style.verticalAlign = 'middle'; }
            const seedBytes = new Uint8Array(32);
            crypto.getRandomValues(seedBytes);
            ethOpSeedHex = Array.from(seedBytes, (x) => ('0' + x.toString(16)).slice(-2)).join('');
            const issued = Math.floor(Date.now() / 1000);
            ethIssuedUsed = issued;
            ethExpiresUsed = 0;
            const r = await api('/agents/ethereum/delegation-message', {
              method: 'POST',
              body: JSON.stringify({
                operational_private_key_seed_hex: ethOpSeedHex,
                agent,
                issued_at: issued,
                expires_at: 0,
                scope: ethScopeUsed,
              }),
            });
            ethDelMessage = r.message;
            root.querySelector('#ethMsg').value = ethDelMessage;
            // Mark message field as valid
            const msgBadge = root.querySelector('#ethMsg').closest('.field').querySelector('.req-badge');
            if (msgBadge) { msgBadge.className = 'badge b-green req-badge'; msgBadge.textContent = '✓'; msgBadge.style.fontSize = '.72rem'; msgBadge.style.verticalAlign = 'middle'; }
            root.querySelector('#eth2').disabled = false;
            toast('ok', 'ok');
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
        root.querySelector('#eth2').onclick = async (ev) => {
          if (!eth) return;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const want = root.querySelector('#ethAgent').value.trim().toLowerCase();
            const accs = await eth.request({ method: 'eth_requestAccounts' });
            const ac = (accs[0] || '').toLowerCase();
            if (ac !== want) throw new Error('account mismatch');
            const sig = await eth.request({
              method: 'personal_sign',
              params: [ethDelMessage, accs[0]],
            });
            ethSigHex = String(sig).startsWith('0x') ? String(sig).slice(2) : String(sig);
            // All steps done — activate the register button
            root.querySelector('#eth3').className = 'btn btn-primary';
            toast('ok', 'ok');
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
        root.querySelector('#eth3').onclick = async (ev) => {
          const agent = root.querySelector('#ethAgent').value.trim();
          const tcp = normalizeServiceTCP(root.querySelector('#ethTcp').value);
          if (!agent || !ethDelMessage) {
            toast(t('agent.eth.need_step1'), 'warn');
            return;
          }
          if (!ethSigHex) {
            toast(t('agent.eth.need_step2'), 'warn');
            return;
          }
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const r = await api('/agents/ethereum/register', {
              method: 'POST',
              body: JSON.stringify({
                agent,
                issued_at: ethIssuedUsed,
                expires_at: ethExpiresUsed,
                scope: ethScopeUsed,
                eth_signature_hex: ethSigHex,
                service_tcp: tcp,
                operational_private_key_seed_hex: ethOpSeedHex,
              }),
            });
            toast(r.aid, 'ok');
            try {
              await api(`/agents/${encodeURIComponent(r.aid)}/publish`, {
                method: 'POST',
                body: '{}',
              });
            } catch (_) {}
            close();
            onRefresh();
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
      },
    });
  }

  function openServiceModal(agentList, editAid = null, editSvc = null) {
    const single = agentList.length === 1;
    const preTopic = editSvc?.topic || '';
    let preCat = 'lang';
    let preFn = '';
    let preQ = '';
    if (preTopic && preTopic.includes('.')) {
      const dot = preTopic.indexOf('.');
      preCat = preTopic.slice(0, dot) || 'lang';
      const rest = preTopic.slice(dot + 1);
      const dash = rest.indexOf('-');
      if (dash >= 0) {
        preFn = rest.slice(0, dash);
        preQ = rest.slice(dash + 1);
      } else preFn = rest;
    }
    const catBtns = CATS.map((c) => {
      const on = c === preCat && CATS.includes(preCat);
      return `<button type="button" data-cat="${c}" class="btn btn-secondary btn-sm${on ? ' cat-on' : ''}">${esc(c)}</button>`;
    }).join('');
    const customOn = !CATS.includes(preCat);
    openModal({
      title: t('service.modal.title'),
      wide: true,
      body: `
        ${single ? '' : `<div class="field"><label>${esc(t('service.modal.agent_pick'))}</label><select id="svAid">${agentList.map((a) => `<option value="${esc(a.aid)}" ${a.aid === editAid ? 'selected' : ''}>${esc(labelAid(a.aid))}</option>`).join('')}</select></div>`}
        <div class="field">
          <label>${esc(t('service.modal.import.label'))}</label>
          <div style="display:flex;gap:.35rem;flex-wrap:wrap">
            <input type="url" id="svUrl" style="flex:1;min-width:12rem" placeholder="${esc(t('service.modal.import.placeholder'))}" />
            <button type="button" class="btn btn-secondary" id="svFetch">${esc(t('service.modal.import.fetch'))}</button>
          </div>
        </div>
        <p class="muted" style="text-align:center">${esc(t('service.modal.import.or'))}</p>
        <div class="field">
          <label>${esc(t('service.modal.category.label'))}</label>
          <div class="cat-btns" id="svCats">${catBtns}<button type="button" data-cat="__" class="btn btn-secondary btn-sm${customOn ? ' cat-on' : ''}">${esc(t('service.modal.category.custom'))}</button></div>
          <input type="text" id="svCatC" class="${CATS.includes(preCat) ? 'hidden' : ''}" style="margin-top:.35rem" placeholder="category" value="${CATS.includes(preCat) ? '' : esc(preCat)}" />
        </div>
        <div class="field">
          <label>${esc(t('service.modal.func.label'))}</label>
          <input type="text" id="svFn" value="${esc(preFn)}" />
          <div class="hint">${esc(t('service.modal.func.hint'))}</div>
        </div>
        <div class="field">
          <label>${esc(t('service.modal.qualifier.label'))}</label>
          <input type="text" id="svQ" value="${esc(preQ)}" />
          <div class="hint">${esc(t('service.modal.qualifier.hint'))}</div>
        </div>
        <div class="muted" id="svPreview"></div>
        <div class="field">
          <label>${esc(t('service.modal.display_name'))}</label>
          <input type="text" id="svName" value="${esc(editSvc?.name || '')}" />
        </div>
        <div class="field">
          <label>${esc(t('service.modal.brief'))}</label>
          <textarea id="svBrief" rows="2" style="width:100%">${esc(editSvc?.brief || '')}</textarea>
        </div>
        <div class="field">
          <label>${esc(t('service.modal.protocols'))}</label>
          <label class="chk"><input type="checkbox" id="svMcp" ${!editSvc || (editSvc.protocols || []).includes('mcp') ? 'checked' : ''} /> mcp</label>
          <label class="chk"><input type="checkbox" id="svA2a" ${editSvc && (editSvc.protocols || []).includes('a2a') ? 'checked' : ''} /> a2a</label>
          <label class="chk"><input type="checkbox" id="svHttp" ${editSvc && (editSvc.protocols || []).includes('http') ? 'checked' : ''} /> http</label>
        </div>
        <div class="field">
          <label>${esc(t('service.modal.tags.label'))}</label>
          <input type="text" id="svTags" value="${esc((editSvc?.tags || []).join(' '))}" />
          <div class="hint">${esc(t('service.modal.tags.hint'))}</div>
        </div>
        <div class="field">
          <label>${esc(t('service.modal.url.label'))}</label>
          <input type="url" id="svMetaUrl" value="${esc(editSvc?.meta?.url || editSvc?.meta?.URL || '')}" />
          <div class="hint">${esc(t('service.modal.url.hint'))}</div>
        </div>
        <details>
          <summary>${esc(t('agent.modal.advanced'))}</summary>
          <div class="field" style="margin-top:.75rem">
            <label>${esc(t('service.modal.ttl.label'))}</label>
            <input type="number" id="svTtl" value="${editSvc?.ttl || 3600}" min="0" />
          </div>
        </details>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="svGo">${esc(t('service.modal.submit'))}</button>
        </div>`,
      onMount(root, { close }) {
        let cat = CATS.includes(preCat) ? preCat : '__';
        if (!CATS.includes(preCat)) cat = '__';

        function currentCat() {
          if (cat === '__') return root.querySelector('#svCatC').value.trim().toLowerCase();
          return cat;
        }

        function updPreview() {
          const name = buildServiceName(currentCat(), root.querySelector('#svFn').value, root.querySelector('#svQ').value);
          root.querySelector('#svPreview').textContent = `${t('service.modal.preview')} ${name || '—'}`;
        }
        root.querySelector('#svCats').onclick = (e) => {
          const btn = e.target.closest('[data-cat]');
          if (!btn) return;
          const c = btn.getAttribute('data-cat');
          cat = c;
          root.querySelectorAll('#svCats button').forEach((b) => b.classList.remove('cat-on'));
          btn.classList.add('cat-on');
          const cust = root.querySelector('#svCatC');
          if (c === '__') cust.classList.remove('hidden');
          else cust.classList.add('hidden');
          updPreview();
        };
        ['#svFn', '#svQ', '#svCatC'].forEach((sel) => {
          root.querySelector(sel).addEventListener('input', updPreview);
        });
        updPreview();

        root.querySelector('#svFetch').onclick = async (ev) => {
          const u = root.querySelector('#svUrl').value.trim();
          if (!u) return;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const r = await fetch(u, { mode: 'cors' });
            if (!r.ok) throw new Error(String(r.status));
            const j = await r.json();
            const m = mapCardJson(j);
            if (m.name) root.querySelector('#svName').value = m.name;
            if (m.brief) root.querySelector('#svBrief').value = m.brief;
            if (m.url) root.querySelector('#svMetaUrl').value = m.url;
            root.querySelector('#svMcp').checked = m.protocols.includes('mcp');
            root.querySelector('#svA2a').checked = m.protocols.includes('a2a');
            toast('ok', 'ok');
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };

        root.querySelector('#svGo').onclick = async (ev) => {
          const aid = single
            ? agentList[0].aid
            : root.querySelector('#svAid').value;
          const full = buildServiceName(
            currentCat(),
            root.querySelector('#svFn').value,
            root.querySelector('#svQ').value,
          );
          if (!full) return;
          const protos = [];
          if (root.querySelector('#svMcp').checked) protos.push('mcp');
          if (root.querySelector('#svA2a').checked) protos.push('a2a');
          if (root.querySelector('#svHttp').checked) protos.push('http');
          const url = root.querySelector('#svMetaUrl').value.trim();
          const meta = url ? { url } : {};
          const ttl = parseInt(root.querySelector('#svTtl').value, 10) || 3600;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            await api(`/agents/${encodeURIComponent(aid)}/services`, {
              method: 'POST',
              body: JSON.stringify({
                services: [full],
                name: root.querySelector('#svName').value.trim(),
                protocols: protos,
                tags: parseTags(root.querySelector('#svTags').value),
                brief: root.querySelector('#svBrief').value.trim(),
                meta,
                ttl,
              }),
            });
            toast('ok', 'ok');
            close();
            onRefresh();
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
      },
    });
  }
}
