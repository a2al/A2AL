import { esc, shortAid, setLoading } from '../util.js';

const QUICK = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];

function utf8ToBase64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
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
    caps = Object.entries(j.capabilities)
      .map(([k, v]) => `${k}: ${v}`)
      .join(', ');
  }
  const url = j.url || j.serverUrl || j.mcpEndpoint || '';
  return { name, version, caps, tools, url, raw: j };
}

async function fetchAgentCardThroughTunnel(api, aid) {
  const paths = ['/.well-known/agent.json', '/.well-known/mcp.json'];
  for (const path of paths) {
    try {
      const cr = await api(`/connect/${encodeURIComponent(aid)}`, {
        method: 'POST',
        body: '{}',
      });
      const res = await fetch('http://' + cr.tunnel + path, { mode: 'cors' });
      if (res.ok) {
        const j = await res.json();
        return { json: j, path };
      }
    } catch (_) {}
  }
  return null;
}

export async function renderDiscover(mount, ctx) {
  const { t, api, toast, copyText } = ctx;
  let agents = [];
  try {
    const r = await api('/agents');
    agents = r.agents || [];
  } catch (_) {}

  const agentOpts =
    agents.length === 0
      ? `<option value="">${esc(t('discover.myagent.empty'))}</option>`
      : `<option value="">${esc(t('discover.myagent.pick'))}</option>${agents
          .map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`)
          .join('')}`;

  const wrap = document.createElement('div');
  wrap.innerHTML = `
    <div class="discover-tabs" role="tablist">
      <button type="button" class="active" data-tab="aid">${esc(t('discover.tab.aid'))}</button>
      <button type="button" data-tab="svc">${esc(t('discover.tab.service'))}</button>
    </div>
    <div id="tabAid" class="discover-tab-panel">
      <div class="discover-search" style="margin-top:1rem">
        <input type="text" id="dAid" placeholder="${esc(t('discover.aid.placeholder'))}" class="mono" />
        <select id="dMyAg">${agentOpts}</select>
        <button type="button" class="btn btn-primary" id="dQuery">${esc(t('discover.query'))}</button>
      </div>
      <p class="muted aid-err hidden" id="dAidErr"></p>
    </div>
    <div id="tabSvc" class="discover-tab-panel hidden">
      <p class="muted" style="margin:1rem 0 .5rem">${esc(t('discover.subtitle'))}</p>
      <div class="discover-search">
        <input type="text" id="dq" placeholder="${esc(t('discover.placeholder'))}" />
        <button type="button" class="btn btn-primary" id="ds">${esc(t('discover.search'))}</button>
      </div>
      <div class="cat-btns" style="margin-bottom:1rem" id="dqCat"></div>
      <div id="dSvcOut"></div>
    </div>
    <div id="dOp" class="hidden" style="margin-top:1.25rem">
      <div class="card">
        <div class="card-b">
          <div style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin-bottom:1rem">
            <strong>${esc(t('discover.target'))}</strong>
            <span class="mono aid-short" id="dOpAid"></span>
            <button type="button" class="btn btn-ghost btn-sm" id="dOpCp">\u29c9</button>
          </div>
          <h3 class="disc-op-h">${esc(t('discover.section.dht'))}</h3>
          <div id="dResolve" class="disc-op-block muted">${esc(t('discover.resolve.idle'))}</div>
          <div id="dLocalSvc" class="disc-op-block hidden"></div>
          <div class="disc-op-block muted" style="margin-top:.75rem">
            <strong>${esc(t('discover.profile'))}</strong> ${esc(t('discover.profile.wip'))}
          </div>
          <div id="dMsgWrap" class="disc-op-block" style="margin-top:.75rem">
            <strong>${esc(t('discover.msg.send'))}</strong>
            <div class="field" style="margin-top:.35rem">
              <label>${esc(t('discover.msg.from'))}</label>
              <select id="dMsgFrom">${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}</select>
            </div>
            <div class="field" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:flex-end">
              <div style="flex:1;min-width:12rem">
                <label>${esc(t('discover.msg.body'))}</label>
                <input type="text" id="dMsgTxt" />
              </div>
              <button type="button" class="btn btn-secondary" id="dMsgGo">${esc(t('discover.msg.submit'))}</button>
            </div>
          </div>
          <h3 class="disc-op-h" style="margin-top:1.25rem">${esc(t('discover.section.connect'))}</h3>
          <div style="display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:.75rem">
            <button type="button" class="btn btn-secondary btn-sm" id="dPing">${esc(t('discover.ping'))}</button>
            <button type="button" class="btn btn-secondary btn-sm" id="dCard">${esc(t('discover.card'))}</button>
            <button type="button" class="btn btn-secondary btn-sm" id="dShowReq">${esc(t('discover.req.title'))}</button>
          </div>
          <div id="dPingOut" class="disc-op-block muted"></div>
          <div id="dCardOut" class="disc-op-block hidden"></div>
          <div id="dReq" class="hidden disc-op-block"></div>
        </div>
      </div>
    </div>`;

  mount.appendChild(wrap);

  if (!agents.length) {
    wrap.querySelector('#dMsgWrap').innerHTML = `<p class="muted">${esc(t('discover.msg.need_agent'))}</p>`;
  }

  const tabAid = wrap.querySelector('#tabAid');
  const tabSvc = wrap.querySelector('#tabSvc');
  const aidInput = wrap.querySelector('#dAid');
  const myAg = wrap.querySelector('#dMyAg');
  const opArea = wrap.querySelector('#dOp');
  const opAidEl = wrap.querySelector('#dOpAid');
  const resolveBox = wrap.querySelector('#dResolve');
  const localSvcBox = wrap.querySelector('#dLocalSvc');
  const aidErr = wrap.querySelector('#dAidErr');
  const svcOut = wrap.querySelector('#dSvcOut');
  const q = wrap.querySelector('#dq');
  const cat = wrap.querySelector('#dqCat');

  let currentAid = '';

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

  function switchTab(which) {
    wrap.querySelectorAll('.discover-tabs button').forEach((btn) => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === which);
    });
    tabAid.classList.toggle('hidden', which !== 'aid');
    tabSvc.classList.toggle('hidden', which !== 'svc');
  }

  wrap.querySelectorAll('.discover-tabs button').forEach((btn) => {
    btn.onclick = () => switchTab(btn.getAttribute('data-tab'));
  });

  myAg.onchange = () => {
    const v = myAg.value;
    if (v) aidInput.value = v;
  };

  function fmtEndpoints(ep) {
    if (ep == null) return '—';
    if (Array.isArray(ep)) return ep.map((x) => esc(String(x))).join(', ') || '—';
    return esc(String(ep));
  }

  function renderLocalServices(list) {
    if (!list || !list.length) {
      localSvcBox.innerHTML = `<p class="muted">${esc(t('discover.local_services.empty'))}</p>`;
      localSvcBox.classList.remove('hidden');
      return;
    }
    localSvcBox.classList.remove('hidden');
    localSvcBox.innerHTML = `<h4 style="font-size:.95rem;margin:0 0 .5rem">${esc(t('discover.local_services'))}</h4>`;
    for (const svc of list) {
      const topic = svc.topic || svc.Topic || '';
      const protos = (svc.protocols || []).map((p) => `<span class="badge b-gray">${esc(p)}</span>`).join(' ');
      const tags = (svc.tags || []).map((x) => `<span class="muted">#${esc(x)}</span>`).join(' ');
      const row = document.createElement('div');
      row.className = 'result-row';
      row.style.marginBottom = '0.5rem';
      row.innerHTML = `
        <div><span class="svc-name">${esc(topic)}</span> ${protos}</div>
        <div><strong>${esc(svc.name || '')}</strong> ${tags}</div>
        ${svc.brief ? `<div class="muted" style="margin-top:.25rem">${esc(svc.brief)}</div>` : ''}`;
      localSvcBox.appendChild(row);
    }
  }

  async function runQuery() {
    const raw = aidInput.value.trim();
    aidErr.classList.add('hidden');
    if (!raw) {
      aidErr.textContent = t('discover.aid.required');
      aidErr.classList.remove('hidden');
      return;
    }
    currentAid = raw;
    opArea.classList.remove('hidden');
    opAidEl.textContent = shortAid(currentAid);
    wrap.querySelector('#dOpCp').onclick = () => copyText(currentAid);
    resolveBox.textContent = t('common.loading');
    localSvcBox.classList.add('hidden');
    localSvcBox.innerHTML = '';
    wrap.querySelector('#dPingOut').textContent = '';
    wrap.querySelector('#dCardOut').classList.add('hidden');
    wrap.querySelector('#dCardOut').innerHTML = '';
    wrap.querySelector('#dReq').classList.add('hidden');
    wrap.querySelector('#dReq').innerHTML = '';

    const [resRes, agRes] = await Promise.allSettled([
      api(`/resolve/${encodeURIComponent(currentAid)}`, { method: 'POST', body: '{}' }),
      api(`/agents/${encodeURIComponent(currentAid)}`),
    ]);

    if (resRes.status === 'fulfilled') {
      const r = resRes.value;
      resolveBox.className = 'disc-op-block';
      resolveBox.innerHTML = `
        <div><strong>address</strong> <span class="mono">${esc(r.address || '')}</span></div>
        <div><strong>endpoints</strong> ${fmtEndpoints(r.endpoints)}</div>
        <div><strong>nat_type</strong> ${esc(String(r.nat_type ?? '—'))}</div>
        <div><strong>seq</strong> ${esc(String(r.seq ?? '—'))} &nbsp; <strong>TTL</strong> ${esc(String(r.ttl ?? '—'))}</div>
        <div><strong>timestamp</strong> ${esc(String(r.timestamp ?? '—'))}</div>`;
    } else {
      const e = resRes.reason;
      resolveBox.className = 'disc-op-block';
      resolveBox.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    }

    if (agRes.status === 'fulfilled') {
      renderLocalServices(agRes.value.services || []);
    } else {
      localSvcBox.classList.add('hidden');
    }
  }

  wrap.querySelector('#dQuery').onclick = runQuery;

  /** Service search */
  async function search() {
    const term = q.value.trim();
    if (!term) return;
    const btn = wrap.querySelector('#ds');
    setLoading(btn, true);
    svcOut.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    try {
      const r = await api('/discover', {
        method: 'POST',
        body: JSON.stringify({ services: [term] }),
      });
      const entries = r.entries || [];
      svcOut.innerHTML = '';
      const count = document.createElement('p');
      count.className = 'muted';
      count.textContent = t('discover.results.count', { n: entries.length });
      svcOut.appendChild(count);
      if (!entries.length) {
        svcOut.appendChild(
          Object.assign(document.createElement('p'), {
            className: 'muted',
            textContent: t('discover.results.empty'),
          }),
        );
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
            <span class="svc-name">${esc(svc)}</span>
            ${protos}
            <span style="flex:1"></span>
            <button type="button" class="btn btn-primary btn-sm" data-use>${esc(t('discover.result.use'))}</button>
          </div>
          <div>${esc(e.name || '')} · ${esc(shortAid(aid))} <button type="button" class="btn btn-ghost btn-sm" data-cp>\u29c9</button></div>
          ${e.brief ? `<div class="muted" style="margin-top:.35rem">${esc(e.brief)}</div>` : ''}`;
        row.querySelector('[data-cp]').onclick = () => copyText(aid);
        row.querySelector('[data-use]').onclick = () => {
          aidInput.value = aid;
          switchTab('aid');
          runQuery();
        };
        svcOut.appendChild(row);
      }
    } catch (e) {
      svcOut.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  }

  wrap.querySelector('#ds').onclick = search;
  q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') search();
  });
  aidInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runQuery();
  });

  /** Mailbox send */
  const msgFromEl = wrap.querySelector('#dMsgFrom');
  if (agents.length === 1 && msgFromEl) msgFromEl.value = agents[0].aid;
  const dMsgGo = wrap.querySelector('#dMsgGo');
  if (dMsgGo) {
    dMsgGo.onclick = async (ev) => {
      if (!currentAid) return;
      const from = wrap.querySelector('#dMsgFrom')?.value;
      if (!from) {
        toast(t('discover.msg.need_from'), 'warn');
        return;
      }
      const txt = wrap.querySelector('#dMsgTxt')?.value;
      if (!txt) return;
      const b = ev.currentTarget;
      setLoading(b, true);
      try {
        await api(`/agents/${encodeURIComponent(from)}/mailbox/send`, {
          method: 'POST',
          body: JSON.stringify({
            recipient: currentAid,
            msg_type: 3,
            body_base64: utf8ToBase64(txt),
          }),
        });
        toast(t('common.sent'), 'ok');
        const inp = wrap.querySelector('#dMsgTxt');
        if (inp) inp.value = '';
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(b, false);
      }
    };
  }

  /** Ping */
  wrap.querySelector('#dPing').onclick = async (ev) => {
    if (!currentAid) return;
    const el = wrap.querySelector('#dPingOut');
    const b = ev.currentTarget;
    setLoading(b, true);
    el.style.color = '';
    el.textContent = t('common.loading');
    const t0 = performance.now();
    try {
      await api(`/connect/${encodeURIComponent(currentAid)}`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      el.textContent = t('discover.ping.ok', { ms: Math.round(performance.now() - t0) });
      el.style.color = 'var(--success)';
    } catch (e) {
      el.textContent = t('discover.ping.fail') + ': ' + e.message;
      el.style.color = 'var(--error)';
    } finally {
      setLoading(b, false);
    }
  };

  /** Agent card */
  wrap.querySelector('#dCard').onclick = async (ev) => {
    if (!currentAid) return;
    const out = wrap.querySelector('#dCardOut');
    const b = ev.currentTarget;
    setLoading(b, true);
    out.classList.remove('hidden');
    out.innerHTML = `<p class="muted">${esc(t('discover.card.fetching'))}</p>`;
    try {
      const got = await fetchAgentCardThroughTunnel(api, currentAid);
      if (!got) {
        out.innerHTML = `<p class="muted">${esc(t('discover.card_failed'))}</p>`;
        return;
      }
      const p = parseCard(got.json);
      out.innerHTML = `
        <div class="muted" style="font-size:.8rem;margin-bottom:.35rem">${esc(got.path)}</div>
        <div><strong>${esc(t('discover.detail.card.name'))}</strong> ${esc(p.name)}</div>
        <div><strong>${esc(t('discover.detail.card.ver'))}</strong> ${esc(p.version)}</div>
        <div><strong>${esc(t('discover.detail.card.caps'))}</strong> ${esc(p.caps)}</div>
        <div><strong>${esc(t('discover.detail.card.tools'))}</strong> ${esc(p.tools.join(', '))}</div>
        ${p.url ? `<div><a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.url)}</a></div>` : ''}`;
    } catch (e) {
      out.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(b, false);
    }
  };

  /** HTTP request panel */
  function mountReq() {
    const req = wrap.querySelector('#dReq');
    req.classList.remove('hidden');
    if (req.dataset.mounted) return;
    req.dataset.mounted = '1';
    const opts = `<option value="">${esc(t('discover.req.node_identity'))}</option>${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}`;
    req.innerHTML = `
      <h4 style="font-size:.95rem;margin:0 0 .5rem">${esc(t('discover.req.title'))}</h4>
      <div class="field">
        <label>${esc(t('discover.req.identity'))}</label>
        <select id="rqAid">${opts}</select>
      </div>
      <div class="field" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
        <select id="rqM"><option>GET</option><option>POST</option></select>
        <input type="text" id="rqP" style="flex:1;min-width:8rem" placeholder="/" value="/" />
        <button type="button" class="btn btn-primary" id="rqGo">${esc(t('discover.req.send'))}</button>
      </div>
      <div class="field hidden" id="rqBodyW">
        <label>${esc(t('discover.req.body'))}</label>
        <textarea id="rqB" rows="3" style="width:100%" class="mono"></textarea>
      </div>
      <div><strong>${esc(t('discover.req.response'))}</strong></div>
      <pre class="resp" id="rqOut"></pre>
      <div class="muted" id="rqMeta"></div>`;
    const m = req.querySelector('#rqM');
    const bw = req.querySelector('#rqBodyW');
    m.onchange = () => {
      if (m.value === 'POST') bw.classList.remove('hidden');
      else bw.classList.add('hidden');
    };
    req.querySelector('#rqGo').onclick = async (ev) => {
      if (!currentAid) return;
      const btn = ev.currentTarget;
      setLoading(btn, true);
      const path = req.querySelector('#rqP').value.trim() || '/';
      const method = m.value;
      const localAid = req.querySelector('#rqAid').value;
      const t0 = performance.now();
      try {
        const connectBody = localAid ? { local_aid: localAid } : {};
        const cr = await api(`/connect/${encodeURIComponent(currentAid)}`, {
          method: 'POST',
          body: JSON.stringify(connectBody),
        });
        const base = 'http://' + cr.tunnel;
        const url = base + (path.startsWith('/') ? path : '/' + path);
        const opt = { method };
        if (method === 'POST') {
          opt.headers = { 'Content-Type': 'application/json' };
          opt.body = req.querySelector('#rqB').value || '{}';
        }
        const res = await fetch(url, opt);
        const txt = await res.text();
        let disp = txt;
        try {
          disp = JSON.stringify(JSON.parse(txt), null, 2);
        } catch (_) {}
        req.querySelector('#rqOut').textContent = disp;
        req.querySelector('#rqMeta').textContent = t('discover.req.status', {
          code: res.status,
          ms: Math.round(performance.now() - t0),
        });
      } catch (e) {
        req.querySelector('#rqOut').textContent = e.message;
        req.querySelector('#rqMeta').textContent = '';
      } finally {
        setLoading(btn, false);
      }
    };
  }

  wrap.querySelector('#dShowReq').onclick = () => mountReq();
}
