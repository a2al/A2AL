import { esc, shortAid, setLoading } from '../util.js';

const QUICK = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];

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

export async function renderDiscover(mount, ctx) {
  const { t, api, toast, relTime, copyText } = ctx;
  let agents = [];
  try {
    const r = await api('/agents');
    agents = r.agents || [];
  } catch (_) {}

  const wrap = document.createElement('div');
  wrap.innerHTML = `
    <p class="muted" style="margin-bottom:1rem">${esc(t('discover.subtitle'))}</p>
    <div class="discover-search">
      <input type="text" id="dq" placeholder="${esc(t('discover.placeholder'))}" />
      <button type="button" class="btn btn-primary" id="ds">${esc(t('discover.search'))}</button>
    </div>
    <div class="cat-btns" style="margin-bottom:1rem" id="dqCat"></div>
    <div id="dout"></div>`;
  mount.appendChild(wrap);
  const q = wrap.querySelector('#dq');
  const out = wrap.querySelector('#dout');
  const cat = wrap.querySelector('#dqCat');
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

  let selected = null;
  let fetchAborter = null;
  let tunnel = null;

  async function search() {
    const term = q.value.trim();
    if (!term) return;
    const btn = wrap.querySelector('#ds');
    setLoading(btn, true);
    selected = null;
    tunnel = null;
    out.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
    try {
      const r = await api('/discover', {
        method: 'POST',
        body: JSON.stringify({ services: [term] }),
      });
      const entries = r.entries || [];
      out.innerHTML = '';
      const count = document.createElement('p');
      count.className = 'muted';
      count.textContent = t('discover.results.count', { n: entries.length });
      out.appendChild(count);
      if (!entries.length) {
        out.appendChild(
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
            <button type="button" class="btn btn-secondary btn-sm" data-det>${esc(t('discover.result.detail'))}</button>
          </div>
          <div>${esc(e.name || '')} · ${esc(shortAid(aid))} <button type="button" class="btn btn-ghost btn-sm" data-cp>⧉</button></div>
          ${e.brief ? `<div class="muted" style="margin-top:.35rem">${esc(e.brief)}</div>` : ''}`;
        row.querySelector('[data-cp]').onclick = () => copyText(aid);
        row.querySelector('[data-det]').onclick = () => showDetail(e);
        out.appendChild(row);
      }
    } catch (e) {
      out.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    } finally {
      setLoading(btn, false);
    }
  }

  wrap.querySelector('#ds').onclick = search;
  q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') search();
  });

  function showDetail(entry) {
    out.querySelectorAll('.detail-panel').forEach((el) => el.remove());
    selected = entry;
    tunnel = null;
    if (fetchAborter) fetchAborter.abort();
    const panel = document.createElement('div');
    panel.className = 'detail-panel';
    panel.innerHTML = `
      <div><strong>AID</strong> ${esc(shortAid(entry.aid))} <button type="button" class="btn btn-ghost btn-sm" data-cp>⧉</button></div>
      <div class="muted" style="margin:.5rem 0">${esc(entry.service || '')}</div>
      ${entry.brief ? `<div>${esc(entry.brief)}</div>` : ''}
      <p class="muted" id="dfetch">${esc(t('discover.detail.fetching'))}</p>
      <div id="dcard" class="hidden"></div>
      <div style="margin-top:.75rem;display:flex;gap:.5rem;flex-wrap:wrap">
        <button type="button" class="btn btn-ghost btn-sm" id="dskip">${esc(t('discover.detail.skip'))}</button>
        <button type="button" class="btn btn-primary btn-sm hidden" id="dconn">${esc(t('discover.detail.connect'))}</button>
      </div>
      <div id="dreq" class="hidden" style="margin-top:1rem;border-top:1px solid var(--border);padding-top:1rem"></div>`;
    out.appendChild(panel);
    panel.querySelector('[data-cp]').onclick = () => copyText(entry.aid);
    panel.querySelector('#dskip').onclick = () => {
      if (fetchAborter) fetchAborter.abort();
      panel.querySelector('#dfetch').classList.add('hidden');
    };

    fetchAborter = new AbortController();
    const sig = fetchAborter.signal;
    (async () => {
      try {
        const r = await api(`/connect/${encodeURIComponent(entry.aid)}`, {
          method: 'POST',
          body: JSON.stringify({}),
        });
        if (sig.aborted) return;
        tunnel = r.tunnel;
        const base = 'http://' + tunnel;
        let cardJ = null;
        for (const path of ['/.well-known/agent.json', '/.well-known/mcp.json']) {
          try {
            const res = await fetch(base + path, { signal: sig, mode: 'cors' });
            if (res.ok) {
              cardJ = await res.json();
              break;
            }
          } catch (_) {}
        }
        panel.querySelector('#dfetch').classList.add('hidden');
        const slot = panel.querySelector('#dcard');
        slot.classList.remove('hidden');
        if (cardJ) {
          const p = parseCard(cardJ);
          slot.innerHTML = `
            <div><strong>${esc(t('discover.detail.card.name'))}</strong> ${esc(p.name)}</div>
            <div><strong>${esc(t('discover.detail.card.ver'))}</strong> ${esc(p.version)}</div>
            <div><strong>${esc(t('discover.detail.card.caps'))}</strong> ${esc(p.caps)}</div>
            <div><strong>${esc(t('discover.detail.card.tools'))}</strong> ${esc(p.tools.join(', '))}</div>
            ${p.url ? `<div><a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.url)}</a></div>` : ''}`;
          panel.querySelector('#dconn').classList.remove('hidden');
        } else {
          slot.innerHTML = `<p class="muted">${esc(t('discover.card_failed'))}</p>`;
          panel.querySelector('#dconn').classList.remove('hidden');
        }
      } catch (e) {
        if (e.name === 'AbortError') return;
        panel.querySelector('#dfetch').textContent = t('common.error', { msg: e.message });
      }
    })();

    panel.querySelector('#dconn').onclick = () => openReq(panel, entry);
  }

  function openReq(panel, entry) {
    if (!tunnel) {
      toast(t('common.error', { msg: 'tunnel' }), 'err');
      return;
    }
    const req = panel.querySelector('#dreq');
    req.classList.remove('hidden');
    const opts = `<option value="">${esc(t('discover.req.node_identity'))}</option>${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}`;
    req.innerHTML = `
      <h3 style="font-size:1rem;margin-bottom:.75rem">${esc(t('discover.req.title'))}</h3>
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
      const b = ev.currentTarget;
      setLoading(b, true);
      const path = req.querySelector('#rqP').value.trim() || '/';
      const method = m.value;
      const localAid = req.querySelector('#rqAid').value;
      const t0 = performance.now();
      try {
        const connectBody = localAid ? { local_aid: localAid } : {};
        const cr = await api(`/connect/${encodeURIComponent(entry.aid)}`, {
          method: 'POST',
          body: JSON.stringify(connectBody),
        });
        tunnel = cr.tunnel;
        const base = 'http://' + tunnel;
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
        setLoading(b, false);
      }
    };
  }
}
