import { setLoading } from '../util.js';

const RESTART_FIELDS = new Set([
  'listen_addr',
  'quic_listen_addr',
  'bootstrap',
  'disable_upnp',
  'fallback_host',
  'min_observed_peers',
  'api_addr',
  'key_dir',
]);

const CFG_DEFAULTS = {
  listen_addr: ':4121',
  quic_listen_addr: '',
  bootstrap: [],
  disable_upnp: false,
  fallback_host: '',
  min_observed_peers: 3,
  api_addr: '127.0.0.1:2121',
  api_token: '',
  key_dir: '',
  log_format: 'text',
  log_level: 'info',
  auto_publish: true,
};

const CFG_EMPTY_NOTES = {
  quic_listen_addr: 'shared with Tangled port',
  fallback_host: 'disabled',
  key_dir: '<data-dir>/keys/',
  api_token: 'no authentication',
};

const NAT = {
  full_cone: { key: 'node.nat.full_cone', cls: 'b-green' },
  restricted: { key: 'node.nat.restricted', cls: 'b-yellow' },
  port_restricted: { key: 'node.nat.port_restricted', cls: 'b-yellow' },
  symmetric: { key: 'node.nat.symmetric', cls: 'b-red' },
  unknown: { key: 'node.nat.unknown', cls: 'b-gray' },
};

function cfgIsEmpty(k, val) {
  if (Array.isArray(val)) return val.length === 0;
  if (typeof val === 'boolean') return val === false;
  return val === '' || val === null || val === undefined;
}

function cfgIsDefault(k, val) {
  const def = CFG_DEFAULTS[k];
  if (Array.isArray(def)) return Array.isArray(val) && val.length === 0;
  return val === def;
}

export async function renderNode(mount, ctx) {
  const { t, api, toast, relTime, shortAid, esc, setToken } = ctx;
  const root = document.createElement('div');
  root.className = 'node-view';
  mount.appendChild(root);

  let host = null;
  let stats = null;
  let status = null;
  try {
    [host, stats, status] = await Promise.all([
      api('/debug/host'),
      api('/debug/stats'),
      api('/status'),
    ]);
  } catch (e) {
    root.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
    return;
  }

  const nat = NAT[host.nat_type_label] || NAT.unknown;
  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = `
    <div class="card-h">${esc(t('node.title'))}</div>
    <div class="card-b">
      <div class="meta-item" style="margin-bottom:.5rem">
        <span class="meta-label">${esc(t('node.aid'))}</span>
        <span class="mono">${esc(shortAid(host.address))}</span>
        <button type="button" class="btn btn-ghost btn-sm" data-copy-node>⧉</button>
        <button type="button" class="btn btn-ghost btn-sm" id="showFullAid">${esc(t('node.full_aid'))}</button>
      </div>
      <pre id="fullAid" class="hidden mono" style="font-size:.75rem;white-space:pre-wrap">${esc(host.address)}</pre>
      <div style="display:grid;gap:.35rem;font-size:.85rem">
        <div>${esc(t('node.dht'))}: <span class="mono">${esc(host.dht_addr || '—')}</span> · ${esc(t('node.quic'))}: <span class="mono">${esc(host.quic_addr || '—')}</span></div>
        <div>${esc(t('node.nat'))}: <span class="badge ${nat.cls}">${esc(t(nat.key))}</span>
        ${host.observed_host ? ` · ${esc(t('node.observed'))}: ${esc(host.observed_host)}:${esc(String(host.observed_port))}` : ''}</div>
        <div>${esc(t('node.peers'))}: ${esc(String(stats.total_peers ?? 0))}</div>
        <div>
          ${esc(t('node.auto_refresh'))}:
          <span class="badge ${status.auto_publish ? 'b-green' : 'b-gray'}">${status.auto_publish ? esc(t('node.auto_refresh.on')) : esc(t('node.auto_refresh.off'))}</span>
          <button type="button" class="btn btn-secondary btn-sm" id="togPub">${status.auto_publish ? esc(t('node.auto_refresh.disable')) : esc(t('node.auto_refresh.enable'))}</button>
        </div>
        <div class="muted">
          ${esc(t('node.last_refresh', { ago: status.node_last_publish_at ? relTime(status.node_last_publish_at) : '—' }))}
          · ${esc(t('node.next_refresh', { eta: status.node_next_republish_estimate ? relTime(status.node_next_republish_estimate) : '—' }))}
        </div>
      </div>
    </div>`;
  root.appendChild(card);
  card.querySelector('[data-copy-node]').onclick = () => {
    navigator.clipboard.writeText(host.address).then(() => toast(t('common.copied'), 'ok', 1200));
  };
  card.querySelector('#showFullAid').onclick = () => {
    card.querySelector('#fullAid').classList.toggle('hidden');
  };
  card.querySelector('#togPub').onclick = async (ev) => {
    const b = ev.currentTarget;
    setLoading(b, true);
    try {
      await api('/config', {
        method: 'PATCH',
        body: JSON.stringify({ auto_publish: !status.auto_publish }),
      });
      toast('ok', 'ok');
      ctx.onRefresh?.();
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    } finally {
      setLoading(b, false);
    }
  };

  const cfgCard = document.createElement('div');
  cfgCard.className = 'card';
  cfgCard.innerHTML = `<div class="card-h">${esc(t('node.config.title'))}</div><div class="card-b" id="cfgMount"></div>`;
  root.appendChild(cfgCard);
  const cfgMount = cfgCard.querySelector('#cfgMount');

  let schema = {};
  let cfg = {};
  try {
    const [sch, cf] = await Promise.all([api('/config/schema'), api('/config')]);
    schema = typeof sch === 'string' ? JSON.parse(sch) : sch;
    cfg = cf;
  } catch (e) {
    cfgMount.textContent = t('common.error', { msg: e.message });
    return;
  }

  let editing = false;
  const props = Object.keys(schema.properties || {});

  function renderCfg() {
    if (editing) return renderCfgEdit();
    cfgMount.innerHTML = `<div style="text-align:right;margin-bottom:.5rem"><button type="button" class="btn btn-secondary btn-sm" id="cfgEd">${esc(t('node.config.edit'))}</button></div>`;
    const tbl = document.createElement('table');
    tbl.className = 'cfg-table';
    const tb = document.createElement('tbody');
    for (const k of props) {
      const val = cfg[k];
      const tr = document.createElement('tr');
      const keyTd = document.createElement('td');
      keyTd.className = 'cfg-key';
      keyTd.textContent = k;
      if (RESTART_FIELDS.has(k)) {
        const sp = document.createElement('span');
        sp.className = 'restart-badge';
        sp.textContent = t('node.config.restart_needed');
        sp.title = t('node.config.restart_tooltip');
        keyTd.appendChild(sp);
      }
      const valTd = document.createElement('td');
      valTd.className = 'cfg-val';
      if (k === 'api_token' && val === '***') {
        valTd.innerHTML = `<span class="badge b-blue">set</span>`;
      } else if (cfgIsEmpty(k, val)) {
        const note = CFG_EMPTY_NOTES[k];
        valTd.textContent = note ? `— (${note})` : '—';
        if (note) valTd.classList.add('muted');
      } else if (Array.isArray(val)) {
        valTd.textContent = val.length ? val.join(', ') : '—';
      } else if (typeof val === 'boolean') {
        valTd.textContent = String(val);
      } else {
        valTd.textContent = String(val);
      }
      if (!cfgIsDefault(k, val) && !cfgIsEmpty(k, val)) {
        const d = document.createElement('div');
        d.className = 'muted';
        d.style.fontSize = '0.72rem';
        d.textContent = `${t('node.config.default')}: ${JSON.stringify(CFG_DEFAULTS[k])}`;
        valTd.appendChild(d);
      }
      tr.appendChild(keyTd);
      tr.appendChild(valTd);
      tb.appendChild(tr);
    }
    tbl.appendChild(tb);
    cfgMount.appendChild(tbl);
    cfgMount.querySelector('#cfgEd').onclick = () => {
      editing = true;
      renderCfg();
    };
  }

  function renderCfgEdit() {
    cfgMount.innerHTML = `<div style="text-align:right;margin-bottom:.5rem;gap:.35rem;display:flex;justify-content:flex-end">
      <button type="button" class="btn btn-secondary btn-sm" id="cfgCx">${esc(t('node.config.cancel'))}</button>
      <button type="button" class="btn btn-primary btn-sm" id="cfgSv">${esc(t('node.config.save'))}</button>
    </div><div id="cfgForm"></div>`;
    const form = cfgMount.querySelector('#cfgForm');
    const inputs = {};
    for (const k of props) {
      const wrap = document.createElement('div');
      wrap.className = 'field';
      const lab = document.createElement('label');
      lab.textContent = k;
      wrap.appendChild(lab);
      const v = cfg[k];
      let inp;
      if (k === 'bootstrap') {
        inp = document.createElement('textarea');
        inp.rows = 2;
        inp.value = Array.isArray(v) ? v.join('\n') : '';
      } else if (typeof v === 'boolean') {
        inp = document.createElement('input');
        inp.type = 'checkbox';
        inp.checked = !!v;
      } else {
        inp = document.createElement('input');
        inp.type = 'text';
        inp.value = v === '***' ? '' : v != null ? String(v) : '';
      }
      inp.dataset.key = k;
      wrap.appendChild(inp);
      form.appendChild(wrap);
      inputs[k] = inp;
    }
    cfgMount.querySelector('#cfgCx').onclick = () => {
      editing = false;
      renderCfg();
    };
    cfgMount.querySelector('#cfgSv').onclick = async (ev) => {
      const b = ev.currentTarget;
      setLoading(b, true);
      const patch = {};
      for (const k of props) {
        const inp = inputs[k];
        const orig = cfg[k];
        if (k === 'bootstrap') {
          const lines = inp.value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          if (JSON.stringify(lines) !== JSON.stringify(orig || [])) patch[k] = lines;
        } else if (typeof orig === 'boolean') {
          if (inp.checked !== orig) patch[k] = inp.checked;
        } else {
          const s = inp.value.trim();
          if (k === 'min_observed_peers') {
            const n = parseInt(s, 10);
            if (!Number.isNaN(n) && n !== orig) patch[k] = n;
          } else if (s !== String(orig === '***' ? '' : orig ?? '')) {
            patch[k] = s;
          }
        }
      }
      try {
        const out = await api('/config', { method: 'PATCH', body: JSON.stringify(patch) });
        if (out.restart_required?.length) {
          toast(t('node.config.restart_notice', { fields: out.restart_required.join(', ') }), 'warn', 6000);
        } else toast('ok', 'ok');
        const cf = await api('/config');
        cfg = cf;
        editing = false;
        renderCfg();
      } catch (e) {
        toast(t('common.error', { msg: e.message }), 'err');
      } finally {
        setLoading(b, false);
      }
    };
  }

  renderCfg();

  const tok = document.createElement('div');
  tok.className = 'card';
  tok.innerHTML = `
    <div class="card-h">${esc(t('node.token.label'))}</div>
    <div class="card-b" style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
      <input type="password" id="apiTok" style="flex:1;min-width:12rem" placeholder="${esc(t('node.token.placeholder'))}" autocomplete="off" />
      <button type="button" class="btn btn-primary btn-sm" id="tokSv">${esc(t('node.token.save'))}</button>
    </div>`;
  root.appendChild(tok);
  tok.querySelector('#tokSv').onclick = () => {
    setToken(tok.querySelector('#apiTok').value.trim());
    toast('ok', 'ok');
  };

  const dbg = document.createElement('div');
  dbg.className = 'muted';
  dbg.style.cssText = 'margin-top:1rem;font-size:.8rem';
  dbg.innerHTML = `${esc(t('node.debug.title'))}:
    <a href="/debug/routing" target="_blank" rel="noopener">${esc(t('node.debug.routing'))}</a> ·
    <a href="/debug/store" target="_blank" rel="noopener">${esc(t('node.debug.store'))}</a> ·
    <a href="/debug/stats" target="_blank" rel="noopener">${esc(t('node.debug.connections'))}</a>`;
  root.appendChild(dbg);
}
