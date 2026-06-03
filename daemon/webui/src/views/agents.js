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
  base64ToUtf8,
} from '../util.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { encode as cborEncode } from 'cborg';
import { encrypt, decrypt, isEnvelope } from '../crypto.js';

// ---------------------------------------------------------------------------
// Local delegation signing — master private key never leaves the browser.
// Mirrors identity.SignDelegation in Go (identity/delegation.go).
// ---------------------------------------------------------------------------

const SIGN_PREFIX = new TextEncoder().encode('a2al-del\x00');
// VersionEd25519 = 0xA0 (address.go)
const AID_VERSION_ED25519 = 0xA0;

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error('invalid hex length');
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function bytesToHex(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function sha256bytes(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// Validate master private key hex: exactly 128 hex chars, no whitespace.
function isValidMasterKeyHex(s) {
  return s.length === 128 && /^[0-9a-fA-F]{128}$/.test(s);
}

// Normalise user input: strip all whitespace.
function normaliseMasterKeyInput(s) {
  return s.replace(/\s/g, '');
}

// Derive AID (21 bytes) from Ed25519 master public key (32 bytes).
// Mirrors crypto.AddressFromPublicKey: AID[0]=0xA0, AID[1:21]=SHA256(masterPub)[0:20]
async function aidBytesFromMasterPub(masterPub) {
  const h = await sha256bytes(masterPub);
  const aid = new Uint8Array(21);
  aid[0] = AID_VERSION_ED25519;
  aid.set(h.slice(0, 20), 1);
  return aid;
}

// Format AID bytes (21 bytes) to canonical string.
// Mirrors nativeFormatAddress / nativeChecksumHex in native_address.go.
// Result: 42-char hex with SHA256-based mixed-case checksum.
async function formatAIDBytes(aidBytes) {
  const lower = bytesToHex(aidBytes); // 42 lowercase hex chars
  const hashBytes = await sha256bytes(new TextEncoder().encode(lower));
  let out = '';
  for (let i = 0; i < lower.length; i++) {
    const c = lower[i];
    if (c >= '0' && c <= '9') { out += c; continue; }
    const nib = i % 2 === 0 ? (hashBytes[Math.floor(i / 2)] >> 4) : (hashBytes[Math.floor(i / 2)] & 0x0f);
    out += nib >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

// Derive displayable AID string from a validated 128-char master key hex.
async function deriveAIDString(masterPrivHex) {
  const masterPub = hexToBytes(masterPrivHex).slice(32, 64);
  const aidBytes = await aidBytesFromMasterPub(masterPub);
  return formatAIDBytes(aidBytes);
}

// Build canonical CBOR map with integer keys (matches Go fxamacker/cbor canonical mode).
function buildDelegationCBOR(masterPub, opPub, aidBytes, issuedAt, expiresAt, scope) {
  return cborEncode(new Map([
    [1, masterPub],
    [2, opPub],
    [3, aidBytes],
    [4, issuedAt],
    [5, expiresAt],
    [6, scope],
  ]));
}

// Sign delegation and return { opPrivHex, delegationHex }.
// AID string is read from the daemon's POST /agents response.
async function signDelegationFromMaster(masterPrivHex) {
  const masterPrivBytes = hexToBytes(masterPrivHex);
  const masterSeed = masterPrivBytes.slice(0, 32);
  const masterPub  = masterPrivBytes.slice(32, 64);
  const aidBytes   = await aidBytesFromMasterPub(masterPub);

  const opPrivBytes = ed25519.utils.randomSecretKey();
  const opPub       = ed25519.getPublicKey(opPrivBytes);

  const issuedAt  = BigInt(Math.floor(Date.now() / 1000));
  const expiresAt = BigInt(0);
  const scope     = 1;

  const fieldsCBOR = buildDelegationCBOR(masterPub, opPub, aidBytes, issuedAt, expiresAt, scope);
  const msg = new Uint8Array(SIGN_PREFIX.length + fieldsCBOR.length);
  msg.set(SIGN_PREFIX, 0);
  msg.set(fieldsCBOR, SIGN_PREFIX.length);

  const sig = ed25519.sign(msg, masterSeed);

  const proofCBOR = cborEncode(new Map([
    [1, masterPub],
    [2, opPub],
    [3, aidBytes],
    [4, issuedAt],
    [5, expiresAt],
    [6, scope],
    [7, sig],
  ]));

  // Go ed25519.PrivateKey layout: seed || pub (64 bytes)
  const opPrivFull = new Uint8Array(64);
  opPrivFull.set(opPrivBytes, 0);
  opPrivFull.set(opPub, 32);

  return {
    opPrivHex:     bytesToHex(opPrivFull),
    delegationHex: bytesToHex(proofCBOR),
  };
}

// Set before calling onRefresh so that renderAgents can highlight the new card.
let _pendingNewAid = null;
function markNewCard(aid) { _pendingNewAid = aid; }

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

// Module-level sets for DHT-verified states, populated by the 120 s stale check.
// Persisted to localStorage so results survive page reloads.
const _LS_DHT_LIVE    = 'a2al.dht.confirmed.live';
const _LS_DHT_EXPIRED = 'a2al.dht.confirmed.expired';

const _dhtConfirmedLive    = new Set();
const _dhtConfirmedExpired = new Set();

// Restore from previous session on module load.
try {
  for (const aid of JSON.parse(localStorage.getItem(_LS_DHT_LIVE)    || '[]')) _dhtConfirmedLive.add(aid);
  for (const aid of JSON.parse(localStorage.getItem(_LS_DHT_EXPIRED) || '[]')) _dhtConfirmedExpired.add(aid);
} catch (_) {}

function _saveDhtConfirmed() {
  try {
    localStorage.setItem(_LS_DHT_LIVE,    JSON.stringify([..._dhtConfirmedLive]));
    localStorage.setItem(_LS_DHT_EXPIRED, JSON.stringify([..._dhtConfirmedExpired]));
  } catch (_) {}
}

function agentStatus(ag) {
  if (!ag.published_to_dht) return { key: 'agent.status.unpublished', cls: 'b-gray' };
  // No publish record in this daemon session: either restarted recently or
  // auto-republish was permanently stopped (agent migrated/higher seq in network).
  // Cannot confirm the DHT record is still live.
  if (!ag.last_publish_at) {
    if (_dhtConfirmedLive.has(ag.aid))    return { key: 'agent.status.published',     cls: 'b-green' };
    if (_dhtConfirmedExpired.has(ag.aid)) return { key: 'agent.status.refresh_failed', cls: 'b-orange' };
    return { key: 'agent.status.stale', cls: 'b-yellow' };
  }
  if (ag.dht_record_expires_at && new Date(ag.dht_record_expires_at) < new Date()) {
    return { key: 'agent.status.refresh_failed', cls: 'b-orange' };
  }
  return { key: 'agent.status.published', cls: 'b-green' };
}

/** Returns true when a ping/connect test is likely to succeed. */
function agentReachable(ag) {
  const st = agentStatus(ag);
  return st.key === 'agent.status.published';
}

// Left-border accent is driven by service_tcp connectivity, independent of DHT publish state.
function tcpAccentCls(ag) {
  if (!ag.service_tcp)           return 'b-gray';
  if (ag.service_tcp_ok === false) return 'b-red';
  if (ag.service_tcp_ok === true)  return 'b-green';
  return 'b-gray'; // configured but not yet probed
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
  const { t, api, toast, relTime, openModal, onRefresh, copyText, isStale } = ctx;
  let agents = [];
  try {
    const res = await api('/agents');
    agents = res.agents || [];
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
      listContainer.appendChild(buildAgentCard(sorted[idx], idx === 0, sorted, idx));
    }
    // Highlight and scroll to a newly registered card if pending
    if (_pendingNewAid) {
      const newCard = listContainer.querySelector(`[data-aid="${CSS.escape(_pendingNewAid)}"]`);
      _pendingNewAid = null;
      if (newCard) {
        newCard.classList.add('card-new');
        newCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        // Remove highlight on first click anywhere on the card
        newCard.addEventListener('click', () => newCard.classList.remove('card-new'), { once: true });
      }
    }
  };
  renderList();

  // ── Agent card builder ──────────────────────────────────────────────────
  function buildAgentCard(ag, svcExpanded, allAgents, idx) {
    const st = agentStatus(ag);
    // Auto-assign a default alias if none is stored yet
    if (!aliasOf(ag.aid)) setAliasOf(ag.aid, generateDefaultAlias());
    const alias = aliasOf(ag.aid);
    const isDemoActive = ag.demo_active;
    const card = document.createElement('div');
    card.className = 'card ag2-card';
    card.dataset.status = tcpAccentCls(ag);
    card.dataset.aid = ag.aid;

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
            <span data-tcp-status="${esc(ag.aid)}">${tcpDot(ag, t)}</span>
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
                placeholder="127.0.0.1:8080 or https://host:443" style="flex:1;min-width:10rem" />
              <button type="button" class="btn btn-primary btn-sm" data-tcp-save>${esc(t('agent.tcp.save'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-tcp-cancel>${esc(t('common.cancel'))}</button>
            </div>
          </div>
        </div>
        <div class="ag2-badges">
          <span class="badge ${esc(st.cls)}" data-aid-badge="${esc(ag.aid)}">● ${esc(t(st.key))}</span>
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
          ${!ag.published_to_dht ? `<button type="button" class="btn btn-primary btn-sm" data-pub-now>${esc(t('agent.action.publish'))}</button>` : ''}
          <button type="button" class="btn btn-secondary btn-sm" data-pub>${esc(t('agent.action.republish'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-export>${esc(t('agent.action.export'))}</button>
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

    infoDiv.querySelector('[data-export]').onclick = () => openExportModal(ag.aid);

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
      { key: 'aidproxy',   label: t('agent.fn.aidproxy') },
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
        panel.innerHTML = `<p class="muted">${esc(t('discover.card.fetching'))}</p>`;
        try {
          let got = null;
          for (const path of ['/.well-known/agent.json', '/.well-known/mcp.json']) {
            try {
              const r = await api(`/fetch/${encodeURIComponent(ag.aid)}`, {
                method: 'POST',
                body: JSON.stringify({ path }),
              });
              if (r.status >= 200 && r.status < 300) {
                got = { json: JSON.parse(base64ToUtf8(r.body)), path };
                break;
              }
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
          const r = await api(`/resolve/${encodeURIComponent(ag.aid)}`, { method: 'POST', body: '{}' });
          const eps = Array.isArray(r.endpoints) && r.endpoints.length
            ? r.endpoints.map((e) => `<span class="mono" style="font-size:.83rem">${esc(e)}</span>`).join('<br/>')
            : '—';
          const nat = r.nat_type != null ? natLabel(t, r.nat_type) : '—';
          panel.innerHTML = `
            <div style="margin-bottom:.35rem"><strong>${esc(t('agent.fn.network.endpoints'))}</strong><br/>${eps}</div>
            <div><strong>${esc(t('agent.fn.network.nat'))}</strong> ${esc(nat)}</div>`;
        } catch (e) {
          panel.innerHTML = `<p style="color:var(--error)">${esc(t('discover.resolve.unavailable'))}</p><p class="muted" style="font-size:.85rem;margin:.15rem 0 0">${esc(t('discover.resolve.unavailable_hint'))}</p>`;
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
        const pingOk = agentReachable(ag);
        panel.innerHTML = `
          <div style="display:flex;gap:.75rem;align-items:center;flex-wrap:wrap">
            <button type="button" class="btn btn-secondary btn-sm" id="fn-ping-btn"${pingOk ? '' : ' disabled'}>${esc(t('agent.fn.ping'))}</button>
            <span id="fn-ping-out" class="muted" style="font-size:.9rem">${pingOk ? '' : esc(t('agent.fn.ping.not_reachable'))}</span>
          </div>`;
        if (!pingOk) break;
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
            el.textContent = e.status === 412 ? t('connect.no_direct_path') : t('connect.peer_offline');
            el.style.color = 'var(--error)';
          } finally {
            setLoading(b, false);
          }
        };
        panel.querySelector('#fn-ping-btn').onclick = doPing;
        // Auto-execute on open
        doPing();
        break;
      }
      case 'aidproxy': {
        const url = `${window.location.origin}/aid/${encodeURIComponent(ag.aid)}/`;
        panel.innerHTML = `
          <div class="muted" style="font-size:.82rem;margin-bottom:.3rem">${esc(t('discover.aidproxy.label'))}</div>
          <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">
            <code class="mono" style="font-size:.9rem">${esc(url)}</code>
            <button type="button" class="btn btn-ghost btn-sm" id="fn-ap-cp">\u29c9</button>
          </div>
          <p class="muted" style="font-size:.8rem;margin:.3rem 0 0">${esc(t('agent.fn.aidproxy.hint'))}</p>`;
        panel.querySelector('#fn-ap-cp').onclick = () => copyText(url);
        break;
      }
    }
  }

  // ── Modal functions (unchanged) ─────────────────────────────────────────

  function openCreateModal() {
    let activeTab = 'new'; // 'new' | 'recover'
    let step = 1;          // 1=idle, 2=loading, 3=ready  (only used by 'new' tab)
    let gen = null;

    openModal({
      title: t('agent.modal.create.title'),
      noBackdropClose: true,
      body: `
        <div class="modal-tabs" id="cmTabs">
          <button type="button" class="active" data-tab="new">${esc(t('agent.modal.create.tab.new'))}</button>
          <button type="button" data-tab="recover">${esc(t('agent.modal.create.tab.recover'))}</button>
        </div>
        <div id="cmBody"></div>`,
      onMount(root, { close }) {
        const body = root.querySelector('#cmBody');

        // Tab switching
        root.querySelectorAll('.modal-tabs button').forEach((btn) => {
          btn.onclick = () => {
            activeTab = btn.dataset.tab;
            root.querySelectorAll('.modal-tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === activeTab));
            render();
          };
        });

        // ── Tab: 建立全新 AID ──────────────────────────────────────────────
        function renderNew() {
          // step 1: idle — show AID input + generate button
          if (step === 1) {
            body.innerHTML = `
              <p class="muted" style="font-size:.85rem;margin:.75rem 0 .9rem">${esc(t('agent.modal.create.description'))}</p>
              <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:1.25rem">
                <input id="cmAid" readonly class="mono"
                  placeholder="${esc(t('agent.modal.create.aid_placeholder'))}"
                  style="flex:1;min-width:0;font-size:.8rem" />
                <button type="button" class="btn btn-primary btn-sm" id="cmGenBtn" style="white-space:nowrap;flex-shrink:0">
                  ${esc(t('agent.modal.create.generate_btn'))}
                </button>
              </div>
              <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
              </div>`;
            body.querySelector('#cmGenBtn').onclick = () => { step = 2; renderNew(); };
            return;
          }

          // step 2: loading
          if (step === 2) {
            body.innerHTML = `
              <p class="muted" style="font-size:.85rem;margin:.75rem 0 .9rem">${esc(t('agent.modal.create.description'))}</p>
              <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:1.25rem">
                <input id="cmAid" readonly class="mono" style="flex:1;min-width:0;font-size:.8rem" />
                <button type="button" class="btn btn-primary btn-sm" disabled style="white-space:nowrap;flex-shrink:0">…</button>
              </div>
              <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
              </div>`;
            api('/identity/generate', { method: 'POST', body: '{}' })
              .then((r) => { gen = r; step = 3; renderNew(); })
              .catch((e) => {
                body.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
              });
            return;
          }

          // step 3: generated — show master key, confirm, register
          if (step === 3 && gen) {
            body.innerHTML = `
              <div class="field" style="margin-top:.75rem">
                <label>AID</label>
                <input readonly class="mono" value="${esc(gen.aid)}" style="width:100%;font-size:.8rem" />
              </div>
              <div class="field">
                <label>${esc(t('agent.modal.masterkey.key_label'))}</label>
                <div class="warn-box" style="margin-bottom:.5rem">${esc(t('agent.modal.masterkey.warning')).replace(/\n/g, '<br/>')}</div>
                <textarea readonly rows="3" class="mono" style="width:100%;font-size:.78rem">${esc(gen.master_private_key_hex)}</textarea>
                <button type="button" class="btn btn-ghost btn-sm" style="margin-top:.4rem" id="cmCopy">\u29c9 ${esc(t('agent.modal.masterkey.copy_btn'))}</button>
              </div>
              <label class="chk" style="margin-bottom:.75rem"><input type="checkbox" id="cmOk" /> <span>${esc(t('agent.modal.masterkey.confirm'))}</span></label>
              <details>
                <summary>${esc(t('agent.modal.advanced'))}</summary>
                <div class="field" style="margin-top:.75rem">
                  <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
                  <input type="text" id="cmTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
                  <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
                </div>
              </details>
              <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
                <button type="button" class="btn btn-secondary" id="cmReg" disabled>${esc(t('agent.modal.create.submit'))}</button>
              </div>`;
            body.querySelector('#cmCopy').onclick = () =>
              navigator.clipboard.writeText(gen.master_private_key_hex)
                .then(() => toast(t('common.copied'), 'ok', 1200));
            const cmOk  = body.querySelector('#cmOk');
            const cmReg = body.querySelector('#cmReg');
            cmOk.addEventListener('change', () => {
              cmReg.disabled  = !cmOk.checked;
              cmReg.className = cmOk.checked ? 'btn btn-primary' : 'btn btn-secondary';
            });
            cmReg.onclick = async (ev) => {
              const b = ev.currentTarget;
              setLoading(b, true);
              try {
                const tcp = normalizeServiceTCP(body.querySelector('#cmTcp').value);
                const r = await api('/agents', {
                  method: 'POST',
                  body: JSON.stringify({
                    operational_private_key_hex: gen.operational_private_key_hex,
                    delegation_proof_hex:        gen.delegation_proof_hex,
                    service_tcp:                 tcp,
                  }),
                });
                toast(r.aid, 'ok');
                try { await api(`/agents/${encodeURIComponent(r.aid)}/publish`, { method: 'POST', body: '{}' }); } catch (_) {}
                markNewCard(r.aid);
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

        // ── Tab: 从主私钥建立 ──────────────────────────────────────────────
        function renderRecover() {
          body.innerHTML = `
            <p class="muted" style="margin:.75rem 0 .9rem;font-size:.85rem">${esc(t('agent.modal.recover.hint'))}</p>
            <div class="field">
              <label>${esc(t('agent.modal.recover.master_key.label'))}</label>
              <textarea id="rcKey" rows="2" class="mono" style="width:100%;font-size:.78rem"
                placeholder="128-char hex"
                autocomplete="off" autocorrect="off" spellcheck="false"></textarea>
            </div>
            <div class="field">
              <label>${esc(t('agent.modal.recover.aid_label'))}</label>
              <input id="rcAid" readonly class="mono"
                value="${esc(t('agent.modal.recover.aid_empty'))}"
                style="width:100%;font-size:.8rem;color:var(--muted)" />
            </div>
            <details style="margin-top:.25rem">
              <summary>${esc(t('agent.modal.advanced'))}</summary>
              <div class="field" style="margin-top:.75rem">
                <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
                <input type="text" id="rcTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
                <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
              </div>
            </details>
            <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
              <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
              <button type="button" class="btn btn-primary" id="rcGo" disabled>${esc(t('agent.modal.create.submit'))}</button>
            </div>`;

          const rcKey = body.querySelector('#rcKey');
          const rcAid = body.querySelector('#rcAid');
          const rcGo  = body.querySelector('#rcGo');

          // Real-time validation and AID preview
          let aidDeriveTimer = null;
          rcKey.addEventListener('input', () => {
            clearTimeout(aidDeriveTimer);
            const raw = normaliseMasterKeyInput(rcKey.value);
            if (raw.length === 0) {
              rcAid.value       = t('agent.modal.recover.aid_empty');
              rcAid.style.color = 'var(--muted)';
              rcGo.disabled     = true;
              return;
            }
            if (!isValidMasterKeyHex(raw)) {
              rcAid.value       = t('agent.modal.recover.aid_invalid');
              rcAid.style.color = 'var(--error)';
              rcGo.disabled     = true;
              return;
            }
            // Valid — derive AID asynchronously (debounced 150 ms)
            rcAid.value       = '…';
            rcAid.style.color = 'var(--muted)';
            rcGo.disabled     = true;
            aidDeriveTimer = setTimeout(async () => {
              try {
                const aidStr      = await deriveAIDString(raw);
                rcAid.value       = aidStr;
                rcAid.style.color = '';
                rcGo.disabled     = false;
              } catch (_) {
                rcAid.value       = t('agent.modal.recover.aid_invalid');
                rcAid.style.color = 'var(--error)';
                rcGo.disabled     = true;
              }
            }, 150);
          });

          rcGo.onclick = async (ev) => {
            const keyHex = normaliseMasterKeyInput(rcKey.value);
            if (!isValidMasterKeyHex(keyHex)) return;
            const b = ev.currentTarget;
            setLoading(b, true);
            try {
              const { opPrivHex, delegationHex } = await signDelegationFromMaster(keyHex);
              const tcp = normalizeServiceTCP(body.querySelector('#rcTcp').value);
              const r = await api('/agents', {
                method: 'POST',
                body: JSON.stringify({
                  operational_private_key_hex: opPrivHex,
                  delegation_proof_hex:        delegationHex,
                  service_tcp:                 tcp,
                }),
              });
              toast(r.aid, 'ok');
              try { await api(`/agents/${encodeURIComponent(r.aid)}/publish`, { method: 'POST', body: '{}' }); } catch (_) {}
              markNewCard(r.aid);
              close();
              onRefresh();
            } catch (e) {
              toast(t('common.error', { msg: e.message }), 'err');
            } finally {
              setLoading(b, false);
            }
          };
        }

        function render() {
          if (activeTab === 'recover') { renderRecover(); return; }
          renderNew();
        }

        render();
      },
    });
  }

  function openExportModal(aid) {
    openModal({
      title: t('agent.action.export'),
      body: `
        <p class="muted" style="font-size:.85rem;margin:0 0 .75rem">${esc(t('agent.export.hint'))}</p>
        <div class="field">
          <label>${esc(t('agent.export.password'))}</label>
          <input type="password" id="exPw" placeholder="${esc(t('agent.export.password_ph'))}" autocomplete="new-password" style="width:100%" />
          <div class="hint">${esc(t('agent.export.password_hint'))}</div>
        </div>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="exGo">${esc(t('agent.export.btn'))}</button>
        </div>`,
      onMount(root, { close }) {
        root.querySelector('#exGo').onclick = async (ev) => {
          const pw = root.querySelector('#exPw').value;
          const b = ev.currentTarget;
          setLoading(b, true);
          try {
            const creds = await api(`/agents/${encodeURIComponent(aid)}/export`);
            const json = JSON.stringify(creds, null, 2);
            let content, filename;
            if (pw) {
              content = await encrypt(json, pw);
              filename = `${aid.slice(0, 12)}.a2al-id.enc`;
            } else {
              content = json;
              filename = `${aid.slice(0, 12)}.a2al-id.json`;
            }
            const blob = new Blob([content], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = filename; a.click();
            URL.revokeObjectURL(url);
            close();
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
        root.querySelector('#exPw').focus();
      },
    });
  }

  function openImportModal() {
    openModal({
      title: t('agent.modal.import.title'),
      body: `
        <div class="field">
          <label>${esc(t('agent.import.file_label'))}</label>
          <input type="file" id="imFile" accept=".json,.enc,application/json,application/octet-stream" />
          <div id="imFileStatus" class="hint" style="display:none;margin-top:.35rem"></div>
        </div>
        <details id="imManual" style="margin-top:.5rem">
          <summary style="cursor:pointer;font-size:.85rem;color:var(--muted,#888)">${esc(t('agent.import.manual_label'))}</summary>
          <div class="field" style="margin-top:.75rem">
            <label>${esc(t('agent.modal.import.op_key.label'))}</label>
            <textarea id="imOp" rows="2" class="mono" style="width:100%"></textarea>
          </div>
          <div class="field">
            <label>${esc(t('agent.modal.import.del_proof.label'))}</label>
            <textarea id="imDel" rows="3" class="mono" style="width:100%"></textarea>
          </div>
        </details>
        <details style="margin-top:.5rem">
          <summary style="cursor:pointer;font-size:.85rem;color:var(--muted,#888)">${esc(t('agent.modal.advanced'))}</summary>
          <div class="field" style="margin-top:.75rem">
            <label>${esc(t('agent.modal.service_tcp.label'))} <span class="muted" style="font-weight:400">${esc(t('agent.modal.service_tcp.optional'))}</span></label>
            <input type="text" id="imTcp" placeholder="http://127.0.0.1:8080" style="width:100%" />
            <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
          </div>
        </details>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="imGo">${esc(t('agent.modal.import.submit'))}</button>
        </div>`,
      onMount(root, { close }) {
        root.querySelector('#imFile').onchange = (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const rd = new FileReader();
          rd.onload = async () => {
            const raw = String(rd.result);
            if (isEnvelope(raw)) {
              // Encrypted file — open password prompt
              openModal({
                title: t('agent.import.decrypt_title'),
                noBackdropClose: true,
                body: `
                  <p class="muted" style="font-size:.85rem;margin:0 0 .75rem">${esc(t('agent.import.decrypt_hint'))}</p>
                  <div class="field">
                    <input type="password" id="decPw" placeholder="${esc(t('agent.import.file_password_ph'))}" autocomplete="off" style="width:100%" />
                    <p id="decErr" class="muted" style="color:var(--danger,#e53935);margin:.35rem 0 0;display:none">${esc(t('vault.unlock.wrong'))}</p>
                  </div>
                  <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                    <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
                    <button type="button" class="btn btn-primary" id="decOk">${esc(t('common.confirm'))}</button>
                  </div>`,
                onMount(dr, { close: closeDecrypt }) {
                  const doDecrypt = async () => {
                    const pw = dr.querySelector('#decPw').value;
                    const btn = dr.querySelector('#decOk');
                    setLoading(btn, true);
                    dr.querySelector('#decErr').style.display = 'none';
                    try {
                      const plain = await decrypt(raw, pw);
                      const j = JSON.parse(plain);
                      if (j.operational_private_key_hex) {
                        root.querySelector('#imOp').value = j.operational_private_key_hex;
                        root.querySelector('#imManual').open = true;
                      }
                      if (j.delegation_proof_hex)
                        root.querySelector('#imDel').value = j.delegation_proof_hex;
                      const status = root.querySelector('#imFileStatus');
                      status.textContent = f.name;
                      status.style.display = '';
                      closeDecrypt();
                    } catch (_) {
                      dr.querySelector('#decErr').style.display = '';
                      dr.querySelector('#decPw').value = '';
                      dr.querySelector('#decPw').focus();
                    } finally {
                      setLoading(btn, false);
                    }
                  };
                  dr.querySelector('#decOk').onclick = doDecrypt;
                  dr.querySelector('#decPw').addEventListener('keydown', (e) => {
                    if (e.key === 'Enter') { e.preventDefault(); doDecrypt(); }
                  });
                  setTimeout(() => dr.querySelector('#decPw').focus(), 50);
                },
              });
              return;
            }
            try {
              const j = JSON.parse(raw);
              if (j.operational_private_key_hex) {
                root.querySelector('#imOp').value = j.operational_private_key_hex;
                root.querySelector('#imManual').open = true;
              }
              if (j.delegation_proof_hex) root.querySelector('#imDel').value = j.delegation_proof_hex;
              const status = root.querySelector('#imFileStatus');
              status.textContent = f.name;
              status.style.display = '';
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
    const initialAgent = agentList.find((a) => a.aid === editAid) || agentList[0];
    const preUrl = (() => {
      const tcp = initialAgent?.service_tcp;
      if (!tcp) return '';
      const base = (tcp.startsWith('https://') || tcp.startsWith('http://'))
        ? tcp.replace(/\/$/, '')
        : 'http://' + tcp;
      return base + '/.well-known/agent.json';
    })();
    openModal({
      title: t('service.modal.title'),
      wide: true,
      body: `
        ${single ? '' : `<div class="field"><label>${esc(t('service.modal.agent_pick'))}</label><select id="svAid">${agentList.map((a) => `<option value="${esc(a.aid)}" ${a.aid === editAid ? 'selected' : ''}>${esc(labelAid(a.aid))}</option>`).join('')}</select></div>`}
        <div class="field">
          <label>${esc(t('service.modal.import.label'))}</label>
          <div style="display:flex;gap:.35rem;flex-wrap:wrap">
            <input type="url" id="svUrl" style="flex:1;min-width:12rem" placeholder="${esc(t('service.modal.import.placeholder'))}" value="${esc(preUrl)}" />
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
            root.querySelector('#svHttp').checked = m.protocols.includes('http');
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

  // Probe tcp status for all agents with service_tcp, concurrently.
  // Each probe has its own 2.5s timeout so one slow endpoint can't block others.
  // When rendered from cache, also refresh agent list + demo status in background.
  function _runProbes(agList) {
    agList.filter(ag => ag.service_tcp).forEach(ag => {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 2500);
      api(`/agents/${encodeURIComponent(ag.aid)}/probe`, { signal: ctrl.signal })
        .then(r => {
          if (!mount.isConnected) return;
          const tcpEl = mount.querySelector(`[data-tcp-status="${CSS.escape(ag.aid)}"]`);
          if (tcpEl) tcpEl.innerHTML = tcpDot({ ...ag, service_tcp_ok: r.service_tcp_ok }, t);
          const card = mount.querySelector(`[data-aid="${CSS.escape(ag.aid)}"]`);
          if (card) card.dataset.status = tcpAccentCls({ ...ag, service_tcp_ok: r.service_tcp_ok });
        }).catch(() => {});
    });
  }
  _runProbes(agents);

  // Background status refresh: re-fetch agents every 60 s and update badges
  // without rebuilding cards (preserves open panels and edit state).
  const statusTimer = setInterval(async () => {
    if (!mount.isConnected) { clearInterval(statusTimer); return; }
    try {
      const r = await api('/agents');
      agents = r.agents || [];
      let dhtChanged = false;
      for (const ag of agents) {
        // Agent was republished by this daemon — clear any stale confirmed state
        // so the normal publish path takes over and the badge reflects real data.
        if (ag.last_publish_at) {
          if (_dhtConfirmedExpired.delete(ag.aid) || _dhtConfirmedLive.delete(ag.aid)) {
            dhtChanged = true;
          }
        }
        const badge = mount.querySelector(`[data-aid-badge="${ag.aid}"]`);
        if (!badge) continue;
        const st = agentStatus(ag);
        badge.className = `badge ${st.cls}`;
        badge.textContent = `● ${t(st.key)}`;
      }
      if (dhtChanged) _saveDhtConfirmed();
    } catch (_) {}
  }, 60000);

  // One-shot DHT verification for stale agents (last_publish_at=null).
  // Fires 120 s after page load — by then the daemon warm-up (60–90 s) has
  // completed and the DHT routing table has stabilised, so Resolve results
  // are trustworthy.  Confirmed live/expired states are persisted to
  // localStorage so subsequent page loads start with the right badge.
  //
  // Confirmed-expired agents are excluded from re-check (they stay expired
  // until the agent is republished, detected by the 60 s refresh clearing
  // the entry when last_publish_at becomes non-null).
  // Confirmed-live agents ARE re-checked so a record that has since expired
  // on the network is correctly moved to expired.
  setTimeout(async () => {
    if (!mount.isConnected) return;
    const toCheck = agents
      .filter(ag =>
        ag.published_to_dht &&
        !ag.last_publish_at &&
        !_dhtConfirmedExpired.has(ag.aid), // skip already-confirmed-expired
      )
      .map(ag => ag.aid);
    if (!toCheck.length) return;
    await Promise.allSettled(toCheck.map(async (aid) => {
      try {
        const r = await api(`/agents/${encodeURIComponent(aid)}/probe`);
        if (r.published_record_seq != null) {
          _dhtConfirmedLive.add(aid);
          _dhtConfirmedExpired.delete(aid);
        } else {
          _dhtConfirmedExpired.add(aid);
          _dhtConfirmedLive.delete(aid);
        }
        _saveDhtConfirmed();
        const badge = mount.querySelector(`[data-aid-badge="${encodeURIComponent(aid)}"]`) ||
                      mount.querySelector(`[data-aid-badge="${aid}"]`);
        if (!badge) return;
        const ag = agents.find(a => a.aid === aid);
        if (!ag) return;
        const st = agentStatus(ag);
        badge.className = `badge ${st.cls}`;
        badge.textContent = `● ${t(st.key)}`;
      } catch (_) {}
    }));
  }, 120000);
}
