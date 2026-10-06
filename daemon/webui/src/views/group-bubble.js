import { esc, shortAid, shortAidHTML, aidAvStyle, colorizeAtShortAids, aliasOf, setAliasOf, nextUniqueDefaultAlias, base64ToUtf8 } from '../util.js';
import { getLocale } from '../i18n.js';
import { getToken } from '../api.js';

const POLL_MS = 1000;
const PAGE = 50;
const CLUSTER_MS = 2 * 60 * 1000;
const BURST_PAGES = 4;
const MSG_GROUP_INVITE = 0x10;
const SYS_KINDS = new Set([
  'invite', 'revoke', 'grant_admin', 'revoke_admin', 'propose_invite',
  'retract', 'meta', 'budget', 'spend', 'snapshot',
]);

export function openGroupBubble(ctx, agent) {
  const { t, api, openModal, toast, copyText } = ctx;
  const viewAid = agent.aid;

  let groups = [];
  let contacts = { friends: [], out_pending: [], in_pending: [] };
  let serverContacts = { friends: [], out_pending: [], in_pending: [] };
  let localOut = loadInviteStore(agent.aid);
  let roomInvites = [];
  let ignoredRoom = loadIgnored(agent.aid);
  let gInviteOn = false;
  let replyDraft = null;
  let lastBoxAt = 0;
  let rosterBusy = 0;
  let threadBusy = 0;
  let sel = '';
  let footOn = '';
  let seen = loadJSON(seenKey(viewAid), {});
  let headMeta = null;
  let entries = [];
  let oldestSeq = 0;
  let headSeq = 0;
  let chatEntries = [];
  let chatScanned = 0;
  let timer = null;
  let es = null;
  let stopped = false;
  let loadingOlder = false;
  let gen = 0;
  let listSig = '';
  let aliasTarget = viewAid;
  let act = {};
  let prevUnread = {};
  const hydrated = new Set();
  const threadCache = new Map();
  let threadEl = null;
  let listScrollEl = null;
  let listFootEl = null;
  let progressEl = null;
  let headEl = null;
  let whoEl = null;
  let subEl = null;
  let composerEl = null;
  let textEl = null;
  let fileEl = null;
  let aliasForm = null;
  let withdrawBtn = null;
  let removeBtn = null;
  let inviteBtn = null;
  let linkBtn = null;
  let leaveBtn = null;
  let listToggleEl = null;
  let winEl = null;
  let winOff = null;
  let geom = { x: 0, y: 0, w: 860, h: 640, listOff: false };
  let listPeek = true;
  const WIN_MIN_W = 320;
  const WIN_MIN_H = 360;
  const WIN_PAD = 8;
  const LIST_W = 208;
  const MIN_CHAT = 280;

  openModal({
    title: '',
    cls: 'modal modal-chat',
    body: `
      <div class="gb">
        <div class="gb-alias-form field" id="gb-who-form" hidden>
          <label>${esc(t('agent.alias.local_label'))}</label>
          <input type="text" maxlength="24" placeholder="${esc(t('agent.alias.placeholder'))}" />
          <div class="hint">${esc(t('agent.alias.local_hint'))}</div>
        </div>
        <div class="gb-progress" id="gb-progress" hidden title="${esc(t('gb.refreshing'))}">
          <i class="gb-progress-bar"></i>
        </div>
        <div class="gb-chat">
          <div class="gb-list">
            <div class="gb-list-scroll" id="gb-list-scroll"></div>
            <div class="gb-list-foot" id="gb-list-foot"></div>
          </div>
          <button type="button" class="gb-list-scrim" id="gb-list-scrim" tabindex="-1" aria-hidden="true"></button>
          <button type="button" class="gb-list-toggle" id="gb-list-toggle" aria-controls="gb-list-scroll"></button>
          <div class="gb-chat-main">
            <div class="gb-chat-head" id="gb-chat-head" hidden>
              <div class="gb-chat-who" id="gb-head-who"></div>
              <button type="button" class="btn btn-ghost btn-sm" data-withdraw hidden>${esc(t('chat.withdraw'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-remove hidden>${esc(t('chat.remove'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-ginvite hidden>${esc(t('gb.invite_member'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-glink hidden>${esc(t('gb.copy_link'))}</button>
              <button type="button" class="btn btn-ghost btn-sm" data-leave hidden>${esc(t('gb.leave'))}</button>
              <div class="gb-chat-sub" id="gb-chat-sub" hidden></div>
            </div>
            <div class="gb-thread" id="gb-thread"></div>
            <div class="gb-composer" id="gb-composer" hidden>
              <div class="gb-reply" id="gb-reply" hidden>
                <span class="gb-reply-txt" id="gb-reply-txt"></span>
                <button type="button" class="gb-act" data-reply-x title="${esc(t('gb.reply_cancel'))}">×</button>
              </div>
              <div class="gb-composer-row">
                <textarea rows="1" id="gb-text" placeholder="${esc(t('chat.placeholder'))}"></textarea>
                <input type="file" id="gb-file" hidden />
                <button type="button" class="btn btn-ghost btn-sm" data-file>${esc(t('chat.file'))}</button>
                <button type="button" class="btn btn-primary btn-sm" data-send>${esc(t('chat.send'))}</button>
              </div>
            </div>
          </div>
        </div>
      </div>`,
    onClose() {
      stopped = true;
      stashThread(sel);
      if (timer) clearTimeout(timer);
      if (es) { es.close(); es = null; }
      winOff?.();
      document.removeEventListener('visibilitychange', onVis);
      document.removeEventListener('mousedown', onMembersOutside);
      document.removeEventListener('keydown', onMembersEsc, true);
    },
    onMount(modal) {
      const h = modal.querySelector('.modal-h');
      const x = h.querySelector('[data-x]');
      h.innerHTML = `<div class="gb-who"></div>`;
      h.appendChild(x);
      threadEl = modal.querySelector('#gb-thread');
      listScrollEl = modal.querySelector('#gb-list-scroll');
      listFootEl = modal.querySelector('#gb-list-foot');
      progressEl = modal.querySelector('#gb-progress');
      headEl = modal.querySelector('#gb-chat-head');
      whoEl = modal.querySelector('#gb-head-who');
      subEl = modal.querySelector('#gb-chat-sub');
      composerEl = modal.querySelector('#gb-composer');
      textEl = modal.querySelector('#gb-text');
      fileEl = modal.querySelector('#gb-file');
      aliasForm = modal.querySelector('#gb-who-form');
      withdrawBtn = modal.querySelector('[data-withdraw]');
      removeBtn = modal.querySelector('[data-remove]');
      inviteBtn = modal.querySelector('[data-ginvite]');
      linkBtn = modal.querySelector('[data-glink]');
      leaveBtn = modal.querySelector('[data-leave]');
      listToggleEl = modal.querySelector('#gb-list-toggle');
      bindWin(modal);
      paintWho();
      h.querySelector('.gb-who').addEventListener('click', onWhoClick);
      whoEl.addEventListener('click', onHeadWhoClick);
      aliasForm.querySelector('input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); saveAlias(); }
        if (e.key === 'Escape') aliasForm.hidden = true;
      });
      aliasForm.querySelector('input').addEventListener('blur', saveAlias);
      threadEl.addEventListener('scroll', onScroll);
      threadEl.addEventListener('click', onThreadClick);
      document.addEventListener('visibilitychange', onVis);
      document.addEventListener('mousedown', onMembersOutside);
      document.addEventListener('keydown', onMembersEsc, true);
      withdrawBtn.onclick = () => {
        if (listedRel(chatPeer()) === 'out_pending') clearInvite(chatPeer());
        else chatAct('refuse');
      };
      removeBtn.onclick = () => chatAct('remove');
      inviteBtn.onclick = () => {
        gInviteOn = !gInviteOn;
        paintHead();
      };
      linkBtn.onclick = () => copyGroupLink();
      leaveBtn.onclick = () => leaveGroup();
      composerEl.querySelector('[data-send]').onclick = () => sendText();
      composerEl.querySelector('[data-file]').onclick = () => fileEl.click();
      composerEl.querySelector('[data-reply-x]').onclick = () => {
        replyDraft = null;
        paintReplyBar();
      };
      if (listToggleEl) {
        listToggleEl.onclick = () => {
          if (isNarrow()) listPeek = !listPeek;
          else {
            geom.listOff = !geom.listOff;
            listPeek = !geom.listOff;
            saveGeom();
          }
          applyGeom();
        };
      }
      const scrim = modal.querySelector('#gb-list-scrim');
      if (scrim) {
        scrim.onclick = () => {
          if (!isNarrow()) return;
          listPeek = false;
          applyGeom();
        };
      }
      fileEl.onchange = (ev) => sendFile(ev.target.files && ev.target.files[0]);
      textEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          sendText();
        }
      });
      boot();
      startDoorbell();
    },
  });

  function selStorageKey() { return `a2al.gb.sel.${viewAid}`; }
  function localOutKey() { return `a2al.gb.out.${viewAid}`; }
  function rosterSnapKey() { return `a2al.gb.roster.${viewAid}`; }
  function threadSnapKey(kind, id) { return `a2al.gb.snap.${viewAid}.${kind}.${id}`; }
  function geomKey() { return `a2al.gb.geom.${viewAid}`; }

  function defaultGeom() {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const maxW = Math.max(240, vw - WIN_PAD * 2);
    const maxH = Math.max(240, vh - WIN_PAD * 2);
    const w = Math.min(860, maxW);
    const h = Math.min(640, Math.max(WIN_MIN_H, Math.round(vh * 0.7)), maxH);
    return {
      x: Math.round((vw - w) / 2),
      y: Math.round((vh - h) / 2),
      w, h,
      listOff: false,
    };
  }

  function clampGeom(g) {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const maxW = Math.max(240, vw - WIN_PAD * 2);
    const maxH = Math.max(240, vh - WIN_PAD * 2);
    const minW = Math.min(WIN_MIN_W, maxW);
    const minH = Math.min(WIN_MIN_H, maxH);
    const w = Math.min(Math.max(minW, Number(g.w) || minW), maxW);
    const h = Math.min(Math.max(minH, Number(g.h) || minH), maxH);
    let x = Number(g.x);
    let y = Number(g.y);
    if (!Number.isFinite(x)) x = Math.round((vw - w) / 2);
    if (!Number.isFinite(y)) y = Math.round((vh - h) / 2);
    x = Math.min(Math.max(WIN_PAD, x), Math.max(WIN_PAD, vw - w - WIN_PAD));
    y = Math.min(Math.max(WIN_PAD, y), Math.max(WIN_PAD, vh - h - WIN_PAD));
    return { x, y, w, h, listOff: !!g.listOff };
  }

  function loadGeom() {
    try {
      const v = JSON.parse(localStorage.getItem(geomKey()) || '');
      if (v && typeof v === 'object') return clampGeom(v);
    } catch (_) { /* */ }
    return clampGeom(defaultGeom());
  }

  function saveGeom() {
    try { localStorage.setItem(geomKey(), JSON.stringify(geom)); } catch (_) { /* */ }
  }

  function isNarrow() {
    return (Number(geom.w) || 0) < LIST_W + MIN_CHAT;
  }

  function listHidden() {
    return isNarrow() ? !listPeek : !!geom.listOff;
  }

  function applyGeom() {
    if (!winEl) return;
    geom = clampGeom(geom);
    winEl.style.left = `${geom.x}px`;
    winEl.style.top = `${geom.y}px`;
    winEl.style.width = `${geom.w}px`;
    winEl.style.height = `${geom.h}px`;
    const root = winEl.querySelector('.gb');
    if (root) {
      const narrow = isNarrow();
      if (narrow && !root.classList.contains('gb-narrow')) listPeek = !geom.listOff;
      root.classList.toggle('gb-narrow', narrow);
      root.classList.toggle('list-off', listHidden());
    }
    paintListToggle();
  }

  function paintListToggle() {
    if (!listToggleEl) return;
    const off = listHidden();
    listToggleEl.title = off ? t('gb.list_show') : t('gb.list_hide');
    listToggleEl.setAttribute('aria-expanded', off ? 'false' : 'true');
    let mark = '';
    if (off) {
      let n = (contacts.in_pending || []).length + roomInvites.length;
      for (const g of groups) n += Number(g.unread_count) || 0;
      for (const it of contacts.friends || []) n += Number(it.unread_count) || 0;
      if (n) mark = `<span class="gb-count">${n > 9 ? '9+' : String(n)}</span>`;
    }
    listToggleEl.innerHTML = `${off ? '›' : '‹'}${mark}`;
  }

  function bindWin(modal) {
    winEl = modal;
    geom = loadGeom();
    applyGeom();
    const handle = document.createElement('div');
    handle.className = 'gb-resize';
    handle.title = t('gb.resize');
    modal.appendChild(handle);
    const head = modal.querySelector('.modal-h');
    let mode = '';
    let sx = 0;
    let sy = 0;
    let ox = 0;
    let oy = 0;
    let ow = 0;
    let oh = 0;
    let moved = false;

    function onWinResize() {
      applyGeom();
      saveGeom();
    }
    function down(kind, e) {
      if (e.button !== 0) return;
      mode = kind;
      moved = false;
      sx = e.clientX;
      sy = e.clientY;
      ox = geom.x;
      oy = geom.y;
      ow = geom.w;
      oh = geom.h;
      winEl.classList.add('dragging');
      e.preventDefault();
    }
    function onHeadDown(e) {
      if (e.target.closest('[data-x], button, input, textarea, a')) return;
      down('drag', e);
    }
    function onHandleDown(e) {
      e.stopPropagation();
      down('resize', e);
    }
    function onMove(e) {
      if (!mode) return;
      const dx = e.clientX - sx;
      const dy = e.clientY - sy;
      if (Math.abs(dx) + Math.abs(dy) > 4) moved = true;
      if (mode === 'drag') geom = clampGeom({ ...geom, x: ox + dx, y: oy + dy });
      else geom = clampGeom({ ...geom, w: ow + dx, h: oh + dy });
      applyGeom();
    }
    function onUp() {
      if (!mode) return;
      mode = '';
      winEl.classList.remove('dragging');
      saveGeom();
    }
    function onHeadClick(e) {
      if (!moved) return;
      e.preventDefault();
      e.stopPropagation();
      moved = false;
    }
    window.addEventListener('resize', onWinResize);
    head.addEventListener('pointerdown', onHeadDown);
    handle.addEventListener('pointerdown', onHandleDown);
    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
    document.addEventListener('pointercancel', onUp);
    head.addEventListener('click', onHeadClick, true);
    winOff = () => {
      window.removeEventListener('resize', onWinResize);
      head.removeEventListener('pointerdown', onHeadDown);
      handle.removeEventListener('pointerdown', onHandleDown);
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
      document.removeEventListener('pointercancel', onUp);
      head.removeEventListener('click', onHeadClick, true);
    };
  }

  function saveRosterSnap() {
    pruneAct();
    const json = JSON.stringify({ groups, serverContacts, roomInvites, act });
    try { localStorage.setItem(rosterSnapKey(), json); } catch (_) { /* */ }
    try { sessionStorage.setItem(rosterSnapKey(), json); } catch (_) { /* */ }
  }

  function restoreRosterSnap() {
    let raw = '';
    try { raw = localStorage.getItem(rosterSnapKey()) || ''; } catch (_) { /* */ }
    if (!raw) {
      try { raw = sessionStorage.getItem(rosterSnapKey()) || ''; } catch (_) { /* */ }
    }
    if (!raw) return false;
    try {
      const v = JSON.parse(raw);
      if (!v || typeof v !== 'object') return false;
      if (Array.isArray(v.groups)) groups = v.groups;
      if (v.serverContacts && typeof v.serverContacts === 'object') {
        serverContacts = v.serverContacts;
        applyLocalOut();
      }
      if (Array.isArray(v.roomInvites)) roomInvites = v.roomInvites;
      if (v.act && typeof v.act === 'object') {
        act = {};
        for (const [k, n] of Object.entries(v.act)) {
          const ts = Number(n) || 0;
          if (ts > 0 && (k.startsWith('g:') || k.startsWith('c:'))) act[k] = ts;
        }
      }
      return groups.length > 0 || (contacts.friends || []).length > 0;
    } catch {
      return false;
    }
  }

  function saveThreadSnap(kind, id, data) {
    if (!id) return;
    const key = `${kind}:${id}`;
    threadCache.set(key, data);
    const json = JSON.stringify(data);
    try { localStorage.setItem(threadSnapKey(kind, id), json); } catch (_) { /* */ }
    try { sessionStorage.setItem(threadSnapKey(kind, id), json); } catch (_) { /* */ }
    const ts = lastEntryTs(data && data.entries);
    if (ts) touch(key, ts);
  }

  function loadThreadSnap(kind, id) {
    if (!id) return null;
    const key = `${kind}:${id}`;
    if (threadCache.has(key)) return threadCache.get(key);
    let raw = '';
    try { raw = localStorage.getItem(threadSnapKey(kind, id)) || ''; } catch (_) { /* */ }
    if (!raw) {
      try { raw = sessionStorage.getItem(threadSnapKey(kind, id)) || ''; } catch (_) { /* */ }
    }
    if (!raw) return null;
    try {
      const v = JSON.parse(raw);
      if (v && typeof v === 'object') {
        threadCache.set(key, v);
        return v;
      }
    } catch { /* */ }
    return null;
  }

  function lastEntryTs(entries) {
    let m = 0;
    for (const e of entries || []) {
      const ts = Number(e && e.ts) || 0;
      if (ts > m) m = ts;
    }
    return m;
  }

  function pruneAct() {
    const keep = new Set();
    for (const g of groups) keep.add(`g:${g.group_id}`);
    for (const it of contacts.friends || []) keep.add(`c:${it.peer}`);
    for (const k of Object.keys(act)) {
      if (!keep.has(k)) delete act[k];
    }
  }

  function touch(key, ts, opt = {}) {
    const n = Number(ts) || 0;
    if (!key || n <= (Number(act[key]) || 0)) return false;
    act[key] = n;
    if (opt.quiet) return true;
    saveRosterSnap();
    if (!stopped && listScrollEl) renderList();
    return true;
  }

  function hydrateActFromSnaps() {
    for (const g of groups) {
      const key = `g:${g.group_id}`;
      if (hydrated.has(key)) continue;
      hydrated.add(key);
      if (act[key]) continue;
      const snap = loadThreadSnap('g', g.group_id);
      const ts = lastEntryTs(snap && snap.entries);
      if (ts) act[key] = ts;
    }
    for (const it of contacts.friends || []) {
      const key = `c:${it.peer}`;
      if (hydrated.has(key)) continue;
      hydrated.add(key);
      if (act[key]) continue;
      const snap = loadThreadSnap('c', it.peer);
      const ts = lastEntryTs(snap && snap.entries);
      if (ts) act[key] = ts;
    }
  }

  function seedUnread() {
    prevUnread = {};
    for (const g of groups) prevUnread[`g:${g.group_id}`] = Number(g.unread_count) || 0;
    for (const it of contacts.friends || []) prevUnread[`c:${it.peer}`] = Number(it.unread_count) || 0;
  }

  function bumpUnread() {
    for (const g of groups) {
      const key = `g:${g.group_id}`;
      const n = Number(g.unread_count) || 0;
      if (Object.prototype.hasOwnProperty.call(prevUnread, key) && n > prevUnread[key]) {
        touch(key, Date.now(), { quiet: true });
      }
      prevUnread[key] = n;
    }
    for (const it of contacts.friends || []) {
      const key = `c:${it.peer}`;
      const n = Number(it.unread_count) || 0;
      if (Object.prototype.hasOwnProperty.call(prevUnread, key) && n > prevUnread[key]) {
        touch(key, Date.now(), { quiet: true });
      }
      prevUnread[key] = n;
    }
  }

  function actOf(key, fallback) {
    return Math.max(Number(act[key]) || 0, Number(fallback) || 0);
  }

  function cmpAct(aKey, aFall, bKey, bFall) {
    const d = actOf(bKey, bFall) - actOf(aKey, aFall);
    if (d) return d;
    if (aKey < bKey) return -1;
    if (aKey > bKey) return 1;
    return 0;
  }

  function listedGroups() {
    return groups.slice().sort((a, b) =>
      cmpAct(`g:${a.group_id}`, a.last_activity_ms, `g:${b.group_id}`, b.last_activity_ms));
  }

  function listedFriends() {
    return (contacts.friends || []).slice().sort((a, b) =>
      cmpAct(`c:${a.peer}`, a.since, `c:${b.peer}`, b.since));
  }

  function stashThread(which) {
    if (!which) return;
    if (which.startsWith('g:') && (entries.length || headMeta)) {
      saveThreadSnap('g', which.slice(2), { entries, oldestSeq, headSeq, headMeta });
    }
    if (which.startsWith('c:') && chatEntries.length) {
      saveThreadSnap('c', which.slice(2), { entries: chatEntries, scanned: chatScanned });
    }
  }

  function setBusy(kind, on) {
    if (kind === 'roster') rosterBusy += on ? 1 : -1;
    else threadBusy += on ? 1 : -1;
    if (rosterBusy < 0) rosterBusy = 0;
    if (threadBusy < 0) threadBusy = 0;
    if (progressEl) progressEl.hidden = rosterBusy + threadBusy <= 0;
  }
  function saveLocalOut() {
    const json = JSON.stringify(localOut);
    try { localStorage.setItem(`a2al.gb.invites.${viewAid}`, json); } catch (_) { /* */ }
    try { sessionStorage.setItem(localOutKey(), json); } catch (_) { /* */ }
  }
  function serverHas(list, peer) {
    return (list || []).some((it) => it.peer === peer);
  }
  function recStatus(rec) {
    if (!rec) return '';
    if (rec.status) return rec.status;
    if (rec.sending) return 'sending';
    if (rec.error) return 'error';
    return 'waiting';
  }
  function applyLocalOut() {
    for (const it of serverContacts.out_pending || []) {
      if (!localOut[it.peer]) {
        localOut[it.peer] = {
          note: it.note || '',
          since: it.since || Date.now(),
          status: 'waiting',
          sending: false,
          seenOut: true,
        };
      }
    }
    for (const peer of Object.keys(localOut)) {
      const rec = localOut[peer];
      const st = recStatus(rec);
      if (st === 'sending') continue;
      if (serverHas(serverContacts.friends, peer)) {
        rec.status = 'accepted';
        rec.sending = false;
        rec.error = '';
      } else if (serverHas(serverContacts.out_pending, peer)) {
        rec.seenOut = true;
        if (st !== 'error' && st !== 'refused') {
          rec.status = 'waiting';
          rec.sending = false;
          rec.error = '';
        }
      } else if (st === 'waiting' && rec.seenOut) {
        rec.status = 'refused';
        rec.sending = false;
      } else if (st === 'accepted') {
        delete localOut[peer];
      }
    }
    saveLocalOut();
    const out = [...(serverContacts.out_pending || [])];
    const have = new Set(out.map((x) => x.peer));
    for (const [peer, rec] of Object.entries(localOut)) {
      if (have.has(peer) || recStatus(rec) === 'accepted') continue;
      out.push({ peer, note: rec.note || '', since: rec.since || 0 });
    }
    contacts = {
      friends: serverContacts.friends || [],
      in_pending: serverContacts.in_pending || [],
      out_pending: out,
    };
  }
  function inviteStatusLabel(rec) {
    const st = recStatus(rec);
    if (st === 'sending') return t('chat.head.sending');
    if (st === 'error') return rec.error || t('chat.request.failed');
    if (st === 'refused') return t('chat.invite.refused');
    if (st === 'accepted') return t('chat.invite.accepted');
    return t('chat.section.out_pending');
  }
  function groupId() { return sel.startsWith('g:') ? sel.slice(2) : ''; }
  function chatPeer() { return sel.startsWith('c:') ? sel.slice(2) : ''; }

  function mcpCall(tool, args) {
    return api('/mcp/call', { method: 'POST', body: JSON.stringify({ tool, args }) });
  }

  function groupLinkOf(gid) {
    const g = groups.find((x) => x.group_id === gid);
    if (!g || !g.creator) return '';
    return `a2al://${g.creator}/groups/${gid}`;
  }

  function parseGroupLink(link) {
    const m = String(link || '').trim().match(/^a2al:\/\/([^/]+)\/groups\/([0-9a-fA-F]{64})$/);
    if (!m) return null;
    return { creator: m[1], group_id: m[2].toLowerCase(), link: `a2al://${m[1]}/groups/${m[2].toLowerCase()}` };
  }

  function parseInviteNote(m) {
    if (Number(m.msg_type) !== MSG_GROUP_INVITE) return null;
    let body;
    try { body = JSON.parse(base64ToUtf8(m.body_base64) || ''); } catch { return null; }
    if (!body || !body.link) return null;
    const parsed = parseGroupLink(body.link);
    if (!parsed) return null;
    const hints = Array.isArray(body.member_hints) ? body.member_hints.filter((x) => typeof x === 'string') : [];
    return {
      message_id: m.message_id || '',
      sender: m.sender || '',
      title: typeof body.title === 'string' ? body.title : '',
      member_hints: hints,
      ...parsed,
    };
  }

  function saveIgnored() {
    try { localStorage.setItem(`a2al.gb.ignore.${viewAid}`, JSON.stringify([...ignoredRoom])); } catch (_) { /* */ }
  }

  function ignoreRoomInvite(id) {
    if (!id) return;
    ignoredRoom.add(id);
    saveIgnored();
    roomInvites = roomInvites.filter((x) => x.message_id !== id);
    listSig = '';
    renderList();
    if (sel === 'requests') paintRequests();
  }

  async function acceptRoomInvite(id, btn) {
    const inv = roomInvites.find((x) => x.message_id === id);
    if (!inv) return;
    if (btn) { btn.disabled = true; btn.textContent = t('gb.joining'); }
    try {
      await mcpCall('group_join', {
        aid: viewAid,
        link: inv.link,
        inviter_aid: inv.sender,
        title: inv.title || undefined,
        member_hints: inv.member_hints.length ? inv.member_hints : undefined,
      });
      await refreshRoster();
      await openSel(`g:${inv.group_id}`);
    } catch (e) {
      if (btn) { btn.disabled = false; btn.textContent = t('gb.join_link'); }
      toast(e.message || t('gb.join_failed'), 'err');
    }
  }

  function formErr(msg) {
    const errEl = threadEl.querySelector('.gb-form-err') || (subEl && subEl.querySelector('.gb-form-err'));
    if (errEl) {
      errEl.hidden = false;
      errEl.textContent = msg;
    } else toast(msg, 'err');
  }

  async function createGroup() {
    const title = (threadEl.querySelector('#gb-gtitle')?.value || '').trim();
    try {
      const out = await mcpCall('group_create', { aid: viewAid, title: title || undefined });
      const gid = out && out.group_id;
      await refreshRoster();
      if (gid) await openSel(`g:${gid}`);
    } catch (e) {
      formErr(e.message || t('gb.create_failed'));
    }
  }

  async function joinByLink(raw) {
    const parsed = parseGroupLink(raw);
    if (!parsed) {
      formErr(t('gb.need_aid_or_link'));
      return;
    }
    try {
      await mcpCall('group_join', { aid: viewAid, link: parsed.link });
      await refreshRoster();
      await openSel(`g:${parsed.group_id}`);
    } catch (e) {
      formErr(e.message || t('gb.join_failed'));
    }
  }

  async function copyGroupLink() {
    const link = groupLinkOf(groupId());
    if (!link) return;
    copyText(link);
  }

  async function inviteMember(raw) {
    const peer = String(raw || '').trim();
    const errEl = subEl && subEl.querySelector('.gb-form-err');
    const show = (msg) => {
      if (errEl) { errEl.hidden = false; errEl.textContent = msg; }
      else toast(msg, 'err');
    };
    if (!peer) { show(t('chat.request.need_peer')); return; }
    if (peer === viewAid) { show(t('chat.request.self')); return; }
    try {
      await mcpCall('group_invite', { aid: viewAid, group_id: groupId(), target_aid: peer });
      gInviteOn = false;
      toast(t('gb.invite_sent'), 'ok');
      paintHead();
    } catch (e) {
      show(e.message || t('gb.invite_failed'));
    }
  }

  function whoName() {
    return aliasOf(viewAid) || shortAid(viewAid);
  }

  function paintWho() {
    const modal = threadEl && threadEl.closest('.modal');
    const bar = modal && modal.querySelector('.gb-who');
    if (!bar) return;
    const name = whoName();
    bar.innerHTML = `
      <div class="gb-av" style="${aidAvStyle(viewAid)}">${esc(initial(name))}</div>
      <span class="gb-who-alias">${esc(name)}</span>
      <button type="button" class="btn btn-ghost btn-xs" data-alias title="${esc(t('agent.alias.set'))}">✏</button>
      <span class="aid-short">${shortAidHTML(viewAid)}</span>
      <button type="button" class="btn btn-ghost btn-xs" data-copy title="${esc(t('common.copy'))}">⧉</button>`;
  }

  function onWhoClick(ev) {
    if (ev.target.closest('[data-alias]')) {
      openAlias(viewAid);
      return;
    }
    if (ev.target.closest('[data-copy]')) copyText(viewAid);
  }

  function openAlias(aid) {
    aliasTarget = aid;
    aliasForm.hidden = false;
    const input = aliasForm.querySelector('input');
    input.value = aliasOf(aid);
    input.focus();
  }

  function saveAlias() {
    if (aliasForm.hidden) return;
    const v = aliasForm.querySelector('input').value.trim();
    setAliasOf(aliasTarget, v || nextUniqueDefaultAlias());
    aliasForm.hidden = true;
    paintWho();
    renderList();
    paintHead();
  }

  function onVis() {
    if (stopped) return;
    if (document.hidden) {
      if (timer) { clearTimeout(timer); timer = null; }
      return;
    }
    tick();
  }

  function schedule() {
    if (stopped || document.hidden) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(tick, POLL_MS);
  }

  function startDoorbell() {
    try {
      const src = new EventSource(`/agents/${encodeURIComponent(viewAid)}/events?types=chat.invites,chat.unread,chat.received,group.unread,mailbox.received`);
      es = src;
      const kick = (ev) => {
        let d = {};
        try { d = JSON.parse(ev.data || '{}') || {}; } catch (_) { /* */ }
        if (d.peer) touch(`c:${d.peer}`, Date.now());
        if (d.group_id) touch(`g:${d.group_id}`, Date.now());
        refreshRoster({ silent: true, box: true }).then(() => refreshThreadTail());
      };
      src.addEventListener('chat.invites', kick);
      src.addEventListener('chat.unread', kick);
      src.addEventListener('chat.received', kick);
      src.addEventListener('group.unread', kick);
      src.addEventListener('mailbox.received', kick);
    } catch (_) { /* poll remains */ }
  }

  async function boot() {
    applyLocalOut();
    restoreRosterSnap();
    hydrateActFromSnaps();
    seedUnread();
    renderList();
    const wanted = sessionStorage.getItem(selStorageKey()) || '';
    let next = validSel(wanted) ? wanted : defaultSel();
    if (!next) {
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('common.loading'))}</div>`;
    }
    const opening = openSel(next, { restore: true });
    await refreshRoster();
    if (stopped) return;
    const prefer = validSel(wanted) ? wanted : defaultSel();
    if (prefer !== sel) await openSel(prefer, { restore: true });
    else await opening;
    schedule();
  }

  async function tick() {
    if (stopped || document.hidden) return;
    await refreshRoster({ silent: true });
    await refreshThreadTail();
    schedule();
  }

  function applyRosterPaint() {
    const joined = new Set(groups.map((x) => String(x.group_id || '').toLowerCase()));
    roomInvites = roomInvites.filter((inv) => inv && !joined.has(inv.group_id) && !ignoredRoom.has(inv.message_id));
    hydrateActFromSnaps();
    bumpUnread();
    renderList();
    if (sel === 'requests') {
      paintHead();
      paintRequests();
    } else if (sel === 'newgroup') {
      paintHead();
    } else if (sel.startsWith('c:')) paintHead();
    if (sel.startsWith('g:') && headMeta) {
      const g0 = groups.find((x) => x.group_id === groupId());
      if (g0 && g0.member_count != null) headMeta.member_count = g0.member_count;
      if (!gInviteOn) paintHead();
    }
    saveRosterSnap();
  }

  async function refreshRoster(opt = {}) {
    if (stopped) return;
    const silent = !!opt.silent;
    if (!silent) {
      setBusy('roster', true);
      renderList();
    }
    const forceBox = opt.box || sel === 'requests';
    const wantBox = forceBox || lastBoxAt === 0 || (Date.now() - lastBoxAt > 4000);
    // Mailbox fires independently — GET /mailbox goes to DHT and can take seconds.
    // Groups and contacts are local state; busy clears as soon as they return.
    if (wantBox) {
      lastBoxAt = Date.now(); // set early to prevent concurrent re-entry during flight
      api(`/agents/${encodeURIComponent(viewAid)}/mailbox`).then((box) => {
        if (stopped) return;
        roomInvites = (box.messages || []).map(parseInviteNote);
        applyRosterPaint();
      }).catch(() => {});
    }
    await Promise.all([
      api(`/agents/${encodeURIComponent(viewAid)}/groups`).then((g) => {
        if (stopped || !g) return;
        groups = (g.groups || []).slice();
        applyRosterPaint();
      }).catch(() => {}),
      api(`/agents/${encodeURIComponent(viewAid)}/chat/contacts`).then((c) => {
        if (stopped || !c) return;
        serverContacts = c;
        applyLocalOut();
        applyRosterPaint();
      }).catch(() => {}),
    ]);
    if (!silent) setBusy('roster', false);
    if (stopped) return;
    applyRosterPaint();
    if (sel && !validSel(sel)) await openSel(defaultSel(), { restore: true });
  }

  function validSel(s) {
    if (s === 'invite' || s === 'requests' || s === 'newgroup') return true;
    if (s.startsWith('g:')) return groups.some((g) => g.group_id === s.slice(2));
    if (s.startsWith('c:')) return !!listedRel(s.slice(2));
    return false;
  }

  function defaultSel() {
    const g0 = listedGroups()[0];
    if (g0) return `g:${g0.group_id}`;
    const f = listedFriends()[0];
    if (f) return `c:${f.peer}`;
    return '';
  }

  function listedRel(peer) {
    for (const key of ['friends', 'out_pending', 'in_pending']) {
      if ((contacts[key] || []).some((it) => it.peer === peer)) return key;
    }
    return '';
  }

  function markSeen(key) {
    if (!key.startsWith('g:') && !key.startsWith('c:')) return;
    seen[key] = 1;
    try { sessionStorage.setItem(seenKey(viewAid), JSON.stringify(seen)); } catch (_) { /* */ }
  }

  function lamps(key, unread) {
    const n = Number(unread) || 0;
    const count = (n > 0 && !seen[key])
      ? `<span class="gb-count" title="${esc(t('gb.unread'))}">${n > 9 ? '9+' : String(n)}</span>`
      : '';
    const pip = n > 0
      ? `<span class="gb-pip" title="${esc(t('gb.pip'))}"></span>`
      : '';
    if (!count && !pip) return '';
    return `<span class="gb-list-lamps">${count}${pip}</span>`;
  }

  function renderList() {
    if (!listScrollEl || !listFootEl) return;
    const y = listScrollEl.scrollTop;
    let html = '';
    html += `<div class="gb-list-h gb-list-h-row"><span>${esc(t('gb.section.groups'))}</span>
      <button type="button" class="gb-add${sel === 'newgroup' ? ' on' : ''}" data-newgroup title="${esc(t('gb.add_group'))}">+</button></div>`;
    for (const g of listedGroups()) {
      const key = `g:${g.group_id}`;
      const title = (g.title || '').trim() || String(g.group_id || '').slice(0, 8);
      const n = Number(g.member_count) || 0;
      html += `<button type="button" class="gb-list-item${sel === key ? ' on' : ''}" data-sel="${esc(key)}">
        <span class="gb-list-main"><span class="gb-list-hash">#</span><span class="gb-list-label">${esc(title)}</span>
        ${n ? `<span class="gb-list-mc">${esc(String(n))}</span>` : ''}</span>
        ${lamps(key, g.unread_count)}</button>`;
    }
    if (!groups.length && rosterBusy) {
      html += `<div class="gb-list-ph muted">${esc(t('common.loading'))}</div>`;
    }
    html += `<div class="gb-list-h gb-list-h-row"><span>${esc(t('gb.section.friends'))}</span>
      <button type="button" class="gb-add${sel === 'invite' ? ' on' : ''}" data-invite title="${esc(t('gb.add_friend'))}">+</button></div>`;
    for (const it of listedFriends()) {
      const key = `c:${it.peer}`;
      html += `<button type="button" class="gb-list-item${sel === key ? ' on' : ''}" data-sel="${esc(key)}">
        <span class="gb-list-main"><span class="gb-list-label">${esc(displayName(it.peer))}</span></span>
        ${lamps(key, it.unread_count)}</button>`;
    }
    if (!(contacts.friends || []).length && rosterBusy) {
      html += `<div class="gb-list-ph muted">${esc(t('common.loading'))}</div>`;
    }
    const sig = html + '|' + sel + '|' + footOn + '|' + roomInvites.length + '|' + (contacts.in_pending || []).length + '|' + rosterBusy;
    if (sig === listSig) {
      paintListToggle();
      return;
    }
    listSig = sig;
    listScrollEl.innerHTML = html;
    listScrollEl.scrollTop = y;
    listScrollEl.querySelectorAll('[data-sel]').forEach((btn) => {
      btn.onclick = () => openSel(btn.dataset.sel);
    });
    const add = listScrollEl.querySelector('[data-invite]');
    if (add) add.onclick = () => openSel('invite');
    const addG = listScrollEl.querySelector('[data-newgroup]');
    if (addG) addG.onclick = () => openSel('newgroup');

    const inN = (contacts.in_pending || []).length + roomInvites.length;
    const outAlert = Object.values(localOut).some((r) => {
      const s = recStatus(r);
      return s === 'error' || s === 'refused';
    });
    const inMark = inN ? `<span class="gb-count">${inN > 9 ? '9+' : String(inN)}</span>` : '';
    const outMark = outAlert ? `<span class="gb-out-alert" title="${esc(t('gb.out_alert'))}">!</span>` : '';
    const reqOn = sel === 'requests';
    listFootEl.innerHTML = `
      <button type="button" class="gb-foot-btn gb-foot-req${reqOn ? ' on' : ''}" data-foot="requests">
        <span>${esc(t('gb.requests'))}</span>${inMark}${outMark}</button>`;
    listFootEl.querySelector('[data-foot]').onclick = () => openSel('requests');
    paintListToggle();
  }

  async function openSel(next, opt = {}) {
    stashThread(sel);
    sel = next || '';
    gInviteOn = false;
    replyDraft = null;
    if (sel !== 'requests') footOn = '';
    if (sel === 'requests' && !footOn) footOn = 'in';  // default tab = received
    try { sessionStorage.setItem(selStorageKey(), sel); } catch (_) { /* */ }
    markSeen(sel);
    listSig = '';
    if (!opt.restore && isNarrow() && sel) {
      listPeek = false;
    }
    renderList();
    applyGeom();
    const g = ++gen;
    if (!sel) {
      headEl.hidden = true;
      composerEl.hidden = true;
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('chat.empty.thread'))}</div>`;
      return;
    }
    if (sel === 'invite') {
      paintHead();
      paintInvite();
      return;
    }
    if (sel === 'newgroup') {
      paintHead();
      paintNewGroup();
      return;
    }
    if (sel === 'requests') {
      paintHead();
      paintRequests();
      return;
    }
    if (sel.startsWith('g:')) {
      await loadGroup(groupId(), g);
      return;
    }
    await loadChat(g, opt);
  }

  function paintHead() {
    if (whoEl && whoEl.querySelector('.gb-members.open')) {
      paintReplyBar();
      return;
    }
    withdrawBtn.hidden = true;
    withdrawBtn.textContent = t('chat.withdraw');
    removeBtn.hidden = true;
    inviteBtn.hidden = true;
    linkBtn.hidden = true;
    leaveBtn.hidden = true;
    subEl.hidden = true;
    subEl.textContent = '';
    if (!sel || sel === '') {
      headEl.hidden = true;
      composerEl.hidden = true;
      paintReplyBar();
      return;
    }
    headEl.hidden = false;
    if (sel === 'invite') {
      whoEl.innerHTML = `<div class="gb-chat-name">${esc(t('gb.add_friend'))}</div>`;
      composerEl.hidden = true;
      paintReplyBar();
      return;
    }
    if (sel === 'newgroup') {
      whoEl.innerHTML = `<div class="gb-chat-name">${esc(t('gb.add_group'))}</div>`;
      composerEl.hidden = true;
      paintReplyBar();
      return;
    }
    if (sel === 'requests') {
      whoEl.innerHTML = `<div class="gb-chat-name">${esc(t('gb.requests'))}</div>`;
      composerEl.hidden = true;
      paintReplyBar();
      return;
    }
    if (sel.startsWith('g:')) {
      const g = groups.find((x) => x.group_id === groupId()) || {};
      const title = (g.title || headMeta?.title || '').trim() || String(groupId()).slice(0, 8);
      const n = Number(headMeta?.member_count ?? g.member_count) || 0;
      const members = headMeta?.members || [];
      const pop = members.map((m) => {
        const al = aliasOf(m.aid);
        const label = al ? esc(al) : shortAidHTML(m.aid);
        return `<div class="gb-mem">
          <span class="gb-av-sm" style="${aidAvStyle(m.aid)}">${esc(initial(al || shortAid(m.aid)))}</span>
          <span>${label}</span>
          <span class="gb-mem-acts">
            <button type="button" class="gb-act" data-copy-aid="${esc(m.aid)}" title="${esc(t('common.copy'))}">⧉</button>
            <button type="button" class="gb-act" data-mention="${esc(m.aid)}" title="${esc(t('gb.mention'))}">@</button>
            <span class="muted">${esc(m.role || '')}</span>
          </span>
        </div>`;
      }).join('');
      whoEl.innerHTML = `
        <span class="gb-chat-name">${esc(title)}</span>
        <div class="gb-members">
          <button type="button" class="gb-members-btn" title="${esc(t('gb.members'))}">${esc(String(n))}</button>
          <div class="gb-members-pop">${pop || `<div class="gb-mem muted">${esc(t('gb.members'))}</div>`}</div>
        </div>`;
      const wrap = whoEl.querySelector('.gb-members');
      wrap.querySelector('.gb-members-btn').onclick = (e) => {
        e.stopPropagation();
        wrap.classList.add('open');
      };
      wrap.addEventListener('mouseenter', () => wrap.classList.add('open'));
      const me = members.find((m) => m.aid === viewAid);
      const role = (me && me.role) || '';
      leaveBtn.hidden = role === 'creator';
      inviteBtn.hidden = role !== 'creator' && role !== 'admin';
      linkBtn.hidden = !groupLinkOf(groupId());
      composerEl.hidden = false;
      if (gInviteOn && !inviteBtn.hidden) {
        subEl.hidden = false;
        subEl.innerHTML = `
          <input type="text" id="gb-gpeer" placeholder="${esc(t('gb.invite_aid_ph'))}" />
          <button type="button" class="btn btn-primary btn-xs" data-gsend>${esc(t('gb.invite_member'))}</button>
          <div class="gb-form-err" hidden></div>`;
        const inp = subEl.querySelector('#gb-gpeer');
        const send = () => inviteMember(inp && inp.value);
        subEl.querySelector('[data-gsend]').onclick = send;
        inp.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') { e.preventDefault(); send(); }
        });
      }
      paintReplyBar();
      return;
    }
    const peer = chatPeer();
    const rel = listedRel(peer);
    const name = displayName(peer);
    whoEl.innerHTML = `
      <span class="gb-who-alias">${esc(name)}</span>
      <button type="button" class="btn btn-ghost btn-xs" data-peer-alias title="${esc(t('agent.alias.set'))}">✏</button>
      <span class="aid-short">${shortAidHTML(peer)}</span>
      <button type="button" class="btn btn-ghost btn-xs" data-peer-copy title="${esc(t('common.copy'))}">⧉</button>`;
    whoEl.querySelector('[data-peer-alias]').onclick = () => openAlias(peer);
    whoEl.querySelector('[data-peer-copy]').onclick = () => copyText(peer);
    removeBtn.hidden = rel !== 'friends';
    const rec = localOut[peer];
    const st = recStatus(rec);
    const inviteOpen = rel === 'out_pending';
    withdrawBtn.hidden = !inviteOpen;
    if (inviteOpen) withdrawBtn.textContent = t('chat.withdraw');
    if (inviteOpen) {
      subEl.hidden = false;
      if (st === 'sending') {
        subEl.textContent = t('chat.head.sending');
      } else if (st === 'error') {
        subEl.innerHTML = `<span class="gb-chat-err">${esc(rec.error || t('chat.request.failed'))}</span>
          <button type="button" class="btn btn-ghost btn-xs" data-retry>${esc(t('chat.request.retry'))}</button>`;
        subEl.querySelector('[data-retry]').onclick = (ev) => {
          ev.preventDefault();
          deliverInvite(peer);
        };
      } else if (st === 'refused') {
        subEl.innerHTML = `<span>${esc(t('chat.head.refused'))}</span>
          <button type="button" class="btn btn-ghost btn-xs" data-retry>${esc(t('chat.invite.again'))}</button>`;
        subEl.querySelector('[data-retry]').onclick = (ev) => {
          ev.preventDefault();
          deliverInvite(peer);
        };
      } else {
        subEl.textContent = t('chat.head.wait');
      }
    }
    composerEl.hidden = rel === 'in_pending' || st === 'refused' || st === 'error';
    paintReplyBar();
  }

  function paintReplyBar() {
    const bar = composerEl && composerEl.querySelector('#gb-reply');
    const txt = composerEl && composerEl.querySelector('#gb-reply-txt');
    if (!bar) return;
    const on = sel.startsWith('g:') && replyDraft && !composerEl.hidden;
    bar.hidden = !on;
    if (on && txt) txt.textContent = t('gb.replying', { who: displayName(replyDraft.author) });
  }

  function mentionAids() {
    const out = [];
    const seen = new Set();
    const add = (aid) => {
      if (!aid || seen.has(aid)) return;
      seen.add(aid);
      out.push(aid);
    };
    for (const m of headMeta?.members || []) add(m.aid);
    for (const e of entries) add(e.author);
    return out;
  }

  function mentionRoster() {
    const rows = [];
    for (const aid of mentionAids()) {
      rows.push({ token: aid, aid });
      const al = aliasOf(aid);
      if (al) rows.push({ token: al, aid });
      rows.push({ token: shortAid(aid), aid });
    }
    rows.sort((a, b) => b.token.length - a.token.length);
    return rows;
  }

  function parseMentions(text) {
    const roster = mentionRoster();
    const to = [];
    const seen = new Set();
    const s = String(text || '');
    let i = 0;
    while (i < s.length) {
      if (s[i] !== '@') { i += 1; continue; }
      const rest = s.slice(i + 1);
      let hit = null;
      for (const row of roster) {
        if (!row.token || rest.length < row.token.length) continue;
        if (rest.slice(0, row.token.length).toLowerCase() !== row.token.toLowerCase()) continue;
        const after = rest[row.token.length];
        if (after != null && after !== '@' && !/\s/.test(after)) continue;
        hit = row;
        break;
      }
      if (hit) {
        if (!seen.has(hit.aid)) {
          seen.add(hit.aid);
          to.push(hit.aid);
        }
        i += 1 + hit.token.length;
      } else {
        i += 1;
      }
    }
    return to;
  }

  function insertMention(aid) {
    if (!aid || !sel.startsWith('g:') || !textEl || composerEl.hidden) return;
    const token = `@${shortAid(aid)} `;
    const start = textEl.selectionStart ?? textEl.value.length;
    const end = textEl.selectionEnd ?? start;
    const v = textEl.value || '';
    const before = v.slice(0, start);
    const ins = (before && !/\s$/.test(before) ? ' ' : '') + token;
    textEl.value = before + ins + v.slice(end);
    const pos = before.length + ins.length;
    textEl.focus();
    textEl.setSelectionRange(pos, pos);
  }

  function setQuote(id) {
    if (!sel.startsWith('g:') || composerEl.hidden) return;
    const e = entries.find((x) => x.id === id);
    if (!e || isSys(e)) return;
    replyDraft = { id: e.id, author: e.author };
    paintReplyBar();
    if (textEl) textEl.focus();
  }

  function onHeadWhoClick(ev) {
    if (!sel.startsWith('g:')) return;
    const m = ev.target.closest('[data-mention]');
    if (m) {
      ev.preventDefault();
      ev.stopPropagation();
      insertMention(m.dataset.mention);
      const wrap = whoEl.querySelector('.gb-members.open');
      if (wrap) wrap.classList.remove('open');
      return;
    }
    const c = ev.target.closest('[data-copy-aid]');
    if (c) {
      ev.preventDefault();
      ev.stopPropagation();
      copyText(c.dataset.copyAid);
    }
  }

  function onMembersOutside(e) {
    const wrap = whoEl && whoEl.querySelector('.gb-members.open');
    if (!wrap || wrap.contains(e.target)) return;
    wrap.classList.remove('open');
  }

  function onMembersEsc(e) {
    if (e.key !== 'Escape') return;
    const wrap = whoEl && whoEl.querySelector('.gb-members.open');
    if (!wrap) return;
    wrap.classList.remove('open');
    e.stopImmediatePropagation();
  }

  async function leaveGroup() {
    if (!sel.startsWith('g:')) return;
    if (!confirm(t('gb.leave.confirm'))) return;
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/groups/${groupId()}/leave`, {
        method: 'POST',
        body: '{}',
      });
      await refreshRoster();
      await openSel(defaultSel());
    } catch (e) {
      toast(e.message || String(e), 'err');
    }
  }

  function paintInvite() {
    composerEl.hidden = true;
    threadEl.innerHTML = `<div class="gb-invite-form">
      <input type="text" id="gb-peer" placeholder="${esc(t('gb.peer_placeholder'))}" />
      <textarea rows="2" id="gb-note" placeholder="${esc(t('gb.note_placeholder'))}"></textarea>
      <button type="button" class="btn btn-primary btn-sm" data-request>${esc(t('chat.send'))}</button>
      <div class="gb-form-err" hidden></div>
    </div>`;
    threadEl.querySelector('[data-request]').onclick = sendRequest;
  }

  function paintRequests() {
    composerEl.hidden = true;
    const inP = contacts.in_pending || [];
    const logs = Object.entries(localOut)
      .map(([peer, rec]) => ({ peer, rec }))
      .sort((a, b) => (b.rec.since || 0) - (a.rec.since || 0));
    const inN = inP.length;
    const inBadge = inN ? `<span class="gb-count">${inN > 9 ? '9+' : String(inN)}</span>` : '';
    const outAlert = logs.some(({ rec }) => { const s = recStatus(rec); return s === 'error' || s === 'refused'; });
    const outBadge = outAlert ? `<span class="gb-out-alert">!</span>` : '';
    const onIn = footOn !== 'out';
    let html = `<div class="gb-req-tabs">
      <button type="button" class="gb-req-tab${onIn ? ' on' : ''}" data-tab="in">
        ${esc(t('gb.pending_in'))}${inBadge}
      </button>
      <button type="button" class="gb-req-tab${!onIn ? ' on' : ''}" data-tab="out">
        ${esc(t('gb.pending_out'))}${outBadge}
      </button>
    </div>`;
    if (onIn) {
      if (!inP.length && !roomInvites.length) {
        html += `<div class="gb-empty muted">${esc(t('gb.empty.received'))}</div>`;
      } else {
        html += `<div class="gb-req-pane">`;
        for (const inv of roomInvites) {
          const title = (inv.title || '').trim() || t('gb.room_invite.plain');
          html += `<div class="gb-board-row">
            <div class="gb-board-item">
              <span class="gb-list-label">${esc(t('gb.room_invite', { who: displayName(inv.sender), title }))}</span>
              <span class="gb-invite-hint">${shortAidHTML(inv.sender)}</span>
            </div>
            <button type="button" class="btn btn-ghost btn-xs" data-ignore="${esc(inv.message_id)}">${esc(t('gb.ignore'))}</button>
            <button type="button" class="btn btn-primary btn-xs" data-join="${esc(inv.message_id)}">${esc(t('gb.join_link'))}</button>
          </div>`;
        }
        for (const it of inP) {
          html += `<button type="button" class="gb-board-item" data-sel="c:${esc(it.peer)}">
            <span class="gb-list-label">${esc(displayName(it.peer))}</span>
            <span class="gb-invite-hint muted">${esc(t('gb.pending_in_hint'))}</span>
          </button>`;
        }
        html += `</div>`;
      }
    } else {
      if (!logs.length) {
        html += `<div class="gb-empty muted">${esc(t('gb.empty.sent'))}</div>`;
      } else {
        html += `<div class="gb-req-pane">`;
        for (const { peer, rec } of logs) {
          const st = recStatus(rec);
          const stCls = st === 'error' || st === 'refused' ? ' err' : (st === 'accepted' ? ' ok' : '');
          html += `<div class="gb-board-row">
            <button type="button" class="gb-board-item" data-sel="c:${esc(peer)}">
              <span class="gb-list-label">${esc(displayName(peer))}</span>
              <span class="gb-invite-st${stCls}">${esc(inviteStatusLabel(rec))}</span>
            </button>
            <button type="button" class="btn btn-ghost btn-xs" data-forget="${esc(peer)}">${esc(st === 'accepted' ? t('chat.invite.forget') : t('chat.withdraw'))}</button>
          </div>`;
        }
        html += `</div>`;
      }
    }
    threadEl.innerHTML = html;
    threadEl.querySelectorAll('[data-tab]').forEach((btn) => {
      btn.onclick = () => {
        footOn = btn.dataset.tab;
        paintRequests();
        renderList();
      };
    });
    threadEl.querySelectorAll('[data-sel]').forEach((btn) => {
      btn.onclick = () => openSel(btn.dataset.sel);
    });
    threadEl.querySelectorAll('[data-forget]').forEach((btn) => {
      btn.onclick = (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        clearInvite(btn.dataset.forget);
      };
    });
    threadEl.querySelectorAll('[data-join]').forEach((btn) => {
      btn.onclick = (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        acceptRoomInvite(btn.dataset.join, btn);
      };
    });
    threadEl.querySelectorAll('[data-ignore]').forEach((btn) => {
      btn.onclick = (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        ignoreRoomInvite(btn.dataset.ignore);
      };
    });
  }

  function paintNewGroup() {
    composerEl.hidden = true;
    threadEl.innerHTML = `<div class="gb-invite-form">
      <input type="text" id="gb-gtitle" maxlength="80" placeholder="${esc(t('gb.create_title_ph'))}" />
      <button type="button" class="btn btn-primary btn-sm" data-create>${esc(t('gb.create'))}</button>
      <input type="text" id="gb-glink" placeholder="${esc(t('gb.join_link_ph'))}" style="margin-top:.85rem" />
      <button type="button" class="btn btn-secondary btn-sm" data-joinlink>${esc(t('gb.join_link'))}</button>
      <div class="gb-form-err" hidden></div>
    </div>`;
    threadEl.querySelector('[data-create]').onclick = createGroup;
    threadEl.querySelector('[data-joinlink]').onclick = () => {
      const link = (threadEl.querySelector('#gb-glink')?.value || '').trim();
      joinByLink(link);
    };
  }

  async function sendRequest() {
    const peer = (threadEl.querySelector('#gb-peer')?.value || '').trim();
    const note = (threadEl.querySelector('#gb-note')?.value || '').trim();
    const errEl = threadEl.querySelector('.gb-form-err');
    const showErr = (msg) => {
      if (errEl) {
        errEl.hidden = false;
        errEl.textContent = msg;
      } else toast(msg, 'err');
    };
    if (!peer) {
      showErr(t('chat.request.need_peer'));
      return;
    }
    if (peer === viewAid) {
      showErr(t('chat.request.self'));
      return;
    }
    const rel = listedRel(peer);
    if (rel === 'friends' || rel === 'in_pending') {
      await openSel(`c:${peer}`);
      return;
    }
    const est = recStatus(localOut[peer]);
    if (est === 'sending' || est === 'waiting') {
      await openSel(`c:${peer}`);
      return;
    }
    localOut[peer] = { note, sending: false, error: '', since: Date.now(), status: 'sending' };
    saveLocalOut();
    applyLocalOut();
    await openSel(`c:${peer}`);
    await deliverInvite(peer);
  }

  async function deliverInvite(peer) {
    let st = localOut[peer];
    if (!st) {
      localOut[peer] = { note: '', sending: true, error: '', since: Date.now(), status: 'sending' };
      st = localOut[peer];
    } else {
      if (st.sending) return;
      st.sending = true;
      st.status = 'sending';
      st.error = '';
    }
    const note = st.note || '';
    saveLocalOut();
    applyLocalOut();
    if (sel === `c:${peer}`) paintHead();
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/request`, {
        method: 'POST',
        body: JSON.stringify({ peer, note }),
      });
      if (!localOut[peer]) {
        try {
          await api(`/agents/${encodeURIComponent(viewAid)}/chat/refuse`, {
            method: 'POST',
            body: JSON.stringify({ peer }),
          });
        } catch (_) { /* already gone */ }
        await refreshRoster();
        return;
      }
      await refreshRoster();
      if (localOut[peer]) {
        localOut[peer].sending = false;
        if (serverHas(serverContacts.friends, peer)) {
          localOut[peer].status = 'accepted';
          localOut[peer].error = '';
        } else {
          localOut[peer].seenOut = true;
          localOut[peer].status = 'waiting';
          localOut[peer].error = '';
        }
        saveLocalOut();
        applyLocalOut();
      }
      if (sel === `c:${peer}`) {
        paintHead();
        const rel = listedRel(peer);
        if (rel === 'friends' || rel === 'in_pending') await loadChat(gen);
      }
    } catch (e) {
      if (!localOut[peer]) return;
      localOut[peer].sending = false;
      localOut[peer].status = 'error';
      localOut[peer].error = chatRequestErr(e.message || String(e), t);
      saveLocalOut();
      await refreshRoster();
      if (sel === `c:${peer}`) paintHead();
    }
  }

  async function clearInvite(peer) {
    if (!peer) return;
    const onServer = serverHas(serverContacts.out_pending, peer);
    const viewing = sel === `c:${peer}`;
    const stayChat = listedRel(peer) === 'friends' || recStatus(localOut[peer]) === 'accepted';
    delete localOut[peer];
    saveLocalOut();
    if (onServer) {
      try {
        await api(`/agents/${encodeURIComponent(viewAid)}/chat/refuse`, {
          method: 'POST',
          body: JSON.stringify({ peer }),
        });
      } catch (_) { /* gone */ }
    }
    applyLocalOut();
    await refreshRoster();
    if (sel === 'requests') paintRequests();
    else if (viewing && !stayChat) await openSel(defaultSel());
  }

  async function loadGroup(id, g) {
    if (g == null) g = ++gen;
    const snap = loadThreadSnap('g', id);
    if (snap && Array.isArray(snap.entries) && snap.entries.length) {
      entries = snap.entries;
      oldestSeq = Number(snap.oldestSeq) || 0;
      headSeq = Number(snap.headSeq) || 0;
      headMeta = snap.headMeta || null;
      paintHead();
      paintGroup('bottom');
    } else {
      entries = [];
      oldestSeq = 0;
      headSeq = 0;
      headMeta = null;
      paintHead();
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('common.loading'))}</div>`;
    }
    setBusy('thread', true);
    try {
      const head = await api(`/agents/${encodeURIComponent(viewAid)}/groups/${id}`);
      if (stopped || g !== gen) return;
      headMeta = head;
      paintHead();
      const maxSeq = Number(head.max_seq) || 0;
      const after = Math.max(0, maxSeq - PAGE);
      const page = await fetchEntries(id, after, PAGE);
      if (stopped || g !== gen) return;
      entries = [];
      oldestSeq = 0;
      mergeEntries(page.entries || []);
      headSeq = Number(page.scanned_to_seq) || maxSeq;
      paintGroup('bottom');
      saveThreadSnap('g', id, { entries, oldestSeq, headSeq, headMeta });
    } catch (_) {
      if (stopped || g !== gen) return;
      if (!entries.length) {
        threadEl.innerHTML = `<div class="gb-empty" style="color:var(--error)">${esc(t('group.bubble.load_error'))}</div>`;
      }
    } finally {
      setBusy('thread', false);
    }
  }

  async function loadChat(g) {
    const peer = chatPeer();
    const snap = loadThreadSnap('c', peer);
    if (snap && Array.isArray(snap.entries) && snap.entries.length) {
      chatEntries = snap.entries;
      chatScanned = Number(snap.scanned) || 0;
      paintHead();
      if (listedRel(peer) === 'in_pending') {
        paintChatInvite();
        return;
      }
      paintChat('bottom');
    } else {
      chatEntries = [];
      chatScanned = 0;
      paintHead();
      const rel = listedRel(peer);
      if (rel === 'in_pending') {
        paintChatInvite();
        return;
      }
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('common.loading'))}</div>`;
    }
    const rel = listedRel(peer);
    if (rel === 'in_pending') return;
    setBusy('thread', true);
    try {
      const page = await api(`/agents/${encodeURIComponent(viewAid)}/chat/peers/${encodeURIComponent(peer)}?after_seq=0&limit=${PAGE}`);
      if (stopped || g !== gen) return;
      chatEntries = [];
      mergeChat(page.entries || []);
      const next = Number(page.scanned_to);
      chatScanned = Number.isFinite(next) ? next : 0;
      paintChat('bottom');
      saveThreadSnap('c', peer, { entries: chatEntries, scanned: chatScanned });
    } catch (_) {
      if (stopped || g !== gen) return;
      if (!chatEntries.length) paintChat('bottom');
    } finally {
      setBusy('thread', false);
    }
  }

  async function refreshThreadTail() {
    if (stopped) return;
    if (sel.startsWith('g:')) {
      const g = gen;
      const id = groupId();
      try {
        const head = await api(`/agents/${encodeURIComponent(viewAid)}/groups/${id}`);
        if (g !== gen) return;
        headMeta = head;
        let maxSeq = Number(head.max_seq) || 0;
        let pages = 0;
        while (maxSeq > headSeq && pages < BURST_PAGES) {
          const page = await fetchEntries(id, headSeq, PAGE);
          if (g !== gen) return;
          mergeEntries(page.entries || []);
          const next = Number(page.scanned_to_seq);
          headSeq = Number.isFinite(next) ? next : maxSeq;
          pages++;
          if (!page.has_more) break;
        }
        if (pages) paintGroup('tail');
        else paintHead();
        saveThreadSnap('g', id, { entries, oldestSeq, headSeq, headMeta });
      } catch (_) { /* next */ }
      return;
    }
    if (sel.startsWith('c:')) {
      const rel = listedRel(chatPeer());
      if (rel === 'in_pending') {
        paintHead();
        paintChatInvite();
        return;
      }
      if (!chatPeer()) return;
      try {
        const staleAfter = chatStaleAfter();
        let after = chatScanned;
        let limit = PAGE;
        if (staleAfter != null) {
          after = Math.min(staleAfter, chatScanned);
          limit = Math.max(PAGE, (chatScanned - after) + PAGE);
        }
        const q = `after_seq=${encodeURIComponent(String(after))}&limit=${limit}`;
        const page = await api(`/agents/${encodeURIComponent(viewAid)}/chat/peers/${encodeURIComponent(chatPeer())}?${q}`);
        const dirty = mergeChat(page.entries || []);
        const next = Number(page.scanned_to);
        if (Number.isFinite(next)) chatScanned = Math.max(chatScanned, next);
        if (dirty) paintChat('tail');
        saveThreadSnap('c', chatPeer(), { entries: chatEntries, scanned: chatScanned });
      } catch (_) { /* next */ }
    }
    if (sel === 'requests') paintRequests();
  }

  async function fetchEntries(id, afterSeq, limit) {
    const q = `after_seq=${encodeURIComponent(String(afterSeq))}&limit=${limit}`;
    return api(`/agents/${encodeURIComponent(viewAid)}/groups/${id}/entries?${q}`);
  }

  function mergeEntries(items) {
    const have = new Set(entries.map((e) => e.id));
    for (const e of items) {
      if (!e?.id || have.has(e.id)) continue;
      have.add(e.id);
      entries.push(e);
    }
    entries.sort((a, b) => (a.seq || 0) - (b.seq || 0));
    if (entries.length) oldestSeq = Number(entries[0].seq) || oldestSeq;
  }

  function chatStaleAfter() {
    const peer = chatPeer();
    let minIdx = Infinity;
    for (const e of chatEntries) {
      if (e.dir !== 'out') continue;
      const idx = Number(e.idx) || 0;
      if (e.status === 'local') {
        minIdx = Math.min(minIdx, idx);
        continue;
      }
      if (e.kind !== 'file') continue;
      const fetched = Array.isArray(e.fetched) ? e.fetched : [];
      if (!peer || !fetched.includes(peer)) minIdx = Math.min(minIdx, idx);
    }
    if (minIdx === Infinity) return null;
    return Math.max(0, minIdx - 1);
  }

  function mergeChat(items) {
    const byKey = new Map(chatEntries.map((e) => [`${e.dir}:${e.seq}`, e]));
    let dirty = false;
    for (const e of items) {
      const k = `${e.dir}:${e.seq}`;
      const prev = byKey.get(k);
      if (!prev) {
        byKey.set(k, e);
        dirty = true;
        continue;
      }
      if (chatEntryStale(prev, e)) {
        byKey.set(k, e);
        dirty = true;
      }
    }
    chatEntries = [...byKey.values()].sort((a, b) => (a.idx || 0) - (b.idx || 0));
    return dirty;
  }

  async function loadOlder() {
    if (loadingOlder || oldestSeq <= 1 || !sel.startsWith('g:')) return;
    loadingOlder = true;
    const end = oldestSeq - 1;
    const after = Math.max(0, end - PAGE);
    const limit = end - after;
    const prevH = threadEl.scrollHeight;
    const prevT = threadEl.scrollTop;
    try {
      const page = await fetchEntries(groupId(), after, limit);
      const n = entries.length;
      mergeEntries(page.entries || []);
      if (entries.length > n) {
        paintGroup();
        threadEl.scrollTop = prevT + (threadEl.scrollHeight - prevH);
      }
    } catch (_) { /* stop */ }
    loadingOlder = false;
  }

  function onScroll() {
    if (sel.startsWith('g:') && threadEl.scrollTop < 24) loadOlder();
  }

  function onThreadClick(ev) {
    const q = ev.target.closest('[data-quote]');
    if (q) {
      ev.preventDefault();
      setQuote(q.dataset.quote);
      return;
    }
    const m = ev.target.closest('[data-mention]');
    if (m) {
      ev.preventDefault();
      insertMention(m.dataset.mention);
      return;
    }
    const c = ev.target.closest('[data-copy-aid]');
    if (c) {
      ev.preventDefault();
      copyText(c.dataset.copyAid);
      return;
    }
    const a = ev.target.closest('[data-cas-ref]');
    if (!a) return;
    ev.preventDefault();
    openCasFile(a.dataset.casAuthor, a.dataset.casRef, a.dataset.casName, a);
  }

  async function openCasFile(author, ref, name, linkEl) {
    if (!ref) return;
    const headers = {};
    const tok = getToken();
    if (tok) headers.Authorization = 'Bearer ' + tok;
    let url = `/agents/${encodeURIComponent(viewAid)}/cas/${encodeURIComponent(ref)}`;
    if (author) url += `?hint=${encodeURIComponent(author)}`;
    const prev = linkEl ? linkEl.textContent : '';
    if (linkEl) linkEl.textContent = t('gb.getting');
    try {
      const r = await fetch(url, { headers });
      if (r.status === 401) {
        window.dispatchEvent(new CustomEvent('a2al:unauthorized'));
        toast(t('gb.file_retry'), 'err');
        return;
      }
      if (r.status === 403) {
        toast(t('gb.file_denied'), 'err');
        return;
      }
      if (!r.ok) {
        toast(t('gb.file_unavailable'), 'err');
        return;
      }
      const blob = await r.blob();
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = name || 'file';
      a.click();
      URL.revokeObjectURL(href);
    } catch (_) {
      toast(t('gb.file_retry'), 'err');
    } finally {
      if (linkEl) linkEl.textContent = prev;
    }
  }

  function pinThread(mode) {
    return mode === 'bottom' || (mode === 'tail' && threadEl.scrollHeight - threadEl.scrollTop - threadEl.clientHeight < 56);
  }

  function paintGroup(mode) {
    const pin = pinThread(mode);
    const prevT = threadEl.scrollTop;
    if (!entries.length) {
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('group.bubble.no_messages'))}</div>`;
      return;
    }
    threadEl.innerHTML = renderThread(entries, t, viewAid);
    threadEl.scrollTop = pin ? threadEl.scrollHeight : prevT;
  }

  function paintChat(mode) {
    if (!chatPeer()) return;
    if (!chatEntries.length) {
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('group.bubble.no_messages'))}</div>`;
      return;
    }
    const pin = pinThread(mode);
    const prevT = threadEl.scrollTop;
    threadEl.innerHTML = renderChatThread(chatEntries, t, viewAid, chatPeer());
    threadEl.scrollTop = pin ? threadEl.scrollHeight : prevT;
  }

  function paintChatInvite() {
    const peer = chatPeer();
    const who = displayName(peer);
    const it = (contacts.in_pending || []).find((x) => x.peer === peer);
    const note = (it && it.note) || '';
    threadEl.innerHTML = `<div class="gb-invite">
      <div class="gb-invite-title">${esc(t('chat.invite.title', { who }))}</div>
      ${note ? `<div class="gb-invite-note">${esc(note)}</div>` : ''}
      <div class="gb-invite-actions">
        <button type="button" class="btn btn-ghost" data-refuse>${esc(t('chat.refuse'))}</button>
        <button type="button" class="btn btn-primary" data-accept>${esc(t('chat.accept'))}</button>
      </div>
    </div>`;
    threadEl.querySelector('[data-accept]').onclick = () => chatAct('accept');
    threadEl.querySelector('[data-refuse]').onclick = () => chatAct('refuse');
  }

  async function chatAct(kind) {
    const peer = chatPeer();
    if (!peer) return;
    if (kind === 'remove' && !confirm(t('chat.remove.confirm'))) return;
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/${kind}`, {
        method: 'POST',
        body: JSON.stringify({ peer }),
      });
      await refreshRoster();
      if (kind === 'accept') await openSel(`c:${peer}`);
      else await openSel(defaultSel());
    } catch (e) {
      toast(chatActErr(e.message || String(e), t), 'err');
    }
  }

  async function sendGroupAppend({ text, objectId, name }) {
    const to = parseMentions(textEl.value || '');
    const replyTo = replyDraft ? replyDraft.id : '';
    if (!to.length && !replyTo) {
      if (objectId) {
        await api(`/agents/${encodeURIComponent(viewAid)}/groups/${groupId()}/append`, {
          method: 'POST',
          body: JSON.stringify({ object_id: objectId, name }),
        });
      } else {
        await api(`/agents/${encodeURIComponent(viewAid)}/groups/${groupId()}/append`, {
          method: 'POST',
          body: JSON.stringify({ text }),
        });
      }
      return;
    }
    const args = { aid: viewAid, group_id: groupId() };
    if (to.length) args.to = to;
    if (replyTo) args.reply_to = replyTo;
    if (objectId) {
      args.kind = 'file';
      args.ref = objectId;
      args.body = utf8ToBase64(JSON.stringify({ name: name || 'file' }));
    } else {
      args.body = utf8ToBase64(text);
    }
    await mcpCall('group_append', args);
  }

  async function sendText() {
    const text = (textEl.value || '').trim();
    if (!text) return;
    try {
      if (sel.startsWith('g:')) {
        await sendGroupAppend({ text });
        textEl.value = '';
        replyDraft = null;
        paintReplyBar();
        touch(sel, Date.now());
        await refreshThreadTail();
        return;
      }
      if (sel.startsWith('c:')) {
        await api(`/agents/${encodeURIComponent(viewAid)}/chat/send`, {
          method: 'POST',
          body: JSON.stringify({ peer: chatPeer(), text }),
        });
        textEl.value = '';
        touch(sel, Date.now());
        await loadChat(gen);
      }
    } catch (e) {
      toast(e.message || String(e), 'err');
    }
  }

  async function sendFile(file) {
    if (!file) return;
    const fileBtn = composerEl.querySelector('[data-file]');
    const sendBtn = composerEl.querySelector('[data-send]');
    const prev = fileBtn ? fileBtn.textContent : '';
    if (fileBtn) { fileBtn.disabled = true; fileBtn.textContent = t('gb.uploading'); }
    if (sendBtn) sendBtn.disabled = true;
    try {
      const up = await api(`/agents/${encodeURIComponent(viewAid)}/cas?name=${encodeURIComponent(file.name)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: file,
      });
      if (sel.startsWith('g:')) {
        await sendGroupAppend({ objectId: up.object_id, name: file.name });
        replyDraft = null;
        paintReplyBar();
        touch(sel, Date.now());
        await refreshThreadTail();
        return;
      }
      if (sel.startsWith('c:')) {
        await api(`/agents/${encodeURIComponent(viewAid)}/chat/send`, {
          method: 'POST',
          body: JSON.stringify({ peer: chatPeer(), object_id: up.object_id, name: file.name }),
        });
        touch(sel, Date.now());
        await loadChat(gen);
      }
    } catch (e) {
      const msg = e.message || String(e);
      toast(/failed to fetch/i.test(msg) ? t('gb.upload_failed') : msg, 'err');
    } finally {
      fileEl.value = '';
      if (fileBtn) { fileBtn.disabled = false; fileBtn.textContent = prev; }
      if (sendBtn) sendBtn.disabled = false;
    }
  }
}

function seenKey(aid) {
  return `a2al.gb.seen.${aid}`;
}

function loadInviteStore(aid) {
  let v = {};
  try {
    const raw = localStorage.getItem(`a2al.gb.invites.${aid}`)
      || sessionStorage.getItem(`a2al.gb.out.${aid}`)
      || '';
    const p = JSON.parse(raw);
    if (p && typeof p === 'object') v = p;
  } catch { /* empty */ }
  for (const rec of Object.values(v)) {
    if (rec.status === 'sending') {
      rec.status = 'error';
    }
    rec.sending = false;
    if (!rec.status) rec.status = rec.error ? 'error' : 'waiting';
  }
  return v;
}

function loadIgnored(aid) {
  try {
    const p = JSON.parse(localStorage.getItem(`a2al.gb.ignore.${aid}`) || '[]');
    return new Set(Array.isArray(p) ? p.filter((x) => typeof x === 'string') : []);
  } catch {
    return new Set();
  }
}

function loadJSON(key, fallback) {
  try {
    const v = JSON.parse(sessionStorage.getItem(key) || '');
    return v && typeof v === 'object' ? v : fallback;
  } catch {
    return fallback;
  }
}

function displayName(aid) {
  return aliasOf(aid) || shortAid(aid);
}

function nameHTML(aid) {
  const al = aliasOf(aid);
  return al ? esc(al) : shortAidHTML(aid);
}

function initial(name) {
  const s = String(name || '').trim();
  return s ? [...s][0] : '?';
}

function dayKey(ts) {
  const d = new Date(Number(ts) || 0);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function dateLabel(ts, t) {
  const d = new Date(Number(ts) || 0);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const that = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diff = (today - that) / 86400000;
  if (diff === 0) return t('group.bubble.today');
  if (diff === 1) return t('group.bubble.yesterday');
  const loc = getLocale() === 'zh-CN' ? 'zh-CN' : getLocale() === 'ja' ? 'ja' : 'en';
  return d.toLocaleDateString(loc, { year: 'numeric', month: 'short', day: 'numeric' });
}

function clock(ts) {
  const d = new Date(Number(ts) || 0);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
}

function decodeBody(entry) {
  const b = entry.body;
  if (b && typeof b === 'object' && b.target_aid) return { target: b.target_aid };
  if (typeof b === 'string' && b) {
    const text = base64ToUtf8(b);
    return { text };
  }
  return {};
}

function isFileEntry(entry) {
  if ((entry.kind || '') === 'file') return true;
  if (!entry.ref) return false;
  const { text } = decodeBody(entry);
  if (!text) return false;
  try {
    const j = JSON.parse(text);
    return !!(j && typeof j === 'object' && !Array.isArray(j) && ('name' in j || 'size' in j));
  } catch {
    return false;
  }
}

function fileMeta(entry) {
  const { text } = decodeBody(entry);
  let name = 'file';
  let size = 0;
  if (text) {
    try {
      const j = JSON.parse(text);
      if (j && typeof j === 'object') {
        if (j.name) name = String(j.name);
        if (j.size != null) size = Number(j.size) || 0;
      }
    } catch { /* keep fallback */ }
  }
  return { name, size };
}

function isSys(entry) {
  const kind = entry.kind || 'msg';
  if (SYS_KINDS.has(kind)) return true;
  if (isFileEntry(entry)) return false;
  const body = decodeBody(entry);
  if (entry.ref && !body.text) return true;
  return false;
}

function renderThread(entries, t, mine) {
  const byId = new Map(entries.map((e) => [e.id, e]));
  let html = '';
  let prev = null;
  for (const e of entries) {
    const dk = dayKey(e.ts);
    if (!prev || dayKey(prev.ts) !== dk) {
      html += `<div class="gb-date">${esc(dateLabel(e.ts, t))}</div>`;
      prev = null;
    }
    if (isSys(e)) {
      html += renderSys(e, t);
      prev = e;
      continue;
    }
    const clustered = prev && !isSys(prev)
      && prev.author === e.author
      && (Number(e.ts) - Number(prev.ts)) < CLUSTER_MS
      && dayKey(prev.ts) === dk;
    html += renderBubble(e, t, mine, clustered, byId);
    prev = e;
  }
  return html;
}

function renderBubble(e, t, mine, clustered, byId) {
  const own = e.author === mine;
  const name = displayName(e.author);
  let inner = '';
  if (isFileEntry(e) && e.ref) {
    const f = fileMeta(e);
    inner = `<a href="#" data-cas-author="${esc(e.author)}" data-cas-ref="${esc(e.ref)}" data-cas-name="${esc(f.name)}">${esc(f.name)}</a>`;
    if (f.size) inner += `<div class="gb-to">${esc(String(f.size))} B</div>`;
  } else {
    const { text } = decodeBody(e);
    inner = colorizeAtShortAids(text || t('group.bubble.undecodable'), [e.author, ...(e.to || [])]);
  }
  let quote = '';
  if (e.reply_to && byId?.has(e.reply_to)) {
    const src = byId.get(e.reply_to);
    const q = decodeBody(src);
    quote = `<div class="gb-quote">${q.text
      ? colorizeAtShortAids(q.text, [src.author, ...(src.to || [])])
      : nameHTML(src.author)}</div>`;
  }
  const mentions = (e.to || []).map((a) => {
    const al = aliasOf(a);
    return al ? `@${esc(al)}` : `@${shortAidHTML(a)}`;
  }).join(' ');
  const copyBtn = `<button type="button" class="gb-act" data-copy-aid="${esc(e.author)}" title="${esc(t('common.copy'))}">⧉</button>`;
  const atBtn = `<button type="button" class="gb-act" data-mention="${esc(e.author)}" title="${esc(t('gb.mention'))}">@</button>`;
  const quoteBtn = `<button type="button" class="gb-act" data-quote="${esc(e.id)}" title="${esc(t('gb.quote'))}">↩</button>`;
  const head = clustered ? '' : `
    <div class="gb-meta">
      <span class="gb-name">${nameHTML(e.author)}</span>
      ${copyBtn}${atBtn}${quoteBtn}
      <span class="gb-time">${esc(clock(e.ts))}</span>
    </div>`;
  const av = clustered
    ? '<div class="gb-av gb-av-sp"></div>'
    : `<button type="button" class="gb-av" style="${aidAvStyle(e.author)}" data-mention="${esc(e.author)}" title="${esc(t('gb.mention'))}">${esc(initial(name))}</button>`;
  return `<div class="gb-row${own ? ' own' : ''}${clustered ? ' clustered' : ''}">
    ${own ? '' : av}
    <div class="gb-col">
      ${head}
      <div class="gb-bubble-wrap">
        <div class="gb-bubble">${quote}${inner}${mentions ? `<div class="gb-to">${esc(mentions)}</div>` : ''}</div>
        ${clustered ? quoteBtn : ''}
      </div>
    </div>
    ${own ? av : ''}
  </div>`;
}

function utf8ToBase64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin);
}

function renderSys(e, t) {
  const who = displayName(e.author);
  const { text, target } = decodeBody(e);
  const tgt = target ? displayName(target) : '';
  const kind = e.kind || '';
  let msg = '';
  const vars = { who, target: tgt, text: text || '' };
  switch (kind) {
    case 'invite': msg = t('group.bubble.sys.invite', vars); break;
    case 'revoke': msg = t('group.bubble.sys.revoke', vars); break;
    case 'grant_admin': msg = t('group.bubble.sys.grant_admin', vars); break;
    case 'revoke_admin': msg = t('group.bubble.sys.revoke_admin', vars); break;
    case 'propose_invite': msg = t('group.bubble.sys.propose_invite', vars); break;
    case 'retract': msg = t('group.bubble.sys.retract', vars); break;
    case 'meta':
      msg = text
        ? t('group.bubble.sys.meta', vars)
        : t('group.bubble.sys.generic', vars);
      break;
    default:
      if (e.ref) msg = t('group.bubble.sys.file', vars);
      else msg = t('group.bubble.sys.generic', vars);
  }
  return `<div class="gb-sys">${esc(msg)}</div>`;
}

function chatRequestErr(msg, t) {
  const s = String(msg || '');
  if (/cannot message this identity/i.test(s)) return t('chat.request.self');
  if (/bad AID/i.test(s)) return t('chat.request.bad_peer');
  if (/this peer is blocked/i.test(s)) return t('chat.request.blocked');
  if (/already requested or friends/i.test(s)) return t('chat.request.already');
  if (/pending invite list is full|retry_later|pow_required/i.test(s)) return t('chat.request.busy');
  if (/signaling not delivered: denied|: denied\b/i.test(s)) return t('chat.request.denied');
  if (/resolve failed|no live envelope|quic connect failed/i.test(s)) return t('chat.request.offline');
  if (/signaling not delivered/i.test(s)) return t('chat.request.failed');
  if (/failed to fetch|networkerror|aborterror|load failed/i.test(s)) return t('chat.request.failed');
  return t('chat.request.failed');
}

function chatActErr(msg, t) {
  const s = String(msg || '');
  if (/no pending invite/i.test(s)) return t('chat.act.not_pending');
  if (/not_friends|not on this identity's chat list/i.test(s)) return t('chat.act.not_friends');
  return chatRequestErr(s, t);
}

function chatEntryStale(prev, next) {
  if (prev.status !== next.status) return true;
  return JSON.stringify(prev.fetched || []) !== JSON.stringify(next.fetched || []);
}

function chatOutStatus(e, t, peer) {
  if (e.dir !== 'out') return '';
  if (e.kind === 'file') {
    if (e.status === 'local') return t('chat.status.local');
    const fetched = Array.isArray(e.fetched) ? e.fetched : [];
    if (peer && fetched.includes(peer)) return t('chat.status.delivered');
    return t('chat.status.wait_peer');
  }
  return e.status === 'local' ? t('chat.status.local') : '';
}

function renderChatThread(entries, t, mine, peer) {
  let html = '';
  let prev = null;
  for (const e of entries) {
    const dk = dayKey(e.ts);
    if (!prev || dayKey(prev.ts) !== dk) {
      html += `<div class="gb-date">${esc(dateLabel(e.ts, t))}</div>`;
      prev = null;
    }
    const own = e.dir === 'out';
    const name = displayName(own ? mine : e.author);
    const clustered = prev && prev.dir === e.dir
      && (Number(e.ts) - Number(prev.ts)) < CLUSTER_MS
      && dayKey(prev.ts) === dk;
    const head = clustered ? '' : `
      <div class="gb-meta">
        <span class="gb-name">${nameHTML(own ? mine : e.author)}</span>
        <span class="gb-time">${esc(clock(e.ts))}</span>
      </div>`;
    const avAid = own ? mine : e.author;
    const av = clustered
      ? '<div class="gb-av gb-av-sp"></div>'
      : `<div class="gb-av" style="${aidAvStyle(avAid)}">${esc(initial(name))}</div>`;
    let body = colorizeAtShortAids(e.body || '', [mine, e.author, peer]);
    if (e.kind === 'file' && e.ref) {
      const label = e.name || e.ref;
      body = `<a href="#" data-cas-author="${esc(e.author || mine)}" data-cas-ref="${esc(e.ref)}" data-cas-name="${esc(label)}">${esc(label)}</a>`;
      if (e.size) body += `<div class="gb-to">${esc(String(e.size))} B</div>`;
    }
    const stText = chatOutStatus(e, t, peer);
    const st = stText ? `<div class="gb-to">${esc(stText)}</div>` : '';
    html += `<div class="gb-row${own ? ' own' : ''}${clustered ? ' clustered' : ''}">
      ${own ? '' : av}
      <div class="gb-col">
        ${head}
        <div class="gb-bubble">${body}${st}</div>
      </div>
      ${own ? av : ''}
    </div>`;
    prev = e;
  }
  return html;
}
