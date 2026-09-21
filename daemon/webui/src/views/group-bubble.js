import { esc, shortAid, aliasOf, base64ToUtf8 } from '../util.js';
import { getLocale } from '../i18n.js';

const POLL_MS = 1000;
const PAGE = 50;
const CLUSTER_MS = 2 * 60 * 1000;
const BURST_PAGES = 4;
const SYS_KINDS = new Set([
  'invite', 'revoke', 'grant_admin', 'revoke_admin', 'propose_invite',
  'retract', 'meta', 'budget', 'spend', 'snapshot',
]);

/**
 * Observe viewAid's local group replica. selfAid is reserved: when set, "mine"
 * bubbles use it (human joined). Step 1 leaves it null.
 */
export function openGroupBubble(ctx, agent) {
  const { t, api, openModal } = ctx;
  const viewAid = agent.aid;
  const selfAid = null;

  let groups = [];
  let groupId = '';
  let entries = [];
  let oldestSeq = 0;
  let headSeq = 0;
  let timer = null;
  let chatTimer = null;
  let chatES = null;
  let stopped = false;
  let loadingOlder = false;
  let gen = 0;
  let threadEl = null;
  let roomsEl = null;
  let titleEl = null;
  let tab = 'room';
  let contacts = { friends: [], out_pending: [], in_pending: [] };
  let chatPeer = '';
  let chatRel = '';
  let chatEntries = [];
  let chatScanned = 0;
  let chatThreadEl = null;
  let chatListEl = null;
  let chatHeadEl = null;
  let chatNameEl = null;
  let chatSubEl = null;
  let chatRemoveBtn = null;
  let chatWithdrawBtn = null;
  let chatComposerEl = null;
  let chatTextEl = null;
  let chatListSig = '';

  function mineAid() {
    return selfAid || viewAid;
  }

  function whoAmI() {
    return aliasOf(viewAid) || shortAid(viewAid);
  }

  openModal({
    title: t('group.bubble.action'),
    cls: 'modal modal-chat',
    body: `
      <div class="gb">
        <div class="gb-tabs">
          <button type="button" class="gb-tab on" data-tab="room">${esc(t('chat.tab.room'))}</button>
          <button type="button" class="gb-tab" data-tab="chat">${esc(t('chat.tab.chat'))}</button>
        </div>
        <div class="gb-pane" data-pane="room">
          <div class="gb-rooms" hidden></div>
          <div class="gb-thread" id="gb-thread"></div>
          <div class="gb-composer" data-slot="composer" hidden>
            <textarea rows="1" disabled></textarea>
            <button type="button" class="btn btn-primary btn-sm" disabled></button>
          </div>
          <button type="button" data-slot="join" hidden></button>
        </div>
        <div class="gb-pane" data-pane="chat" hidden>
          <div class="gb-chat">
            <div class="gb-list" id="gb-chat-list"></div>
            <div class="gb-chat-main">
              <div class="gb-chat-head" id="gb-chat-head" hidden>
                <div class="gb-chat-who">
                  <div class="gb-chat-name" id="gb-chat-name"></div>
                  <div class="gb-chat-sub" id="gb-chat-sub"></div>
                </div>
                <button type="button" class="btn btn-ghost btn-sm" data-withdraw hidden>${esc(t('chat.withdraw'))}</button>
                <button type="button" class="btn btn-ghost btn-sm" data-remove hidden>${esc(t('chat.remove'))}</button>
              </div>
              <div class="gb-thread" id="gb-chat-thread"></div>
              <div class="gb-composer" id="gb-chat-composer" hidden>
                <textarea rows="1" id="gb-chat-text" placeholder="${esc(t('chat.placeholder'))}"></textarea>
                <input type="file" id="gb-chat-file" hidden />
                <button type="button" class="btn btn-ghost btn-sm" data-file>${esc(t('chat.file'))}</button>
                <button type="button" class="btn btn-primary btn-sm" data-send>${esc(t('chat.send'))}</button>
              </div>
            </div>
          </div>
        </div>
      </div>`,
    onClose() {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (chatTimer) clearTimeout(chatTimer);
      if (chatES) { chatES.close(); chatES = null; }
      document.removeEventListener('visibilitychange', onVis);
    },
    onMount(modal) {
      titleEl = modal.querySelector('.modal-h span');
      threadEl = modal.querySelector('#gb-thread');
      roomsEl = modal.querySelector('.gb-rooms');
      chatThreadEl = modal.querySelector('#gb-chat-thread');
      chatListEl = modal.querySelector('#gb-chat-list');
      chatHeadEl = modal.querySelector('#gb-chat-head');
      chatNameEl = modal.querySelector('#gb-chat-name');
      chatSubEl = modal.querySelector('#gb-chat-sub');
      chatRemoveBtn = modal.querySelector('[data-remove]');
      chatWithdrawBtn = modal.querySelector('[data-withdraw]');
      chatComposerEl = modal.querySelector('#gb-chat-composer');
      chatTextEl = modal.querySelector('#gb-chat-text');
      threadEl.addEventListener('scroll', onScroll);
      document.addEventListener('visibilitychange', onVis);
      modal.querySelectorAll('.gb-tab').forEach((btn) => {
        btn.onclick = () => setTab(btn.dataset.tab);
      });
      chatRemoveBtn.onclick = () => chatAct('remove');
      chatWithdrawBtn.onclick = () => chatAct('refuse');
      chatComposerEl.querySelector('[data-send]').onclick = () => chatSend();
      chatComposerEl.querySelector('[data-file]').onclick = () => modal.querySelector('#gb-chat-file').click();
      modal.querySelector('#gb-chat-file').onchange = (ev) => chatSendFile(ev.target.files && ev.target.files[0]);
      chatTextEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          chatSend();
        }
      });
      boot();
      startChatDoorbell();
    },
  });

  function setTab(next) {
    tab = next;
    const modal = chatThreadEl.closest('.modal');
    modal.querySelectorAll('.gb-tab').forEach((b) => b.classList.toggle('on', b.dataset.tab === tab));
    modal.querySelectorAll('.gb-pane').forEach((p) => { p.hidden = p.dataset.pane !== tab; });
    if (tab === 'chat') {
      setTitle(`${t('chat.tab.chat')} · ${whoAmI()}`);
      chatTick();
    } else {
      setTitle(groups.length ? roomLabel(groups.find((g) => g.group_id === groupId) || groups[0]) : t('group.bubble.action'));
      schedule();
    }
  }

  function onVis() {
    if (stopped) return;
    if (document.hidden) {
      if (timer) { clearTimeout(timer); timer = null; }
      if (chatTimer) { clearTimeout(chatTimer); chatTimer = null; }
      return;
    }
    if (tab === 'chat') chatTick();
    else tick();
    scheduleContacts();
  }

  function schedule() {
    if (stopped || document.hidden || tab !== 'room') return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(tick, POLL_MS);
  }

  function scheduleChat() {
    scheduleContacts();
  }

  function startChatDoorbell() {
    refreshContacts();
    scheduleContacts();
    try {
      const es = new EventSource(`/agents/${encodeURIComponent(viewAid)}/events?types=chat.invites,chat.unread,chat.received`);
      chatES = es;
      const kick = () => {
        refreshContacts();
        if (tab === 'chat') refreshThread();
      };
      es.addEventListener('chat.invites', kick);
      es.addEventListener('chat.unread', kick);
      es.addEventListener('chat.received', kick);
    } catch (_) { /* poll remains */ }
  }

  function paintChatBadge() {
    const modal = chatThreadEl && chatThreadEl.closest('.modal');
    if (!modal) return;
    const btn = modal.querySelector('.gb-tab[data-tab="chat"]');
    if (!btn) return;
    const n = (Number(contacts.invites) || 0) + (Number(contacts.unread) || 0);
    let dot = btn.querySelector('.gb-dot');
    if (!n) {
      if (dot) dot.remove();
      return;
    }
    if (!dot) {
      dot = document.createElement('span');
      dot.className = 'gb-dot';
      btn.appendChild(dot);
    }
    dot.textContent = n > 9 ? '9+' : String(n);
  }

  function scheduleContacts() {
    if (stopped || document.hidden) return;
    if (chatTimer) clearTimeout(chatTimer);
    chatTimer = setTimeout(async () => {
      await refreshContacts();
      if (tab === 'chat') await refreshThread();
      scheduleContacts();
    }, POLL_MS);
  }

  async function refreshContacts() {
    if (stopped) return;
    try {
      contacts = await api(`/agents/${encodeURIComponent(viewAid)}/chat/contacts`);
      paintChatBadge();
      if (tab !== 'chat') return;
      if (chatPeer) {
        const rel = listedRel(chatPeer);
        if (!rel) {
          chatPeer = '';
          chatRel = '';
          chatEntries = [];
        } else {
          chatRel = rel;
        }
      }
      renderChatList();
      updateChatChrome();
      if (chatRel === 'in_pending') paintChat();
    } catch (_) { /* next */ }
  }

  async function refreshThread() {
    if (stopped || tab !== 'chat' || !chatPeer) return;
    try {
      const q = `after_seq=${encodeURIComponent(String(chatScanned))}&limit=${PAGE}`;
      const page = await api(`/agents/${encodeURIComponent(viewAid)}/chat/peers/${encodeURIComponent(chatPeer)}?${q}`);
      mergeChat(page.entries || []);
      const next = Number(page.scanned_to);
      if (Number.isFinite(next)) chatScanned = next;
      paintChat();
      if (chatRel === 'friends') await markChatRead(chatScanned);
    } catch (_) { /* next */ }
  }

  async function markChatRead(scanned) {
    if (!chatPeer || chatRel !== 'friends') return;
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/mark-read`, {
        method: 'POST',
        body: JSON.stringify({ peer: chatPeer, scanned_to: scanned || 0 }),
      });
      await refreshContacts();
    } catch (_) { /* next */ }
  }

  async function chatTick() {
    await refreshContacts();
    await refreshThread();
    scheduleContacts();
  }

  function renderChatList() {
    const sections = [
      ['friends', t('chat.section.friends')],
      ['out_pending', t('chat.section.out_pending')],
      ['in_pending', t('chat.section.in_pending')],
    ];
    const sigParts = [chatPeer];
    let html = '';
    for (const [key, label] of sections) {
      const items = contacts[key] || [];
      if (!items.length) continue;
      html += `<div class="gb-list-h">${esc(label)}</div>`;
      for (const it of items) {
        const peer = it.peer || '';
        const on = peer === chatPeer ? ' on' : '';
        const unread = Number(it.unread_count) || 0;
        const ping = key === 'in_pending' || unread > 0;
        const mark = ping ? `<span class="gb-dot">${unread > 9 ? '9+' : (unread || '')}</span>` : '';
        html += `<button type="button" class="gb-list-item${on}" data-peer="${esc(peer)}" data-rel="${esc(key)}"><span>${esc(displayName(peer))}</span>${mark}</button>`;
        sigParts.push(`${key}:${peer}:${unread}`);
      }
    }
    if (!html) html = `<div class="gb-empty muted">${esc(t('chat.empty.contacts'))}</div>`;
    const sig = sigParts.join('|');
    if (sig === chatListSig) return;
    chatListSig = sig;
    chatListEl.innerHTML = html;
    chatListEl.querySelectorAll('[data-peer]').forEach((btn) => {
      btn.onclick = () => openChatPeer(btn.dataset.peer, btn.dataset.rel);
    });
  }

  async function openChatPeer(peer, rel) {
    chatPeer = peer;
    chatRel = rel;
    chatEntries = [];
    chatScanned = 0;
    renderChatList();
    updateChatChrome();
    try {
      const page = await api(`/agents/${encodeURIComponent(viewAid)}/chat/peers/${encodeURIComponent(peer)}?after_seq=0&limit=${PAGE}`);
      mergeChat(page.entries || []);
      const next = Number(page.scanned_to);
      chatScanned = Number.isFinite(next) ? next : 0;
    } catch (_) { /* empty */ }
    paintChat('bottom');
    if (rel === 'friends') markChatRead(chatScanned);
  }

  function listedRel(peer) {
    for (const key of ['friends', 'out_pending', 'in_pending']) {
      if ((contacts[key] || []).some((it) => it.peer === peer)) return key;
    }
    return '';
  }

  function contactNote(peer) {
    const it = (contacts.in_pending || []).find((x) => x.peer === peer);
    return (it && it.note) || '';
  }

  function updateChatChrome() {
    if (!chatPeer) {
      chatHeadEl.hidden = true;
      chatComposerEl.hidden = true;
      return;
    }
    chatHeadEl.hidden = false;
    chatNameEl.textContent = displayName(chatPeer);
    const pendingOut = chatRel === 'out_pending';
    const pendingIn = chatRel === 'in_pending';
    chatSubEl.textContent = pendingOut ? t('chat.head.wait') : '';
    chatSubEl.hidden = !pendingOut;
    chatRemoveBtn.hidden = chatRel !== 'friends';
    chatWithdrawBtn.hidden = !pendingOut;
    chatComposerEl.hidden = pendingIn;
  }

  function mergeChat(items) {
    const seen = new Set(chatEntries.map((e) => `${e.dir}:${e.seq}`));
    for (const e of items) {
      const k = `${e.dir}:${e.seq}`;
      if (seen.has(k)) continue;
      seen.add(k);
      chatEntries.push(e);
    }
    chatEntries.sort((a, b) => (a.idx || 0) - (b.idx || 0));
  }

  function paintChat(mode) {
    if (!chatPeer) {
      chatThreadEl.innerHTML = `<div class="gb-empty muted">${esc(t('chat.empty.thread'))}</div>`;
      return;
    }
    if (chatRel === 'in_pending') {
      const who = displayName(chatPeer);
      const note = contactNote(chatPeer);
      chatThreadEl.innerHTML = `<div class="gb-invite">
        <div class="gb-invite-title">${esc(t('chat.invite.title', { who }))}</div>
        ${note ? `<div class="gb-invite-note">${esc(note)}</div>` : ''}
        <div class="gb-invite-actions">
          <button type="button" class="btn btn-ghost" data-refuse>${esc(t('chat.refuse'))}</button>
          <button type="button" class="btn btn-primary" data-accept>${esc(t('chat.accept'))}</button>
        </div>
      </div>`;
      chatThreadEl.querySelector('[data-accept]').onclick = () => chatAct('accept');
      chatThreadEl.querySelector('[data-refuse]').onclick = () => chatAct('refuse');
      return;
    }
    if (!chatEntries.length) {
      chatThreadEl.innerHTML = `<div class="gb-empty muted">${esc(t('group.bubble.no_messages'))}</div>`;
      return;
    }
    const nearBottom = chatThreadEl.scrollHeight - chatThreadEl.scrollTop - chatThreadEl.clientHeight < 56;
    chatThreadEl.innerHTML = renderChatThread(chatEntries, t, viewAid);
    if (mode === 'bottom' || (mode === 'tail' && nearBottom) || mode === undefined) {
      if (mode === 'bottom' || nearBottom || mode === undefined) chatThreadEl.scrollTop = chatThreadEl.scrollHeight;
    }
  }

  async function chatAct(kind) {
    if (!chatPeer) return;
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/${kind}`, {
        method: 'POST',
        body: JSON.stringify({ peer: chatPeer }),
      });
      chatRel = kind === 'accept' ? 'friends' : '';
      if (kind === 'refuse' || kind === 'remove') {
        chatPeer = '';
        chatEntries = [];
      }
      await chatTick();
    } catch (e) {
      chatThreadEl.innerHTML = `<div class="gb-empty" style="color:var(--error)">${esc(e.message || String(e))}</div>`;
    }
  }

  async function chatSend() {
    const text = (chatTextEl.value || '').trim();
    if (!text || !chatPeer) return;
    try {
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/send`, {
        method: 'POST',
        body: JSON.stringify({ peer: chatPeer, text }),
      });
      chatTextEl.value = '';
      chatScanned = 0;
      chatEntries = [];
      await chatTick();
    } catch (e) {
      chatSubEl.hidden = false;
      chatSubEl.textContent = e.message || String(e);
    }
  }

  async function chatSendFile(file) {
    if (!file || !chatPeer) return;
    try {
      const up = await api(`/agents/${encodeURIComponent(viewAid)}/cas?name=${encodeURIComponent(file.name)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: file,
      });
      await api(`/agents/${encodeURIComponent(viewAid)}/chat/send`, {
        method: 'POST',
        body: JSON.stringify({ peer: chatPeer, object_id: up.object_id, text: file.name }),
      });
      chatScanned = 0;
      chatEntries = [];
      await chatTick();
    } catch (e) {
      chatSubEl.hidden = false;
      chatSubEl.textContent = e.message || String(e);
    }
  }

  async function boot() {
    if (stopped) return;
    threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('common.loading'))}</div>`;
    try {
      const r = await api(`/agents/${encodeURIComponent(viewAid)}/groups`);
      if (stopped) return;
      groups = (r.groups || []).slice().sort((a, b) =>
        (b.last_activity_ms || 0) - (a.last_activity_ms || 0));
    } catch (e) {
      if (stopped) return;
      threadEl.innerHTML = `<div class="gb-empty" style="color:var(--error)">${esc(t('group.bubble.load_error'))}</div>`;
      return;
    }
    if (!groups.length) {
      setTitle(t('group.bubble.action'));
      threadEl.innerHTML = `<div class="gb-empty">
        <div>${esc(t('group.bubble.empty'))}</div>
        <div class="muted" style="margin-top:.35rem">${esc(t('group.bubble.empty_hint'))}</div>
      </div>`;
      return;
    }
    renderRoomPicker();
    await loadGroup(groups[0].group_id);
    if (!stopped) schedule();
  }

  function renderRoomPicker() {
    if (groups.length < 2) {
      roomsEl.hidden = true;
      roomsEl.innerHTML = '';
      return;
    }
    roomsEl.hidden = false;
    roomsEl.innerHTML = `<select class="gb-select">${
      groups.map((g) => `<option value="${esc(g.group_id)}">${esc(roomLabel(g))}</option>`).join('')
    }</select>`;
    const sel = roomsEl.querySelector('select');
    sel.value = groupId || groups[0].group_id;
    sel.onchange = () => loadGroup(sel.value);
  }

  async function loadGroup(id) {
    const g = ++gen;
    groupId = id;
    entries = [];
    oldestSeq = 0;
    headSeq = 0;
    const meta = groups.find((x) => x.group_id === id);
    if (tab === 'room') setTitle(roomLabel(meta || { group_id: id, title: '' }));
    if (roomsEl.querySelector('select')) roomsEl.querySelector('select').value = id;
    threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('common.loading'))}</div>`;
    try {
      const head = await api(`/agents/${encodeURIComponent(viewAid)}/groups/${id}`);
      if (stopped || g !== gen) return;
      const maxSeq = Number(head.max_seq) || 0;
      const after = Math.max(0, maxSeq - PAGE);
      const page = await fetchEntries(after, PAGE);
      if (stopped || g !== gen) return;
      mergeEntries(page.entries || []);
      headSeq = Number(page.scanned_to_seq) || maxSeq;
      paint('bottom');
    } catch (_) {
      if (stopped || g !== gen) return;
      threadEl.innerHTML = `<div class="gb-empty" style="color:var(--error)">${esc(t('group.bubble.load_error'))}</div>`;
    }
  }

  async function tick() {
    if (stopped || document.hidden || !groupId || tab !== 'room') return;
    const g = gen;
    try {
      const head = await api(`/agents/${encodeURIComponent(viewAid)}/groups/${groupId}`);
      if (g !== gen) return;
      let maxSeq = Number(head.max_seq) || 0;
      let pages = 0;
      while (maxSeq > headSeq && pages < BURST_PAGES) {
        const page = await fetchEntries(headSeq, PAGE);
        if (g !== gen) return;
        mergeEntries(page.entries || []);
        const next = Number(page.scanned_to_seq);
        headSeq = Number.isFinite(next) ? next : maxSeq;
        pages++;
        if (!page.has_more) break;
      }
      if (pages) paint('tail');
    } catch (_) { /* next tick */ }
    schedule();
  }

  async function fetchEntries(afterSeq, limit) {
    const q = `after_seq=${encodeURIComponent(String(afterSeq))}&limit=${limit}`;
    return api(`/agents/${encodeURIComponent(viewAid)}/groups/${groupId}/entries?${q}`);
  }

  function mergeEntries(items) {
    const seen = new Set(entries.map((e) => e.id));
    for (const e of items) {
      if (!e?.id || seen.has(e.id)) continue;
      seen.add(e.id);
      entries.push(e);
    }
    entries.sort((a, b) => (a.seq || 0) - (b.seq || 0));
    if (entries.length) {
      oldestSeq = Number(entries[0].seq) || oldestSeq;
    }
  }

  async function loadOlder() {
    if (loadingOlder || oldestSeq <= 1) return;
    loadingOlder = true;
    const end = oldestSeq - 1;
    const after = Math.max(0, end - PAGE);
    const limit = end - after;
    const prevH = threadEl.scrollHeight;
    const prevT = threadEl.scrollTop;
    try {
      const page = await fetchEntries(after, limit);
      const n = entries.length;
      mergeEntries(page.entries || []);
      if (entries.length > n) {
        paint();
        threadEl.scrollTop = prevT + (threadEl.scrollHeight - prevH);
      }
    } catch (_) { /* stop */ }
    loadingOlder = false;
  }

  function onScroll() {
    if (threadEl.scrollTop < 24) loadOlder();
  }

  function setTitle(s) {
    if (titleEl) titleEl.textContent = s;
  }

  function roomLabel(g) {
    const title = (g.title || '').trim();
    const who = aliasOf(viewAid) || shortAid(viewAid);
    return title ? `${who} · ${title}` : `${who} · ${String(g.group_id || '').slice(0, 8)}`;
  }

  function paint(mode) {
    const nearBottom = threadEl.scrollHeight - threadEl.scrollTop - threadEl.clientHeight < 56;
    if (!entries.length) {
      threadEl.innerHTML = `<div class="gb-empty muted">${esc(t('group.bubble.no_messages'))}</div>`;
      return;
    }
    threadEl.innerHTML = renderThread(entries, t, mineAid());
    if (mode === 'bottom' || (mode === 'tail' && nearBottom)) {
      threadEl.scrollTop = threadEl.scrollHeight;
    }
  }
}

function displayName(aid) {
  return aliasOf(aid) || shortAid(aid);
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

function isSys(entry) {
  const kind = entry.kind || 'msg';
  if (SYS_KINDS.has(kind)) return true;
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
  const { text } = decodeBody(e);
  const body = text || t('group.bubble.undecodable');
  let quote = '';
  if (e.reply_to && byId?.has(e.reply_to)) {
    const src = byId.get(e.reply_to);
    const q = decodeBody(src);
    quote = `<div class="gb-quote">${esc(q.text || displayName(src.author))}</div>`;
  }
  const mentions = (e.to || []).map((a) => `@${displayName(a)}`).join(' ');
  const head = clustered ? '' : `
    <div class="gb-meta">
      <span class="gb-name">${esc(name)}</span>
      <span class="gb-time">${esc(clock(e.ts))}</span>
    </div>`;
  const av = clustered ? '<div class="gb-av gb-av-sp"></div>' : `<div class="gb-av">${esc(initial(name))}</div>`;
  return `<div class="gb-row${own ? ' own' : ''}${clustered ? ' clustered' : ''}">
    ${own ? '' : av}
    <div class="gb-col">
      ${head}
      <div class="gb-bubble">${quote}${esc(body)}${mentions ? `<div class="gb-to">${esc(mentions)}</div>` : ''}</div>
    </div>
    ${own ? av : ''}
  </div>`;
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

function renderChatThread(entries, t, mine) {
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
        <span class="gb-name">${esc(name)}</span>
        <span class="gb-time">${esc(clock(e.ts))}</span>
      </div>`;
    const av = clustered ? '<div class="gb-av gb-av-sp"></div>' : `<div class="gb-av">${esc(initial(name))}</div>`;
    let body = esc(e.body || '');
    if (e.kind === 'file' && e.ref) {
      const href = `/aid/${encodeURIComponent(e.author || mine)}/cas/${encodeURIComponent(e.ref)}`;
      body = `<a href="${esc(href)}" download="${esc(e.name || e.ref)}">${esc(e.name || e.ref)}</a>`;
      if (e.size) body += `<div class="gb-to">${esc(String(e.size))} B</div>`;
    }
    const st = e.status === 'local' ? `<div class="gb-to">${esc(t('chat.status.local'))}</div>` : '';
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
