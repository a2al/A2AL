import { setLoading } from './util.js';

function namedRows(items, emptyText, esc) {
  const named = (items || []).filter((e) => e.aid);
  if (!named.length) {
    return `<p class="muted ra-empty">${esc(emptyText)}</p>`;
  }
  return named.map((e) => `
    <div class="acl-row" data-id="${esc(e.id)}">
      <code class="mono">${esc(e.aid)}</code>
      <button type="button" class="btn btn-ghost btn-xs" data-del>${esc('×')}</button>
    </div>`).join('');
}

function joinEntry(items) {
  return (items || []).find((e) => !e.aid && (e.secret_set || e.secret)) || null;
}

function eventLine(ev, esc, t, relTime) {
  if (!ev || !ev.aid) {
    return `<span class="muted">${esc(t('node.ra.event_none'))}</span>`;
  }
  const when = ev.time ? relTime(ev.time) : '—';
  const ip = ev.ip || '—';
  return `<code class="mono">${esc(ev.aid)}</code><span class="muted"> · ${esc(when)} · ${esc(ip)}</span>`;
}

export function lampHTML(on) {
  return `<span class="ra-lamp${on ? ' on' : ''}" aria-hidden="true"></span>`;
}

export function mountRemoteAdmin(mount, ctx, initial) {
  const { t, api, toast, esc, relTime } = ctx;
  let state = initial || { enabled: false, acl: { default: 'deny', allow: [], deny: [] } };
  let joinEditing = false;
  let joinRevealed = false;
  let onChange = null;

  function paint() {
    const on = !!state.enabled;
    const acl = state.acl || { allow: [], deny: [] };
    const join = joinEntry(acl.allow);
    mount.innerHTML = `
      <div class="ra-toolbar">
        <button type="button" class="btn ${on ? 'btn-secondary' : 'btn-primary'} btn-sm" id="raTog">
          ${esc(on ? t('node.ra.disable') : t('node.ra.enable'))}
        </button>
        <span class="badge ${on ? 'b-orange' : 'b-gray'}">${esc(on ? t('node.ra.on') : t('node.ra.off'))}</span>
      </div>
      <div class="ra-lists">
        <div>
          <label>${esc(t('acl.modal.allow'))}</label>
          <div id="raAllow"></div>
          <div class="ra-add">
            <input type="text" id="raAllowAid" placeholder="${esc(t('acl.modal.aid_placeholder'))}" />
            <button type="button" class="btn btn-secondary btn-sm" id="raAllowAdd">${esc(t('acl.modal.add'))}</button>
          </div>
        </div>
        <div>
          <label>${esc(t('acl.modal.deny'))}</label>
          <div id="raDeny"></div>
          <div class="ra-add">
            <input type="text" id="raDenyAid" placeholder="${esc(t('acl.modal.aid_placeholder'))}" />
            <button type="button" class="btn btn-secondary btn-sm" id="raDenyAdd">${esc(t('acl.modal.add'))}</button>
          </div>
        </div>
      </div>
      <div class="ra-join">
        <label>${esc(t('acl.modal.join'))}</label>
        <div id="raJoin"></div>
        ${join ? `<p class="muted ra-join-warn">${esc(t('node.ra.join_warn'))}</p>` : ''}
      </div>
      <div class="ra-events">
        <div><span class="muted">${esc(t('node.ra.last_ok'))}</span> ${eventLine(state.last_ok, esc, t, relTime)}</div>
        <div><span class="muted">${esc(t('node.ra.last_bad'))}</span> ${eventLine(state.last_bad_secret, esc, t, relTime)}</div>
      </div>`;
    const allowBox = mount.querySelector('#raAllow');
    const denyBox = mount.querySelector('#raDeny');
    allowBox.innerHTML = namedRows(acl.allow, t('acl.modal.empty'), esc);
    denyBox.innerHTML = namedRows(acl.deny, t('acl.modal.empty'), esc);
    allowBox.querySelectorAll('[data-del]').forEach((btn) => {
      btn.onclick = () => delEntry('allow', btn.closest('.acl-row').dataset.id);
    });
    denyBox.querySelectorAll('[data-del]').forEach((btn) => {
      btn.onclick = () => delEntry('deny', btn.closest('.acl-row').dataset.id);
    });
    paintJoin();
    mount.querySelector('#raTog').onclick = toggle;
    mount.querySelector('#raAllowAdd').onclick = () => addEntry('allow', mount.querySelector('#raAllowAid'));
    mount.querySelector('#raDenyAdd').onclick = () => addEntry('deny', mount.querySelector('#raDenyAid'));
  }

  function paintJoin() {
    const joinBox = mount.querySelector('#raJoin');
    const join = joinEntry(state.acl && state.acl.allow);
    const secret = (join && join.secret) || '';
    if (joinEditing) {
      joinBox.innerHTML = `
        <div class="ra-add">
          <input type="text" id="raJoinSecret" value="${esc(secret)}" placeholder="${esc(secret ? '' : t('acl.modal.join_placeholder'))}" />
          <button type="button" class="btn btn-secondary btn-sm" id="raJoinSave">${esc(t('acl.modal.join_save'))}</button>
        </div>`;
      joinBox.querySelector('#raJoinSave').onclick = saveJoin;
      return;
    }
    if (!join) {
      joinBox.innerHTML = `
        <div class="ra-add">
          <span class="muted">${esc(t('acl.modal.join_empty'))}</span>
          <button type="button" class="btn btn-secondary btn-sm" id="raJoinEdit">${esc(t('acl.modal.join_edit'))}</button>
        </div>`;
    } else {
      const shown = joinRevealed ? secret : '*'.repeat(Math.max(8, secret.length));
      joinBox.innerHTML = `
        <div class="ra-add">
          <code class="mono ra-secret">${esc(shown)}</code>
          <button type="button" class="btn btn-ghost btn-xs" id="raJoinEye">${joinRevealed ? '🙈' : '👁'}</button>
          <button type="button" class="btn btn-secondary btn-sm" id="raJoinEdit">${esc(t('acl.modal.join_edit'))}</button>
        </div>`;
      joinBox.querySelector('#raJoinEye').onclick = () => {
        joinRevealed = !joinRevealed;
        paintJoin();
      };
    }
    joinBox.querySelector('#raJoinEdit').onclick = () => {
      joinEditing = true;
      paintJoin();
    };
  }

  async function reload() {
    state = await api('/node/remote-admin');
    paint();
    onChange?.(state);
  }

  async function toggle(ev) {
    const b = ev.currentTarget;
    setLoading(b, true);
    try {
      await api('/node/remote-admin', {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !state.enabled }),
      });
      await reload();
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    } finally {
      setLoading(b, false);
    }
  }

  async function addEntry(list, input) {
    const v = input.value.trim();
    if (!v) return;
    try {
      await api(`/node/remote-admin/${list}`, {
        method: 'POST',
        body: JSON.stringify({ aid: v }),
      });
      input.value = '';
      await reload();
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    }
  }

  async function delEntry(list, id) {
    try {
      await api(`/node/remote-admin/${list}/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await reload();
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    }
  }

  async function saveJoin() {
    const secret = (mount.querySelector('#raJoinSecret')?.value || '').trim();
    const join = joinEntry(state.acl && state.acl.allow);
    try {
      if (!secret) {
        if (join?.id) {
          await api(`/node/remote-admin/allow/${encodeURIComponent(join.id)}`, { method: 'DELETE' });
        }
      } else {
        await api('/node/remote-admin/allow', {
          method: 'POST',
          body: JSON.stringify({ secret }),
        });
      }
      joinEditing = false;
      joinRevealed = false;
      await reload();
    } catch (e) {
      toast(t('common.error', { msg: e.message }), 'err');
    }
  }

  paint();

  return {
    setOnChange(fn) { onChange = fn; },
    enabled() { return !!state.enabled; },
  };
}
