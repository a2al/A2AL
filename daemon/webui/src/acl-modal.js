import { esc, shortAid, aliasOf, ensureAlias } from './util.js';

function renderNamed(items, emptyText) {
  const named = (items || []).filter((e) => e.aid);
  if (!named.length) {
    return `<p class="muted" style="margin:.35rem 0 0;font-size:.83rem">${esc(emptyText)}</p>`;
  }
  return named.map((e) => `
    <div class="acl-row" data-id="${esc(e.id)}" style="display:flex;gap:.4rem;align-items:center;margin-top:.35rem">
      <code class="mono" style="flex:1;font-size:.8rem;word-break:break-all">${esc(e.aid)}</code>
      <button type="button" class="btn btn-ghost btn-xs" data-del>${esc('×')}</button>
    </div>`).join('');
}

function joinEntry(items) {
  return (items || []).find((e) => !e.aid && (e.secret_set || e.secret)) || null;
}

/** Open the local ACL editor for one agent (holder's door, not Discover). */
export function openACLModal(ctx, agent) {
  const { t, api, toast, openModal, onRefresh } = ctx;
  const alias = aliasOf(agent.aid) || ensureAlias(agent.aid);

  openModal({
    title: t('acl.modal.title'),
    wide: true,
    noBackdropClose: true,
    body: `
      <div class="pub-modal-card">
        <div class="pub-modal-identity-row profile-modal-identity-row">
          <span class="pub-modal-alias">${esc(alias)}</span>
          <span class="mono muted">${esc(shortAid(agent.aid))}</span>
        </div>
      </div>

      <div class="pub-modal-section" style="margin-top:1.1rem">
        <div class="field" style="margin-bottom:0">
          <label>${esc(t('acl.modal.default'))}</label>
          <div style="display:flex;gap:.8rem;margin-top:.35rem">
            <label class="muted" style="display:flex;gap:.3rem;align-items:center">
              <input type="radio" name="aclDef" value="public" /> ${esc(t('acl.badge.public'))}
            </label>
            <label class="muted" style="display:flex;gap:.3rem;align-items:center">
              <input type="radio" name="aclDef" value="deny" /> ${esc(t('acl.badge.restricted'))}
            </label>
          </div>
          <p id="aclScopePublic" class="muted hidden" style="margin:.4rem 0 0;font-size:.82rem;line-height:1.45">${esc(t('acl.modal.scope_public'))}</p>
          <p id="aclScopeRestricted" class="muted hidden" style="margin:.4rem 0 0;font-size:.82rem;line-height:1.45">${esc(t('acl.modal.scope_restricted'))}</p>
        </div>
      </div>

      <div id="aclRestricted" class="hidden">
        <div class="pub-modal-section">
          <label>${esc(t('acl.modal.allow'))}</label>
          <div id="aclAllow"></div>
          <div style="display:flex;gap:.35rem;margin-top:.5rem;flex-wrap:wrap">
            <input type="text" id="aclAllowAid" placeholder="${esc(t('acl.modal.aid_placeholder'))}" style="flex:1;min-width:12rem" />
            <button type="button" class="btn btn-secondary btn-sm" id="aclAllowAdd">${esc(t('acl.modal.add'))}</button>
          </div>
        </div>

        <div class="pub-modal-section" style="margin-top:1.1rem">
          <label>${esc(t('acl.modal.join'))}</label>
          <div class="muted" style="font-size:.82rem;margin:.25rem 0 .4rem">${esc(t('acl.modal.join_hint'))}</div>
          <div id="aclJoin"></div>
        </div>

        <div class="acl-billing" id="aclBilling">
          <div class="acl-billing-head">
            <label>${esc(t('acl.modal.billing'))}</label>
            <label class="muted" data-soon style="display:flex;gap:.3rem;align-items:center;font-size:.83rem;white-space:nowrap">
              <input type="checkbox" /> ${esc(t('acl.modal.billing_enable'))}
            </label>
          </div>
          <p class="muted" style="margin:.2rem 0 .45rem;font-size:.8rem;line-height:1.4">${esc(t('acl.modal.billing_hint'))}</p>
          <div class="acl-billing-row">
            <span class="acl-billing-k">${esc(t('acl.modal.billing_mode'))}</span>
            <span class="acl-billing-v">
              <label class="acl-chip" data-soon><input type="checkbox" /> ${esc(t('acl.modal.billing_sub'))}</label>
              <label class="acl-chip" data-soon><input type="checkbox" /> ${esc(t('acl.modal.billing_meter'))}</label>
              <label class="acl-chip" data-soon><input type="checkbox" /> ${esc(t('acl.modal.billing_balance'))}</label>
            </span>
          </div>
          <div class="acl-billing-row">
            <span class="acl-billing-k">${esc(t('acl.modal.billing_rail'))}</span>
            <span class="acl-billing-v">
              <button type="button" class="btn btn-ghost btn-xs" data-soon>Stripe</button>
              <button type="button" class="btn btn-ghost btn-xs" data-soon>PayPal</button>
              <button type="button" class="btn btn-ghost btn-xs" data-soon>${esc(t('acl.modal.billing_chain'))}</button>
              <button type="button" class="btn btn-ghost btn-xs" data-soon>Web API</button>
              <button type="button" class="btn btn-ghost btn-xs" data-soon>${esc(t('acl.modal.billing_log'))}</button>
            </span>
          </div>
        </div>
      </div>

      <div class="pub-modal-section" style="margin-top:1.1rem">
        <label>${esc(t('acl.modal.deny'))}</label>
        <div id="aclDeny"></div>
        <div style="display:flex;gap:.35rem;margin-top:.5rem;flex-wrap:wrap">
          <input type="text" id="aclDenyAid" placeholder="${esc(t('acl.modal.aid_placeholder'))}" style="flex:1;min-width:12rem" />
          <button type="button" class="btn btn-secondary btn-sm" id="aclDenyAdd">${esc(t('acl.modal.add'))}</button>
        </div>
      </div>`,
    onMount(root) {
      const allowBox = root.querySelector('#aclAllow');
      const denyBox = root.querySelector('#aclDeny');
      const joinBox = root.querySelector('#aclJoin');
      const restricted = root.querySelector('#aclRestricted');
      let policy = { default: 'public', allow: [], deny: [] };
      let joinEditing = false;
      let joinRevealed = false;

      function paint() {
        const def = policy.default === 'deny' ? 'deny' : 'public';
        root.querySelectorAll('input[name="aclDef"]').forEach((el) => {
          el.checked = el.value === def;
        });
        restricted.classList.toggle('hidden', def !== 'deny');
        root.querySelector('#aclScopePublic').classList.toggle('hidden', def !== 'public');
        root.querySelector('#aclScopeRestricted').classList.toggle('hidden', def !== 'deny');
        allowBox.innerHTML = renderNamed(policy.allow, t('acl.modal.empty'));
        denyBox.innerHTML = renderNamed(policy.deny, t('acl.modal.empty'));
        allowBox.querySelectorAll('[data-del]').forEach((btn) => {
          btn.onclick = () => delEntry('allow', btn.closest('.acl-row').dataset.id);
        });
        denyBox.querySelectorAll('[data-del]').forEach((btn) => {
          btn.onclick = () => delEntry('deny', btn.closest('.acl-row').dataset.id);
        });
        paintJoin();
      }

      function paintJoin() {
        const join = joinEntry(policy.allow);
        const secret = (join && join.secret) || '';
        if (joinEditing) {
          joinBox.innerHTML = `
            <div style="display:flex;gap:.35rem;margin-top:.35rem;flex-wrap:wrap;align-items:center">
              <input type="text" id="aclJoinSecret" value="${esc(secret)}" placeholder="${esc(secret ? '' : t('acl.modal.join_placeholder'))}" style="flex:1;min-width:10rem" />
              <button type="button" class="btn btn-secondary btn-sm" id="aclJoinSave">${esc(t('acl.modal.join_save'))}</button>
            </div>`;
          joinBox.querySelector('#aclJoinSave').onclick = saveJoin;
          const inp = joinBox.querySelector('#aclJoinSecret');
          inp.focus();
          inp.select();
          return;
        }
        if (!join) {
          joinBox.innerHTML = `
            <div style="display:flex;gap:.4rem;align-items:center;margin-top:.35rem">
              <span class="muted" style="flex:1;font-size:.83rem">${esc(t('acl.modal.join_empty'))}</span>
              <button type="button" class="btn btn-secondary btn-sm" id="aclJoinEdit">${esc(t('acl.modal.join_edit'))}</button>
            </div>`;
        } else {
          const shown = joinRevealed ? secret : '*'.repeat(Math.max(8, secret.length));
          joinBox.innerHTML = `
            <div style="display:flex;gap:.35rem;align-items:center;margin-top:.35rem">
              <code class="mono" style="flex:1;font-size:.85rem;letter-spacing:.12em">${esc(shown)}</code>
              <button type="button" class="btn btn-ghost btn-xs" id="aclJoinEye" title="${esc(t('acl.modal.join_toggle'))}" style="font-size:1rem;line-height:1">${joinRevealed ? '🙈' : '👁'}</button>
              <button type="button" class="btn btn-secondary btn-sm" id="aclJoinEdit">${esc(t('acl.modal.join_edit'))}</button>
            </div>`;
          joinBox.querySelector('#aclJoinEye').onclick = () => {
            joinRevealed = !joinRevealed;
            paintJoin();
          };
        }
        joinBox.querySelector('#aclJoinEdit').onclick = () => {
          joinEditing = true;
          paintJoin();
        };
      }

      async function saveJoin() {
        const secret = (joinBox.querySelector('#aclJoinSecret')?.value || '').trim();
        const join = joinEntry(policy.allow);
        try {
          if (!secret) {
            if (join?.id) {
              await api(`/agents/${encodeURIComponent(agent.aid)}/acl/allow/${encodeURIComponent(join.id)}`, { method: 'DELETE' });
            }
          } else {
            await api(`/agents/${encodeURIComponent(agent.aid)}/acl/allow`, {
              method: 'POST',
              body: JSON.stringify({ secret }),
            });
          }
          joinEditing = false;
          joinRevealed = false;
          await reload();
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      }

      async function reload() {
        policy = await api(`/agents/${encodeURIComponent(agent.aid)}/acl`);
        paint();
      }

      async function delEntry(list, id) {
        try {
          await api(`/agents/${encodeURIComponent(agent.aid)}/acl/${list}/${encodeURIComponent(id)}`, { method: 'DELETE' });
          await reload();
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      }

      async function addEntry(list, input) {
        const v = input.value.trim();
        if (!v) return;
        try {
          await api(`/agents/${encodeURIComponent(agent.aid)}/acl/${list}`, {
            method: 'POST',
            body: JSON.stringify({ aid: v }),
          });
          input.value = '';
          await reload();
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      }

      root.querySelectorAll('input[name="aclDef"]').forEach((el) => {
        el.onchange = async () => {
          if (!el.checked) return;
          try {
            await api(`/agents/${encodeURIComponent(agent.aid)}/acl`, {
              method: 'PATCH',
              body: JSON.stringify({ default: el.value }),
            });
            policy.default = el.value;
            paint();
            onRefresh();
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
            paint();
          }
        };
      });

      root.querySelector('#aclBilling')?.addEventListener('click', (ev) => {
        const el = ev.target.closest('[data-soon]');
        if (!el) return;
        ev.preventDefault();
        const box = el.matches('input[type=checkbox]') ? el : el.querySelector('input[type=checkbox]');
        if (box) box.checked = false;
        toast(t('acl.modal.coming_soon'));
      });

      root.querySelector('#aclAllowAdd').onclick = () => addEntry('allow', root.querySelector('#aclAllowAid'));
      root.querySelector('#aclDenyAdd').onclick = () => addEntry('deny', root.querySelector('#aclDenyAid'));

      reload().catch((e) => toast(t('common.error', { msg: e.message }), 'err'));
    },
  });
}
