import { openProfileModal } from './profile-modal.js';
import {
  esc,
  shortAid,
  aliasOf,
  setAliasOf,
  ensureAlias,
  nextUniqueDefaultAlias,
  labelAid,
  setLoading,
  parseTags,
  buildServiceName,
  partitionProtocols,
  gatherProtocols,
  agentCardUrlFromServiceTcp,
} from './util.js';

const PUB_CATS = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];

function parseTopic(topic) {
  let preCat = 'lang';
  let preFn = '';
  let preQ = '';
  if (topic && topic.includes('.')) {
    const dot = topic.indexOf('.');
    preCat = topic.slice(0, dot) || 'lang';
    const rest = topic.slice(dot + 1);
    const dash = rest.indexOf('-');
    if (dash >= 0) {
      preFn = rest.slice(0, dash);
      preQ = rest.slice(dash + 1);
    } else preFn = rest;
  }
  return { preCat, preFn, preQ };
}

function agentFor(list, aid) {
  return list.find((a) => a.aid === aid) || list[0];
}

function wireAliasEditor(root, aidOrFn) {
  const aliasEl = root.querySelector('#pubAliasVal');
  const form = root.querySelector('#pubAliasForm');
  const input = root.querySelector('#pubAliasInput');
  if (!aliasEl || !form || !input) return;
  const getAid = typeof aidOrFn === 'function' ? aidOrFn : () => aidOrFn;

  root.querySelector('#pubAliasEdit')?.addEventListener('click', () => {
    const open = form.style.display !== 'none';
    form.style.display = open ? 'none' : '';
    if (!open) input.focus();
  });

  const save = () => {
    const v = input.value.trim() || nextUniqueDefaultAlias();
    setAliasOf(getAid(), v);
    aliasEl.textContent = v;
    input.value = v;
    form.style.display = 'none';
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') save();
    if (e.key === 'Escape') form.style.display = 'none';
  });
  input.addEventListener('blur', save);
}

function refreshProfileCard(root, agent) {
  const aidEl = root.querySelector('#pubAidLine');
  const nameEl = root.querySelector('#pubProfileName');
  const briefEl = root.querySelector('#pubProfileBrief');
  if (aidEl) aidEl.textContent = shortAid(agent?.aid || '');
  if (nameEl) {
    nameEl.textContent = agent?.profile?.name || '—';
    nameEl.classList.toggle('is-empty', !agent?.profile?.name);
  }
  if (briefEl) {
    briefEl.textContent = agent?.profile?.brief || '—';
    briefEl.classList.toggle('is-empty', !agent?.profile?.brief);
  }
}

function protoCheckboxHtml(editSvc) {
  const defaultProtos = editSvc ? (editSvc.protocols || []) : ['mcp'];
  const { checked: on, custom } = partitionProtocols(defaultProtos);
  const boxes = ['mcp', 'a2a', 'http', 'grpc', 'websocket']
    .map((p) => {
      const id = `svProto_${p}`;
      const isOn = on.includes(p);
      return `<label class="chk${isOn ? ' chk-on' : ''}"><input type="checkbox" id="${id}" ${isOn ? 'checked' : ''} /> ${p}</label>`;
    })
    .join('');
  return { boxes: `<div class="pub-modal-protocols">${boxes}</div>`, custom: custom.join(' ') };
}

/** Publish-capability modal (L2 only; profile edited separately). */
export function openPublishModal(ctx, { agentList, editAid = null, editSvc = null }) {
  const { t, api, toast, openModal, onRefresh } = ctx;
  const isEdit = !!editSvc;
  const showPicker = editAid == null && agentList.length > 1;
  let currentAid = editAid || agentList[0]?.aid;

  const preTopic = editSvc?.topic || '';
  const { preCat, preFn, preQ } = parseTopic(preTopic);
  const customOn = !PUB_CATS.includes(preCat);
  const catBtns = PUB_CATS.map((c) => {
    const on = c === preCat && PUB_CATS.includes(preCat);
    return `<button type="button" data-cat="${c}" class="btn btn-secondary btn-sm${on ? ' cat-on' : ''}" ${isEdit ? 'disabled' : ''}>${esc(c)}</button>`;
  }).join('');

  const initialAgent = agentFor(agentList, currentAid);
  const alias = aliasOf(currentAid) || ensureAlias(currentAid);
  const { boxes: protoBoxes, custom: protoCustom } = protoCheckboxHtml(editSvc);
  const defaultMetaUrl =
    editSvc?.meta?.url || editSvc?.meta?.URL || agentCardUrlFromServiceTcp(initialAgent?.service_tcp) || '';

  openModal({
    title: t('service.modal.title'),
    wide: true,
    noBackdropClose: true,
    body: `
      ${showPicker ? `<div class="field"><label>${esc(t('service.modal.agent_pick'))}</label><select id="svAid">${agentList.map((a) => `<option value="${esc(a.aid)}" ${a.aid === currentAid ? 'selected' : ''}>${esc(labelAid(a.aid))}</option>`).join('')}</select></div>` : ''}

      <div class="pub-modal-card" id="pubIdentity">
        <div class="pub-modal-identity-row">
          <span class="pub-modal-alias" id="pubAliasVal">${esc(alias)}</span>
          <button type="button" class="pub-modal-alias-edit" id="pubAliasEdit" title="${esc(t('agent.alias.set'))}">✏</button>
        </div>
        <div id="pubAliasForm" class="pub-modal-alias-form field" style="display:none;max-width:16rem">
          <label>${esc(t('agent.alias.local_label'))}</label>
          <input type="text" id="pubAliasInput" maxlength="24" value="${esc(alias)}" placeholder="${esc(t('agent.alias.placeholder'))}" style="width:100%" />
          <div class="hint">${esc(t('agent.alias.local_hint'))}</div>
        </div>
        <div class="mono muted" id="pubAidLine">${esc(shortAid(initialAgent?.aid || ''))}</div>

        <div class="pub-modal-profile-row">
          <div class="pub-modal-eyebrow" style="margin-bottom:0">${esc(t('service.modal.section.profile'))}</div>
          <button type="button" class="btn btn-ghost btn-sm" id="pubEditProfile">${esc(t('service.modal.profile.edit_link'))}</button>
        </div>
        <div class="pub-modal-profile-name${initialAgent?.profile?.name ? '' : ' is-empty'}" id="pubProfileName">${esc(initialAgent?.profile?.name || '—')}</div>
        <div class="pub-modal-profile-brief${initialAgent?.profile?.brief ? '' : ' is-empty'}" id="pubProfileBrief">${esc(initialAgent?.profile?.brief || '—')}</div>
      </div>

      <div class="pub-modal-section">
        <div class="pub-modal-section-title">${esc(t('service.modal.section.index'))}</div>
        <div class="pub-modal-section-hint">${esc(t('service.modal.index.hint'))}</div>
        ${isEdit ? `<p class="warn-box pub-modal-locked-note">${esc(t('service.modal.index.locked'))}</p>` : ''}
        <div class="form-grid-2">
          <div class="field form-grid-wide">
            <label>${esc(t('service.modal.category.label'))}</label>
            <div class="cat-btns" id="svCats">${catBtns}<button type="button" data-cat="__" class="btn btn-secondary btn-sm${customOn ? ' cat-on' : ''}" ${isEdit ? 'disabled' : ''}>${esc(t('service.modal.category.custom'))}</button></div>
            <input type="text" id="svCatC" class="${PUB_CATS.includes(preCat) ? 'hidden' : ''}" style="margin-top:.35rem" placeholder="${esc(t('service.modal.category.custom_placeholder'))}" value="${PUB_CATS.includes(preCat) ? '' : esc(preCat)}" ${isEdit ? 'readonly' : ''} />
          </div>
          <div class="field">
            <label>${esc(t('service.modal.func.label'))}</label>
            <input type="text" id="svFn" value="${esc(preFn)}" placeholder="${esc(t('service.modal.func.placeholder'))}" ${isEdit ? 'readonly' : ''} />
            <div class="hint">${esc(t('service.modal.func.hint'))}</div>
          </div>
          <div class="field">
            <label>${esc(t('service.modal.qualifier.label'))}</label>
            <input type="text" id="svQ" value="${esc(preQ)}" placeholder="${esc(t('service.modal.qualifier.placeholder'))}" ${isEdit ? 'readonly' : ''} />
            <div class="hint">${esc(t('service.modal.qualifier.hint'))}</div>
          </div>
        </div>
        <div class="pub-modal-index-preview" id="svPreview"></div>
      </div>

      <div class="pub-modal-section">
        <div class="pub-modal-section-title">${esc(t('service.modal.section.discover'))}</div>
        <div class="pub-modal-section-hint">${esc(t('service.modal.discover.hint'))}</div>
        <div class="form-grid-2">
          <div class="field">
            <label>${esc(t('service.modal.svc.name'))}</label>
            <input type="text" id="svSvcName" value="${esc(editSvc?.name || '')}" placeholder="${esc(t('service.modal.svc.name_placeholder'))}" />
            <div class="hint">${esc(t('service.modal.svc.name_hint'))}</div>
          </div>
          <div class="field">
            <label>${esc(t('service.modal.tags.label'))}</label>
            <input type="text" id="svTags" value="${esc((editSvc?.tags || []).join(' '))}" placeholder="${esc(t('service.modal.tags.placeholder'))}" />
            <div class="hint">${esc(t('service.modal.tags.hint'))}</div>
          </div>
          <div class="field form-grid-wide">
            <label>${esc(t('service.modal.svc.brief'))}</label>
            <textarea id="svSvcBrief" rows="2" style="width:100%" placeholder="${esc(t('service.modal.svc.brief_placeholder'))}">${esc(editSvc?.brief || '')}</textarea>
          </div>
          <div class="field form-grid-wide">
            <label>${esc(t('service.modal.protocols'))}</label>
            ${protoBoxes}
          </div>
          <div class="field">
            <label>${esc(t('service.modal.protocols.custom_placeholder').replace(/…$/, ''))}</label>
            <input type="text" id="svProtoCustom" placeholder="${esc(t('service.modal.protocols.custom_placeholder'))}" value="${esc(protoCustom)}" />
            <div class="hint">${esc(t('service.modal.protocols.custom_hint'))}</div>
          </div>
          <div class="field">
            <label>${esc(t('service.modal.pricing.label'))}</label>
            <select id="svPrice" class="pub-modal-price-select" disabled>
              <option selected>${esc(t('service.modal.pricing.free'))}</option>
            </select>
            <div class="hint">${esc(t('service.modal.pricing.hint'))}</div>
          </div>
        </div>
      </div>

      <details class="pub-modal-section">
        <summary>${esc(t('agent.modal.advanced'))}</summary>
        <div class="form-grid-2" style="margin-top:.9rem">
          <div class="field">
            <label>${esc(t('service.modal.url.label'))}</label>
            <input type="url" id="svMetaUrl" value="${esc(defaultMetaUrl)}" placeholder="${esc(t('service.modal.url.placeholder'))}" />
            <div class="hint">${esc(t('service.modal.url.hint'))}</div>
          </div>
          <div class="field">
            <label>${esc(t('service.modal.ttl.label'))}</label>
            <input type="number" id="svTtl" value="${editSvc?.ttl || 3600}" min="0" />
          </div>
        </div>
      </details>

      <div class="pub-modal-actions">
        <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
        <button type="button" class="btn btn-primary" id="svGo">${esc(isEdit ? t('common.save') : t('service.modal.submit'))}</button>
      </div>`,
    onMount(root, { close }) {
      let cat = PUB_CATS.includes(preCat) ? preCat : '__';
      if (!PUB_CATS.includes(preCat)) cat = '__';

      function getAid() {
        if (showPicker) return root.querySelector('#svAid').value;
        return currentAid;
      }

      function currentAgent() {
        return agentFor(agentList, getAid());
      }

      function currentCat() {
        if (isEdit) return preCat;
        if (cat === '__') return root.querySelector('#svCatC').value.trim().toLowerCase();
        return cat;
      }

      function updPreview() {
        const preview = isEdit
          ? preTopic
          : buildServiceName(currentCat(), root.querySelector('#svFn').value, root.querySelector('#svQ').value);
        root.querySelector('#svPreview').textContent = `${t('service.modal.index.preview')} ${preview || '—'}`;
      }

      function syncAgentUi() {
        const ag = currentAgent();
        currentAid = ag?.aid || currentAid;
        const a = aliasOf(currentAid) || ensureAlias(currentAid);
        root.querySelector('#pubAliasVal').textContent = a;
        root.querySelector('#pubAliasInput').value = a;
        refreshProfileCard(root, ag);
      }

      wireAliasEditor(root, () => currentAid);

      root.querySelectorAll('.pub-modal-protocols .chk').forEach((label) => {
        const cb = label.querySelector('input');
        cb.addEventListener('change', () => label.classList.toggle('chk-on', cb.checked));
      });

      if (showPicker) {
        root.querySelector('#svAid').addEventListener('change', () => {
          syncAgentUi();
          const ag = currentAgent();
          const url = agentCardUrlFromServiceTcp(ag?.service_tcp);
          if (url && !root.querySelector('#svMetaUrl').value.trim()) {
            root.querySelector('#svMetaUrl').value = url;
          }
        });
      }

      root.querySelector('#pubEditProfile').onclick = () => {
        const ag = currentAgent();
        if (!ag) return;
        close();
        openProfileModal(ctx, ag);
      };

      if (!isEdit) {
        root.querySelector('#svCats').onclick = (e) => {
          const btn = e.target.closest('[data-cat]');
          if (!btn || btn.disabled) return;
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
      }
      updPreview();

      root.querySelector('#svGo').onclick = async (ev) => {
        const aid = getAid();
        const full = isEdit
          ? preTopic
          : buildServiceName(
              currentCat(),
              root.querySelector('#svFn').value,
              root.querySelector('#svQ').value,
            );
        if (!full) return;
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
              name: root.querySelector('#svSvcName').value.trim(),
              protocols: gatherProtocols(root),
              tags: parseTags(root.querySelector('#svTags').value),
              brief: root.querySelector('#svSvcBrief').value.trim(),
              meta,
              ttl,
            }),
          });
          toast(t('common.sent'), 'ok');
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
