import {
  esc,
  shortAid,
  aliasOf,
  ensureAlias,
  setLoading,
  parseTags,
  fetchAgentCardForAgent,
  profileDraftFromAgent,
  profileDraftFromCardJson,
  mergeProfileDraft,
  agentCardUrlFromServiceTcp,
} from './util.js';

function applyDraftToForm(root, draft) {
  root.querySelector('#pfName').value = draft.name || '';
  root.querySelector('#pfBrief').value = draft.brief || '';
  root.querySelector('#pfProtos').value = (draft.protocols || []).join(' ');
  root.querySelector('#pfModalities').value = (draft.modalities || []).join(' ');
}

function readDraftFromForm(root) {
  return {
    name: root.querySelector('#pfName').value.trim(),
    brief: root.querySelector('#pfBrief').value.trim(),
    protocols: parseTags(root.querySelector('#pfProtos').value),
    modalities: parseTags(root.querySelector('#pfModalities').value),
  };
}

/** Open the profile (network business card) editor for one agent. */
export function openProfileModal(ctx, agent) {
  const { t, api, toast, openModal, onRefresh } = ctx;
  const alias = aliasOf(agent.aid) || ensureAlias(agent.aid);
  let draft = profileDraftFromAgent(agent);
  let cardUrl = agentCardUrlFromServiceTcp(agent.service_tcp) || '';
  let lastCard = null;

  openModal({
    title: t('profile.modal.title'),
    wide: true,
    noBackdropClose: true,
    body: `
      <div class="pub-modal-card">
        <div class="pub-modal-identity-row profile-modal-identity-row">
          <span class="pub-modal-alias">${esc(alias)}</span>
          <span class="mono muted">${esc(shortAid(agent.aid))}</span>
        </div>
        <div class="profile-modal-scope">${esc(t('profile.modal.scope_hint'))}</div>
      </div>

      <div class="pub-modal-tool-box">
        <button type="button" class="btn btn-secondary btn-sm" id="pfFill">${esc(t('profile.modal.fill_from_card'))}</button>
        <span class="hint">${esc(t('profile.modal.fill_from_card.hint'))}</span>
      </div>

      <div class="pub-modal-section" style="margin-top:1.3rem;padding-top:1.3rem">
        <div class="field">
          <label>${esc(t('profile.modal.name'))}</label>
          <input type="text" id="pfName" value="${esc(draft.name)}" placeholder="${esc(t('profile.modal.name_placeholder'))}" />
          <div class="hint">${esc(t('profile.modal.name_hint'))}</div>
        </div>
        <div class="field" style="margin-bottom:0">
          <label>${esc(t('profile.modal.brief'))}</label>
          <textarea id="pfBrief" rows="2" style="width:100%" placeholder="${esc(t('profile.modal.brief_placeholder'))}">${esc(draft.brief)}</textarea>
          <div class="hint">${esc(t('profile.modal.brief_hint'))}</div>
        </div>
      </div>

      <details class="pub-modal-section">
        <summary>${esc(t('profile.modal.advanced'))}</summary>
        <div class="form-grid-2" style="margin-top:.9rem">
          <div class="field" style="margin-bottom:0">
            <label>${esc(t('profile.modal.protocols'))}</label>
            <input type="text" id="pfProtos" value="${esc((draft.protocols || []).join(' '))}" placeholder="${esc(t('profile.modal.protocols_placeholder'))}" />
            <div class="hint">${esc(t('profile.modal.tags_hint'))}</div>
          </div>
          <div class="field" style="margin-bottom:0">
            <label>${esc(t('profile.modal.modalities'))}</label>
            <input type="text" id="pfModalities" value="${esc((draft.modalities || []).join(' '))}" placeholder="${esc(t('profile.modal.modalities_placeholder'))}" />
            <div class="hint">${esc(t('profile.modal.tags_hint'))}</div>
          </div>
        </div>
      </details>

      <div class="pub-modal-actions">
        <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
        <button type="button" class="btn btn-primary" id="pfSave">${esc(t('common.save'))}</button>
      </div>`,
    onMount(root, { close }) {
      const fillBtn = root.querySelector('#pfFill');

      function updateFillBtn() {
        fillBtn.disabled = !lastCard && !agent.service_tcp;
      }

      updateFillBtn();

      async function loadCard(silent) {
        const got = await fetchAgentCardForAgent(api, agent.aid, agent.service_tcp);
        if (!got) {
          if (!silent) toast(t('profile.modal.source.none'), 'warn');
          cardUrl = '';
          lastCard = null;
          updateFillBtn();
          return null;
        }
        lastCard = got.json;
        cardUrl = got.url;
        return got;
      }

      async function applyFromCard({ overwrite, silent }) {
        const got = overwrite
          ? await loadCard(silent)
          : (lastCard ? { json: lastCard, url: cardUrl } : await loadCard(silent));
        if (!got) return;
        const incoming = profileDraftFromCardJson(got.json);
        draft = mergeProfileDraft(readDraftFromForm(root), incoming, { overwrite });
        applyDraftToForm(root, draft);
        updateFillBtn();
        if (!silent) toast(t('profile.modal.fill_ok'), 'ok');
      }

      fillBtn.onclick = async (ev) => {
        const b = ev.currentTarget;
        setLoading(b, true);
        try {
          await applyFromCard({ overwrite: true, silent: false });
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        } finally {
          setLoading(b, false);
        }
      };

      root.querySelector('#pfSave').onclick = async (ev) => {
        const b = ev.currentTarget;
        setLoading(b, true);
        draft = readDraftFromForm(root);
        try {
          await api(`/agents/${encodeURIComponent(agent.aid)}/profile`, {
            method: 'POST',
            body: JSON.stringify({
              name: draft.name,
              brief: draft.brief,
              protocols: draft.protocols,
              modalities: draft.modalities,
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

      (async () => {
        try {
          await applyFromCard({ overwrite: false, silent: true });
        } catch (_) {}
      })();
    },
  });
}
