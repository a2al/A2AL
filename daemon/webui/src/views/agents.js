import {
  esc,
  shortAid,
  setLoading,
  parseTags,
  buildServiceName,
  mapCardJson,
} from '../util.js';

const CATS = ['lang', 'gen', 'sense', 'data', 'reason', 'code', 'tool'];

function agentKind(aid) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(aid)) ? 'Ethereum' : 'Ed25519';
}

function agentStatus(ag) {
  if (!ag.published_to_dht) return { key: 'agent.status.unpublished', cls: 'b-gray' };
  if (ag.next_republish_estimate) {
    const overdueSec = (Date.now() - new Date(ag.next_republish_estimate).getTime()) / 1000;
    if (overdueSec > 600) return { key: 'agent.status.refresh_failed', cls: 'b-yellow' };
  }
  return { key: 'agent.status.published', cls: 'b-green' };
}

function flattenServices(agents) {
  const rows = [];
  for (const ag of agents || []) {
    for (const s of ag.services || []) {
      rows.push({ agent: ag, svc: s });
    }
  }
  return rows;
}

export async function renderAgents(mount, ctx) {
  const { t, api, toast, relTime, openModal, onRefresh, copyText } = ctx;
  let agents = [];
  try {
    const r = await api('/agents');
    agents = r.agents || [];
  } catch (e) {
    mount.innerHTML = `<p class="muted">${esc(t('common.error', { msg: e.message }))}</p>`;
    return;
  }

  const frag = document.createElement('div');

  const identSection = document.createElement('div');
  identSection.className = 'card';
  identSection.innerHTML = `<div class="card-h">${esc(t('agent.section.identity'))}</div><div class="card-b" id="identBody"></div>`;
  frag.appendChild(identSection);
  const identBody = identSection.querySelector('#identBody');

  if (!agents.length) {
    identBody.innerHTML = `
      <div class="guide-box">
        <h2>${esc(t('agent.empty.title'))}</h2>
        <div class="body">${esc(t('agent.empty.body')).replace(/\n/g, '<br/>')}</div>
        <div class="guide-actions">
          <button type="button" class="btn btn-primary" id="acreate">${esc(t('agent.action.create'))}</button>
          <button type="button" class="btn btn-secondary" id="aimport">${esc(t('agent.action.import'))}</button>
          <button type="button" class="btn btn-secondary" id="aeth">${esc(t('agent.action.eth'))}</button>
        </div>
      </div>`;
    identBody.querySelector('#acreate').onclick = () => openCreateModal();
    identBody.querySelector('#aimport').onclick = () => openImportModal();
    identBody.querySelector('#aeth').onclick = () => openEthModal();
  } else {
    const row = document.createElement('div');
    row.className = 'agent-row';
    for (const ag of agents) {
      const st = agentStatus(ag);
      const card = document.createElement('div');
      card.className = 'agent-card';
      card.innerHTML = `
        <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
          <span class="badge ${st.cls}">● ${esc(t(st.key))}</span>
          <span class="badge b-blue">${esc(agentKind(ag.aid))}</span>
        </div>
        <div class="aid-line">
          <span class="aid-short">${esc(shortAid(ag.aid))}</span>
          <button type="button" class="btn btn-ghost btn-sm" data-copy="${esc(ag.aid)}">⧉</button>
        </div>
        <div class="muted" style="font-size:.86rem">
          ${esc(t('agent.last_refresh', { ago: ag.last_publish_at ? relTime(ag.last_publish_at) : '—' }))}<br/>
          ${esc(t('agent.next_refresh', { eta: ag.next_republish_estimate ? relTime(ag.next_republish_estimate) : '—' }))}
        </div>
        <div class="agent-actions">
          <button type="button" class="btn btn-secondary btn-sm" data-pub="${esc(ag.aid)}">${esc(t('agent.action.refresh'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-exp>${esc(t('agent.action.export'))}</button>
          <button type="button" class="btn btn-danger btn-sm" data-del="${esc(ag.aid)}">${esc(t('agent.action.delete'))}</button>
        </div>`;
      card.querySelector('[data-copy]').onclick = () => copyText(ag.aid);
      card.querySelector('[data-pub]').onclick = async (ev) => {
        const b = ev.currentTarget;
        setLoading(b, true);
        try {
          const p = await api(`/agents/${encodeURIComponent(ag.aid)}/publish`, {
            method: 'POST',
            body: '{}',
          });
          toast(`ok seq ${p.seq}`, 'ok');
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        } finally {
          setLoading(b, false);
        }
      };
      card.querySelector('[data-exp]').onclick = () => toast(t('agent.export.unavailable'), 'info');
      card.querySelector('[data-del]').onclick = async () => {
        if (!confirm(t('agent.delete.confirm'))) return;
        try {
          await api(`/agents/${encodeURIComponent(ag.aid)}`, {
            method: 'DELETE',
            body: '{}',
          });
          toast('ok', 'ok');
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      };
      row.appendChild(card);
    }
    const addBar = document.createElement('div');
    addBar.style.cssText = 'display:flex;flex-direction:column;gap:.5rem;justify-content:center;min-width:8rem';
    addBar.innerHTML = `
      <button type="button" class="btn btn-secondary btn-sm" id="addCreate">+ ${esc(t('agent.action.create'))}</button>
      <button type="button" class="btn btn-ghost btn-sm" id="addImport">${esc(t('agent.action.import'))}</button>
      <button type="button" class="btn btn-ghost btn-sm" id="addEth">${esc(t('agent.action.eth'))}</button>`;
    addBar.querySelector('#addCreate').onclick = () => openCreateModal();
    addBar.querySelector('#addImport').onclick = () => openImportModal();
    addBar.querySelector('#addEth').onclick = () => openEthModal();
    row.appendChild(addBar);
    identBody.appendChild(row);
  }

  const svcSection = document.createElement('div');
  svcSection.className = 'card';
  svcSection.innerHTML = `<div class="card-h">${esc(t('service.section'))}</div><div class="card-b svc-list" id="svcBody"></div>`;
  frag.appendChild(svcSection);
  const svcBody = svcSection.querySelector('#svcBody');
  const flat = flattenServices(agents);

  if (!flat.length) {
    svcBody.innerHTML = `
      <div class="guide-box" style="padding:1.5rem 1rem">
        <h2 style="font-size:1.05rem">${esc(t('service.empty.title'))}</h2>
        <div class="body">${esc(t('service.empty.body')).replace(/\n/g, '<br/>')}</div>
        <button type="button" class="btn btn-primary" id="pubFirst" ${agents.length ? '' : 'disabled'}>${esc(t('service.action.publish'))}</button>
      </div>`;
    const b = svcBody.querySelector('#pubFirst');
    if (b && !b.disabled) b.onclick = () => openServiceModal(agents);
  } else {
    const top = document.createElement('div');
    top.style.cssText = 'margin-bottom:1rem;text-align:right';
    top.innerHTML = `<button type="button" class="btn btn-primary btn-sm" id="pubMore">${esc(t('service.action.publish'))}</button>`;
    top.querySelector('#pubMore').onclick = () => openServiceModal(agents);
    svcBody.appendChild(top);
    for (const { agent: ag, svc } of flat) {
      const topic = svc.topic || '';
      const el = document.createElement('div');
      el.className = 'svc-card';
      const protos = (svc.protocols || []).map((p) => `<span class="badge b-gray">${esc(p)}</span>`).join(' ');
      const tags = (svc.tags || []).map((x) => `<span class="muted">#${esc(x)}</span>`).join(' ');
      el.innerHTML = `
        <div class="svc-head">
          <span class="svc-name">${esc(topic)}</span>
          ${protos}
          <span style="flex:1"></span>
          <button type="button" class="btn btn-secondary btn-sm" data-un="${esc(ag.aid)}" data-svc="${esc(topic)}">${esc(t('service.action.unpublish'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-ed="${esc(ag.aid)}" data-svc="${esc(topic)}">${esc(t('service.action.edit'))}</button>
        </div>
        <div><strong>${esc(svc.name || '')}</strong> ${tags}</div>
        ${svc.brief ? `<div class="muted" style="margin-top:.35rem">${esc(svc.brief)}</div>` : ''}
        <div class="muted" style="margin-top:.35rem;font-size:.82rem">
          Agent: ${esc(shortAid(ag.aid))}
          ${ag.last_publish_at ? ` · ${esc(t('agent.last_refresh', { ago: relTime(ag.last_publish_at) }))}` : ''}
        </div>`;
      el.querySelector('[data-un]').onclick = async (ev) => {
        if (!confirm(t('service.action.unpublish') + '?')) return;
        const aid = ev.currentTarget.getAttribute('data-un');
        const s = ev.currentTarget.getAttribute('data-svc');
        try {
          await api(`/agents/${encodeURIComponent(aid)}/services/${encodeURIComponent(s)}`, {
            method: 'DELETE',
            body: '{}',
          });
          toast(t('service.unpublish.notice'), 'warn');
          onRefresh();
        } catch (e) {
          toast(t('common.error', { msg: e.message }), 'err');
        }
      };
      el.querySelector('[data-ed]').onclick = (ev) => {
        const aid = ev.currentTarget.getAttribute('data-ed');
        const s = ev.currentTarget.getAttribute('data-svc');
        openServiceModal(agents, aid, s);
      };
      svcBody.appendChild(el);
    }
  }

  const noteSection = document.createElement('div');
  noteSection.className = 'card';
  noteSection.innerHTML = `<div class="card-h">${esc(t('agent.note.title'))}</div><div class="card-b" id="noteInbox"></div>`;
  frag.appendChild(noteSection);
  const noteInbox = noteSection.querySelector('#noteInbox');
  if (!agents.length) {
    noteInbox.innerHTML = `<p class="muted">${esc(t('agent.note.need_agent'))}</p>`;
  } else {
    noteInbox.innerHTML = `
      <div class="field" style="display:flex;flex-wrap:wrap;gap:.5rem;align-items:flex-end">
        <div>
          <label class="muted" style="display:block;margin-bottom:.25rem">${esc(t('service.modal.agent_pick'))}</label>
          <select id="noteAid">${agents.map((a) => `<option value="${esc(a.aid)}">${esc(shortAid(a.aid))}</option>`).join('')}</select>
        </div>
        <button type="button" class="btn btn-primary" id="notePoll">${esc(t('agent.note.poll'))}</button>
      </div>
      <div id="noteList" style="margin-top:.75rem"></div>`;
    noteInbox.querySelector('#notePoll').onclick = async (ev) => {
      const aid = noteInbox.querySelector('#noteAid').value;
      const b = ev.currentTarget;
      setLoading(b, true);
      const list = noteInbox.querySelector('#noteList');
      list.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
      try {
        const r = await api(`/agents/${encodeURIComponent(aid)}/mailbox/poll`, {
          method: 'POST',
          body: '{}',
        });
        const msgs = r.messages || [];
        if (!msgs.length) {
          list.innerHTML = `<p class="muted">${esc(t('agent.note.empty'))}</p>`;
          return;
        }
        list.innerHTML = '';
        for (const m of msgs) {
          const row = document.createElement('div');
          row.className = 'result-row';
          row.style.marginBottom = '0.5rem';
          let bodyText = m.body_base64 || '';
          if (Number(m.msg_type) === 3 && bodyText) {
            try {
              const bin = atob(bodyText);
              const bytes = new Uint8Array(bin.length);
              for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
              bodyText = new TextDecoder().decode(bytes);
            } catch (_) {
              /* keep base64 */
            }
          }
          row.innerHTML = `
            <div class="muted" style="font-size:.82rem">${esc(t('agent.note.from'))} ${esc(shortAid(m.sender || ''))} · ${esc(t('agent.note.type'))} ${esc(String(m.msg_type))}</div>
            <div style="margin-top:.35rem;white-space:pre-wrap">${esc(bodyText)}</div>`;
          list.appendChild(row);
        }
      } catch (e) {
        list.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
      } finally {
        setLoading(b, false);
      }
    };
  }

  mount.appendChild(frag);

  function openCreateModal() {
    let step = 1;
    let gen = null;
    openModal({
      title: t('agent.modal.create.title'),
      body: `<div id="cmBody"></div>`,
      onMount(root, { close }) {
        const body = root.querySelector('#cmBody');
        function render() {
          if (step === 1) {
            body.innerHTML = `<p class="muted">${esc(t('common.loading'))}</p>`;
            api('/identity/generate', { method: 'POST', body: '{}' })
              .then((r) => {
                gen = r;
                step = 2;
                render();
              })
              .catch((e) => {
                body.innerHTML = `<p style="color:var(--error)">${esc(t('common.error', { msg: e.message }))}</p>`;
              });
            return;
          }
          if (step === 2 && gen) {
            body.innerHTML = `
              <div class="field">
                <label>AID</label>
                <input readonly class="mono" value="${esc(gen.aid)}" />
              </div>
              <div class="warn-box">${esc(t('agent.modal.masterkey.warning')).replace(/\n/g, '<br/>')}</div>
              <div class="field">
                <textarea readonly rows="3" class="mono" style="width:100%;font-size:.78rem">${esc(gen.master_private_key_hex)}</textarea>
                <button type="button" class="btn btn-ghost btn-sm" style="margin-top:.35rem" id="cmCopy">⧉ ${esc(t('common.copy'))}</button>
              </div>
              <label class="chk" style="margin-bottom:.5rem"><input type="checkbox" id="cmOk" /> <span>${esc(t('agent.modal.masterkey.confirm'))}</span></label>
              <details style="margin-top:1rem">
                <summary>${esc(t('agent.modal.advanced'))}</summary>
                <div class="field" style="margin-top:.75rem">
                  <label>${esc(t('agent.modal.service_tcp.label'))}</label>
                  <input type="text" id="cmTcp" placeholder="127.0.0.1:8080" />
                  <div class="hint">${esc(t('agent.modal.service_tcp.hint'))}</div>
                </div>
              </details>
              <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
                <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
                <button type="button" class="btn btn-primary" id="cmReg">${esc(t('agent.modal.submit'))}</button>
              </div>`;
            body.querySelector('#cmCopy').onclick = () =>
              navigator.clipboard.writeText(gen.master_private_key_hex)
                .then(() => toast(t('common.copied'), 'ok', 1200));
            body.querySelector('#cmReg').onclick = async (ev) => {
              if (!body.querySelector('#cmOk').checked) {
                toast(t('agent.modal.masterkey.confirm'), 'warn');
                return;
              }
              const b = ev.currentTarget;
              setLoading(b, true);
              try {
                const tcp = body.querySelector('#cmTcp').value.trim();
                const r = await api('/agents', {
                  method: 'POST',
                  body: JSON.stringify({
                    operational_private_key_hex: gen.operational_private_key_hex,
                    delegation_proof_hex: gen.delegation_proof_hex,
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
          }
        }
        render();
      },
    });
  }

  function openImportModal() {
    openModal({
      title: t('agent.modal.import.title'),
      body: `
        <div class="field">
          <label>${esc(t('agent.modal.import.op_key.label'))}</label>
          <textarea id="imOp" rows="2" class="mono" style="width:100%"></textarea>
        </div>
        <div class="field">
          <label>${esc(t('agent.modal.import.del_proof.label'))}</label>
          <textarea id="imDel" rows="3" class="mono" style="width:100%"></textarea>
        </div>
        <div class="field">
          <label>${esc(t('agent.modal.import.or_file'))}</label>
          <input type="file" id="imFile" accept=".json,application/json" />
        </div>
        <details style="margin-top:.5rem">
          <summary>${esc(t('agent.modal.advanced'))}</summary>
          <div class="field" style="margin-top:.75rem">
            <label>${esc(t('agent.modal.service_tcp.label'))}</label>
            <input type="text" id="imTcp" />
          </div>
        </details>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="imGo">${esc(t('agent.modal.submit'))}</button>
        </div>`,
      onMount(root, { close }) {
        root.querySelector('#imFile').onchange = (e) => {
          const f = e.target.files?.[0];
          if (!f) return;
          const rd = new FileReader();
          rd.onload = () => {
            try {
              const j = JSON.parse(String(rd.result));
              if (j.operational_private_key_hex)
                root.querySelector('#imOp').value = j.operational_private_key_hex;
              if (j.delegation_proof_hex) root.querySelector('#imDel').value = j.delegation_proof_hex;
            } catch (_) {
              toast(t('common.error', { msg: 'JSON' }), 'err');
            }
          };
          rd.readAsText(f);
        };
        root.querySelector('#imGo').onclick = async (ev) => {
          const op = root.querySelector('#imOp').value.trim();
          const del = root.querySelector('#imDel').value.trim();
          const tcp = root.querySelector('#imTcp').value.trim();
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
        <div class="field"><label>Ethereum address</label><input type="text" id="ethAgent" readonly class="mono" /></div>
        <button type="button" class="btn btn-secondary" id="eth1">1 · MetaMask · delegation message</button>
        <div class="field" style="margin-top:.75rem"><label>Message</label><textarea id="ethMsg" rows="2" readonly class="mono" style="width:100%"></textarea></div>
        <button type="button" class="btn btn-secondary" id="eth2" disabled>2 · Sign in MetaMask</button>
        <div class="field" style="margin-top:.75rem">
          <label>${esc(t('agent.modal.service_tcp.label'))}</label>
          <input type="text" id="ethTcp" />
        </div>
        <div style="margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end">
          <button type="button" class="btn btn-secondary" data-close>${esc(t('common.cancel'))}</button>
          <button type="button" class="btn btn-primary" id="eth3">3 · ${esc(t('agent.modal.submit'))}</button>
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
            const accs = await eth.request({ method: 'eth_requestAccounts' });
            const agent = (accs[0] || '').toLowerCase();
            if (!/^0x[0-9a-fA-F]{40}$/.test(agent)) throw new Error('address');
            root.querySelector('#ethAgent').value = agent;
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
            toast('ok', 'ok');
          } catch (e) {
            toast(t('common.error', { msg: e.message }), 'err');
          } finally {
            setLoading(b, false);
          }
        };
        root.querySelector('#eth3').onclick = async (ev) => {
          const agent = root.querySelector('#ethAgent').value.trim();
          const tcp = root.querySelector('#ethTcp').value.trim();
          if (!ethOpSeedHex || !ethDelMessage || !ethSigHex || !agent) return;
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
    openModal({
      title: t('service.modal.title'),
      wide: true,
      body: `
        ${single ? '' : `<div class="field"><label>${esc(t('service.modal.agent_pick'))}</label><select id="svAid">${agentList.map((a) => `<option value="${esc(a.aid)}" ${a.aid === editAid ? 'selected' : ''}>${esc(shortAid(a.aid))}</option>`).join('')}</select></div>`}
        <div class="field">
          <label>${esc(t('service.modal.import.label'))}</label>
          <div style="display:flex;gap:.35rem;flex-wrap:wrap">
            <input type="url" id="svUrl" style="flex:1;min-width:12rem" placeholder="${esc(t('service.modal.import.placeholder'))}" />
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
}
