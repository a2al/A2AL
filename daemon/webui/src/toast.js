const DUR = { ok: 3000, warn: 4000, err: 5000, info: 4000 };

export function toast(msg, type = 'info', ms) {
  const el = document.getElementById('toasts');
  if (!el) return;
  const div = document.createElement('div');
  div.className = 'toast t-' + type;
  div.textContent = msg;
  el.appendChild(div);
  const t = ms != null ? ms : DUR[type] || DUR.info;
  setTimeout(() => {
    div.classList.add('fade');
    setTimeout(() => div.remove(), 350);
  }, t);
}
