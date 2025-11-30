// public/js/reset.js
document.addEventListener('DOMContentLoaded', () => {
  const tokenInput = document.getElementById('token');
  const pw = document.getElementById('password');
  const pw2 = document.getElementById('password2');
  const btn = document.getElementById('btnReset');
  const out = document.getElementById('out');

  // Fill token from query string if present
  try {
    const qs = new URLSearchParams(window.location.search);
    const t = qs.get('token');
    if (t) tokenInput.value = t;
  } catch (e) {}

  btn.addEventListener('click', async () => {
    out.innerHTML = 'Enviando...';
    const token = (tokenInput.value || '').trim();
    const newpw = (pw.value || '').trim();
    const newpw2 = (pw2.value || '').trim();
    if (!token) { out.innerHTML = '<span style="color:#f39c12">Token ausente</span>'; return; }
    if (newpw.length < 8) { out.innerHTML = '<span style="color:#f39c12">Senha muito curta</span>'; return; }
    if (newpw !== newpw2) { out.innerHTML = '<span style="color:#f39c12">Senhas não conferem</span>'; return; }

    try {
      const resp = await fetch('/auth/password/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: newpw })
      });
      const j = await resp.json();
      if (!resp.ok) {
        out.innerHTML = `<span style="color:#e74c3c">Erro: ${j.error || 'falha'}</span>`;
        return;
      }
      out.innerHTML = `<div style="color:#2ecc71">Senha redefinida com sucesso. Faça login.</div>`;
      setTimeout(() => { window.location.href = '/login.html'; }, 2000);
    } catch (err) {
      out.innerHTML = `<span style="color:#e74c3c">Erro ao redefinir</span>`;
    }
  });
});
