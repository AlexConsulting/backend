// public/js/login.js
document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const passInput = document.getElementById('password');
  const btn = document.getElementById('btnLogin');
  const out = document.getElementById('out');

  btn.addEventListener('click', async () => {
    out.innerHTML = 'Autenticando...';

    const email = (emailInput.value || '').trim();
    const password = (passInput.value || '').trim();

    if (!email || !password) {
      out.innerHTML = '<span style="color:#f39c12">Informe e-mail e senha</span>';
      return;
    }

    try {
      const resp = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const j = await resp.json();
      if (!resp.ok || !j.success) {
        out.innerHTML = `<span style="color:#e74c3c">Erro: ${j.msg || 'falha'}</span>`;
        return;
      }

      out.innerHTML = '<span style="color:#2ecc71">Login bem-sucedido</span>';

      setTimeout(() => {
        window.location.href = '/dashboard.html';
      }, 800);

    } catch (err) {
      out.innerHTML = '<span style="color:#e74c3c">Erro ao conectar</span>';
    }
  });
});
