// public/js/forgot.js
document.addEventListener('DOMContentLoaded', () => {
  const emailInput = document.getElementById('email');
  const btn = document.getElementById('btnSend');
  const out = document.getElementById('out');
  const devMode = document.getElementById('devMode');

  btn.addEventListener('click', async () => {
    out.innerHTML = 'Enviando...';
    const email = (emailInput.value || '').trim();
    if (!email) { out.innerHTML = '<span style="color:#f39c12">Informe um e-mail válido</span>'; return; }

    try {
      const resp = await fetch('/auth/password/forgot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, mode: devMode.checked ? 'dev' : 'prod' })
      });
      const j = await resp.json();
      if (!resp.ok) {
        out.innerHTML = `<span style="color:#e74c3c">Erro: ${j.error || 'falha'}</span>`;
        return;
      }
      // If dev token returned, show it
      if (j.dev_token) {
        out.innerHTML = `<div><strong>Token (DEV mode):</strong></div>
          <pre>${j.dev_token}</pre>
          <div><a href="${j.reset_url}" target="_blank">Abrir link de reset</a></div>
          <div style="margin-top:8px;color:#9aa4b2">Token expira em: ${j.expires_at}</div>`;
      } else {
        out.innerHTML = `<div style="color:#2ecc71">Se o e-mail existir, um link foi enviado (verifique sua caixa).</div>`;
      }
    } catch (err) {
      out.innerHTML = `<span style="color:#e74c3c">Erro ao enviar</span>`;
    }
  });
});
