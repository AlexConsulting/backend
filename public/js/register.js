// public/js/register.js
document.addEventListener('DOMContentLoaded', () => {
  const nameInput = document.getElementById('name');
  const emailInput = document.getElementById('email');
  const passInput = document.getElementById('password');
  const pass2Input = document.getElementById('password2');
  const btn = document.getElementById('btnRegister');
  const out = document.getElementById('out');

  btn.addEventListener('click', async () => {
    out.innerHTML = '';

    const name = (nameInput.value || '').trim();
    const email = (emailInput.value || '').trim();
    const pw = (passInput.value || '').trim();
    const pw2 = (pass2Input.value || '').trim();

    if (!name) {
      out.innerHTML = '<span style="color:#f39c12">Informe seu nome completo</span>';
      return;
    }
    if (!email) {
      out.innerHTML = '<span style="color:#f39c12">Informe um e-mail</span>';
      return;
    }
    if (pw.length < 8) {
      out.innerHTML = '<span style="color:#f39c12">A senha deve ter ao menos 8 caracteres</span>';
      return;
    }
    if (pw !== pw2) {
      out.innerHTML = '<span style="color:#f39c12">As senhas não coincidem</span>';
      return;
    }

    out.innerHTML = 'Criando conta...';

    try {
      const resp = await fetch('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password: pw })
      });

      const j = await resp.json();
      if (!resp.ok) {
        out.innerHTML = `<span style="color:#e74c3c">Erro: ${j.error || 'falha ao registrar'}</span>`;
        return;
      }

      out.innerHTML = '<span style="color:#2ecc71">Conta criada com sucesso!</span>';

      setTimeout(() => {
        window.location.href = '/login.html';
      }, 1200);

    } catch (err) {
      out.innerHTML = '<span style="color:#e74c3c">Erro ao conectar</span>';
    }
  });
});