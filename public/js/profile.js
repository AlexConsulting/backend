// public/js/profile.js
// Loads user profile data, allows name change and password update

async function apiGet(url) {
  const resp = await fetch(url, { credentials: 'include' });
  if (!resp.ok) throw new Error('API error');
  return resp.json();
}

async function apiPost(url, data) {
  const resp = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {})
  });
  if (!resp.ok) throw new Error('API error');
  return resp.json();
}

async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  window.location.href = '/login.html';
}

function formatDate(ts) {
  if (!ts) return "-";
  return new Date(ts).toLocaleString('pt-BR');
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const user = await apiGet('/auth/session');
    const plan = await apiGet('/plans/current');
    const quota = await apiGet('/quota/current');

    // Fill static fields
    document.getElementById('userName').textContent = user.name;
    document.getElementById('userEmail').textContent = user.email;
    document.getElementById('userPlan').textContent = plan.plan_name.toUpperCase();
    document.getElementById('userQuota').textContent = `${quota.used} / ${quota.limit}`;
    document.getElementById('userCreated').textContent = formatDate(user.created_at);
    document.getElementById('userLastLogin').textContent = formatDate(user.last_login);

    // === Update name ===
    document.getElementById('btnUpdateName').addEventListener('click', async () => {
      const newName = document.getElementById('newName').value.trim();
      const out = document.getElementById('nameOut');

      if (newName.length < 2) {
        out.textContent = "Nome muito curto";
        out.style.color = "#e74c3c";
        return;
      }

      try {
        const r = await apiPost('/profile/update', { name: newName });
        if (r.success) {
          out.textContent = "Nome atualizado com sucesso!";
          out.style.color = "#2ecc71";
          document.getElementById('userName').textContent = newName;
        } else {
          out.textContent = "Falha ao atualizar nome";
          out.style.color = "#e74c3c";
        }
      } catch (err) {
        out.textContent = "Erro no servidor";
        out.style.color = "#e74c3c";
      }
    });

    // === Change password ===
    document.getElementById('btnChangePw').addEventListener('click', async () => {
      const pw1 = document.getElementById('pw1').value;
      const pw2 = document.getElementById('pw2').value;
      const out = document.getElementById('pwOut');

      if (pw1.length < 8) {
        out.textContent = "A senha deve ter no mínimo 8 caracteres";
        out.style.color = "#e74c3c";
        return;
      }
      if (pw1 !== pw2) {
        out.textContent = "As senhas não coincidem";
        out.style.color = "#e74c3c";
        return;
      }

      try {
        const r = await apiPost('/auth/password/change', { password: pw1 });
        if (r.success) {
          out.textContent = "Senha alterada com sucesso!";
          out.style.color = "#2ecc71";
          document.getElementById('pw1').value = "";
          document.getElementById('pw2').value = "";
        } else {
          out.textContent = "Falha ao alterar senha";
          out.style.color = "#e74c3c";
        }
      } catch (err) {
        out.textContent = "Erro no servidor";
        out.style.color = "#e74c3c";
      }
    });

  } catch (err) {
    console.error(err);
    window.location.href = '/login.html';
  }
});
