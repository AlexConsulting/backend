// public/js/plans.js
// Loads available plans and handles upgrade flow

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

document.addEventListener('DOMContentLoaded', async () => {
  const area = document.getElementById('plansArea');

  try {
    const current = await apiGet('/plans/current');
    const plans = await apiGet('/plans/list');

    area.innerHTML = '';

    plans.forEach(p => {
      const div = document.createElement('div');
      div.className = 'plan-card';

      const isCurrent = p.id === current.plan_id;

      div.innerHTML = `
        <div class="plan-title">${p.name.toUpperCase()}</div>
        <div class="quota">${p.quota} consultas</div>
        ${isCurrent ? `<div style='margin-top:18px;color:#2ecc71;font-weight:600'>PLANO ATUAL</div>` : `
          <button class="btn-upgrade" data-plan="${p.id}">Upgrade</button>
        `}
      `;

      area.appendChild(div);
    });

    // Bind upgrade buttons
    document.querySelectorAll('.btn-upgrade').forEach(btn => {
      btn.addEventListener('click', async () => {
        const planId = btn.getAttribute('data-plan');

        try {
          const result = await apiPost('/plans/upgrade', { plan_id: planId });

          if (result.success) {
            alert('Plano atualizado com sucesso!');
            location.reload();
          } else {
            alert('Falha ao atualizar o plano.');
          }
        } catch (err) {
          console.error(err);
          alert('Erro ao processar upgrade.');
        }
      });
    });

  } catch (err) {
    console.error(err);
    window.location.href = '/login.html';
  }
});