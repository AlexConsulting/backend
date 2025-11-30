// public/js/dashboard.js
// Handles dashboard data loading, history table and modal

async function apiGet(url) {
  const resp = await fetch(url, { credentials: 'include' });
  if (!resp.ok) throw new Error('API error');
  return resp.json();
}

async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  window.location.href = '/login.html';
}

function openModal(text) {
  document.getElementById('modalContent').textContent = text;
  document.getElementById('modalBg').style.display = 'flex';
}

function closeModal() {
  document.getElementById('modalBg').style.display = 'none';
}

// NOVA FUNÇÃO: carregar saudação
async function loadUserWelcome() {
  try {
    const user = await apiGet('/auth/session');
    document.getElementById('userWelcome').innerHTML =
      `Bem-vindo, <strong>${user.name}</strong><br><small>${user.email}</small>`;
  } catch {}
}

document.addEventListener('DOMContentLoaded', async () => {
  loadUserWelcome();

  const cardPlan = document.getElementById('card-plan');
  const cardQuota = document.getElementById('card-quota');
  const novaAnaliseBtn = document.getElementById('nova-analise-btn'); // Referência ao botão de Nova Análise
  const tbody = document.querySelector('#tblHistory tbody');
  const upgradeButton = document.getElementById('upgrade-button');

  try {
    const plan = await apiGet('/plans/current');
    const quota = await apiGet('/quota/current');
    const history = await apiGet('/history/list');

    cardPlan.textContent = `Plano atual: ${plan.plan_name.toUpperCase()}`;
    cardQuota.textContent = `Quota usada: ${quota.used} / ${quota.limit}`;

    // Verifica se a quota foi excedida
    if (quota.used >= quota.limit) {
      cardQuota.style.color = 'red';  // Cor vermelha para quota excedida
      upgradeButton.style.display = 'inline-block'; // Exibe o botão de upgrade
      novaAnaliseBtn.disabled = true;  // Desabilita o botão de nova análise
      novaAnaliseBtn.style.cursor = 'not-allowed';  // Muda o cursor para mostrar que está desabilitado
      novaAnaliseBtn.title = 'Quota atingida! Faça upgrade do seu plano.';  // Tooltip informando sobre a quota
      alert('Quota atingida! Faça upgrade do seu plano.');
      
      // Previne o redirecionamento quando a quota for atingida
      novaAnaliseBtn.addEventListener('click', (event) => {
        event.preventDefault();  // Impede o redirecionamento
        alert('Você não pode realizar novas análises. Faça upgrade do seu plano.');
      });
    }

    tbody.innerHTML = '';
    history.forEach(h => {
      const tr = document.createElement('tr');
      const date = new Date(h.timestamp).toLocaleString('pt-BR');

      tr.innerHTML = `
        <td>${date}</td>
        <td>${h.query}</td>
        <td>${h.type}</td>
        <td><button data-id="${h.id}" class="btnDetails">Detalhes</button></td>
      `;
      tbody.appendChild(tr);
    });

    document.querySelectorAll('.btnDetails').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = btn.getAttribute('data-id');
        const detail = await apiGet(`/history/item?id=${id}`);
        openModal(detail.result || JSON.stringify(detail, null, 2));
      });
    });

  } catch (err) {
    console.error(err);
    window.location.href = '/login.html';
  }
});
