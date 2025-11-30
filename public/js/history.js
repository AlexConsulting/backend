// public/js/history.js
// Loads full history and handles detail modal

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

document.addEventListener('DOMContentLoaded', async () => {
  const tbody = document.querySelector('#tblHistory tbody');

  try {
    const history = await apiGet('/history/list');

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