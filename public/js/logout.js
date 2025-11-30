// Detecta se o dispositivo é mobile
const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

if (isMobile) {
  // Para dispositivos móveis, faz o logout no frontend (limpando o cookie)
  document.getElementById('mobileLogoutButton').addEventListener('click', () => {
    // Simula o logout no frontend, limpando o cookie localmente
    document.cookie = "user_id=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    
    // Redireciona para a página de login
    window.location.href = '/login.html';
  });
} else {
  // Para desktop, faz a requisição POST para o backend
  document.getElementById('logoutButton').addEventListener('click', async () => {
    try {
      // Faz a requisição POST para o logout no backend
      const response = await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'include' // Certifique-se de enviar o cookie de sessão
      });

      // Após o logout, redireciona para a página de login
      window.location.href = '/login.html';
    } catch (error) {
      console.error('Erro ao realizar logout:', error);
    }
  });
}
