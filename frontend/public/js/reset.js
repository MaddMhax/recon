// Password reset page — driven by the ?token=... in the URL.
const token = new URLSearchParams(window.location.search).get('token');
const intro = document.getElementById('resetIntro');
const form = document.getElementById('resetForm');
const errEl = document.getElementById('resetError');

async function init() {
  if (!token) {
    intro.textContent = 'Lien invalide : aucun token fourni.';
    return;
  }
  try {
    const { email } = await api.get(`/api/auth/reset/${encodeURIComponent(token)}`);
    intro.textContent = `Choisissez un nouveau mot de passe pour ${email}.`;
    form.classList.remove('hidden');
  } catch (err) {
    intro.textContent = err.message || 'Lien invalide ou expiré.';
  }
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errEl.textContent = '';
  const pwd = document.getElementById('pwd').value;
  const pwd2 = document.getElementById('pwd2').value;
  if (pwd !== pwd2) { errEl.textContent = 'Les mots de passe ne correspondent pas.'; return; }
  if (pwd.length < 8) { errEl.textContent = 'Au moins 8 caractères.'; return; }
  try {
    await api.post('/api/auth/reset', { token, password: pwd });
    form.classList.add('hidden');
    intro.classList.add('hidden');
    document.getElementById('resetDone').classList.remove('hidden');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

init();
