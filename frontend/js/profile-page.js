// ====================================================================
// Page /profile : apparence (couleur + photo) et changement de mot de passe.
// ====================================================================

let ME = null;
// undefined = avatar unchanged, null = remove, string = new data URL.
let avatarPending;

async function initProfilePage() {
  try {
    const { user } = await api.get('/api/auth/me');
    ME = user;
  } catch (_) {
    window.location.href = '/'; // not logged in
    return;
  }

  if (ME.role === 'admin') document.getElementById('navAdmin').classList.remove('hidden');
  initProfileMenu(ME); // header chip + button
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    await api.post('/api/auth/logout');
    window.location.href = '/';
  });

  const sso = !!ME.ssoProvider;
  document.getElementById('accountLine').textContent =
    `${ME.email} · ${ME.role === 'admin' ? 'Administrateur' : 'Auditeur'}${sso ? ' · SSO' : ''}`;

  initAppearance();
  initPassword(sso);
}

// ---- Apparence ----------------------------------------------------
function initAppearance() {
  const color = ME.color || colorFor(ME.email);
  const hex = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#4ade80';
  const colorInput = document.getElementById('pmColor');
  colorInput.value = hex;
  document.getElementById('pmColorHex').textContent = hex;
  avatarPending = undefined;
  drawAvatarPreview();

  colorInput.addEventListener('input', () => {
    document.getElementById('pmColorHex').textContent = colorInput.value;
    drawAvatarPreview();
  });

  document.getElementById('pmFile').addEventListener('change', (e) => {
    const errEl = document.getElementById('pmError');
    errEl.textContent = '';
    const f = e.target.files[0];
    if (!f) return;
    if (!['image/png', 'image/jpeg'].includes(f.type)) {
      errEl.textContent = 'Seuls les fichiers JPEG et PNG sont acceptés.';
      e.target.value = '';
      return;
    }
    if (f.size > 2 * 1024 * 1024) {
      errEl.textContent = 'Image trop volumineuse (max 2 Mo).';
      e.target.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => { avatarPending = reader.result; drawAvatarPreview(); };
    reader.readAsDataURL(f);
  });

  document.getElementById('pmRemove').addEventListener('click', () => {
    avatarPending = null;
    document.getElementById('pmFile').value = '';
    drawAvatarPreview();
  });

  document.getElementById('pmSave').addEventListener('click', saveAppearance);
}

function drawAvatarPreview() {
  const p = document.getElementById('pmPreview');
  const color = document.getElementById('pmColor').value;
  let url = null;
  if (typeof avatarPending === 'string') url = avatarPending;
  else if (avatarPending === undefined && ME.hasAvatar) url = avatarUrlOf(ME);
  if (url) {
    p.style.backgroundImage = `url("${url}")`;
    p.style.backgroundColor = '';
    p.textContent = '';
  } else {
    p.style.backgroundImage = '';
    p.style.backgroundColor = color;
    p.textContent = initials(ME.email);
  }
}

async function saveAppearance() {
  const errEl = document.getElementById('pmError');
  errEl.textContent = '';
  const body = { color: document.getElementById('pmColor').value };
  if (avatarPending !== undefined) body.avatar = avatarPending; // string (new) or null (remove)
  try {
    const { user } = await api.patch('/api/auth/me', body);
    ME = user;
    avatarPending = undefined;
    document.getElementById('pmFile').value = '';
    renderHeaderUser(); // refresh the header chip
    drawAvatarPreview();
    toast('Profil mis à jour');
  } catch (err) {
    errEl.textContent = err.message;
  }
}

// ---- Sécurité (mot de passe) --------------------------------------
function initPassword(sso) {
  // SSO-provisioned accounts have no password the user knows — hide the form.
  if (sso) {
    document.getElementById('passwordForm').style.display = 'none';
    document.getElementById('ssoPwNote').style.display = '';
    return;
  }

  document.getElementById('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const errEl = document.getElementById('pwError');
    errEl.textContent = '';
    const cur = document.getElementById('curPwd').value;
    const nw = document.getElementById('newPwd').value;
    const nw2 = document.getElementById('newPwd2').value;
    if (nw !== nw2) { errEl.textContent = 'Les deux mots de passe ne correspondent pas.'; return; }
    if (nw.length < 8) { errEl.textContent = 'Le nouveau mot de passe doit faire au moins 8 caractères.'; return; }
    try {
      await api.post('/api/auth/me/password', { currentPassword: cur, newPassword: nw });
      e.target.reset();
      toast('Mot de passe mis à jour');
    } catch (err) {
      errEl.textContent = err.message;
    }
  });
}

initProfilePage();
