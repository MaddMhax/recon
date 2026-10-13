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
    redirectToLogin(); // session gone since the page was served
    return;
  }
  markAuthenticated();

  if (ME.role === 'admin') document.getElementById('navAdmin').classList.remove('hidden');
  initProfileMenu(ME); // header chip + button
  document.getElementById('logoutBtn').addEventListener('click', async () => {
    try { await api.post('/api/auth/logout'); } catch (_) { /* leave anyway */ }
    window.location.replace('/login');
  });

  const sso = !!ME.ssoProvider;
  document.getElementById('accountLine').textContent =
    `${ME.email} · ${ME.role === 'admin' ? 'Administrateur' : 'Auditeur'}${sso ? ' · SSO' : ''}`;

  initAppearance();
  initPassword(sso);
  initSsoLink();
}

// ---- Connexion SSO (liaison du compte) -----------------------------
async function initSsoLink() {
  const panel = document.getElementById('ssoPanel');
  const errEl = document.getElementById('ssoLinkError');
  // Outcome of a linking round-trip (?sso=linked / ?sso_error=...).
  const params = new URLSearchParams(window.location.search);
  if (params.get('sso') === 'linked') toast('Compte lié au SSO');
  if (params.get('sso_error')) errEl.textContent = params.get('sso_error');
  if (params.has('sso') || params.has('sso_error')) window.history.replaceState({}, '', window.location.pathname);

  let status = null;
  try { status = await api.get('/api/auth/sso/status'); } catch (_) { /* SSO unavailable */ }
  if (!status || !status.enabled) return;
  panel.classList.remove('hidden');

  const draw = () => {
    document.getElementById('ssoStatus').textContent = ME.ssoLinked
      ? `Votre compte est lié à votre identité ${status.label ? `(« ${status.label} »)` : 'SSO'}. Vous pouvez vous connecter par le SSO.`
      : "Votre compte n'est pas lié au SSO. Liez-le pour pouvoir vous connecter avec votre fournisseur d'identité.";
    document.getElementById('ssoLinkBtn').classList.toggle('hidden', !!ME.ssoLinked);
    // SSO-provisioned accounts cannot unlink (they have no password).
    document.getElementById('ssoUnlinkBtn').classList.toggle('hidden', !ME.ssoLinked || !!ME.ssoProvider);
  };
  draw();

  document.getElementById('ssoLinkBtn').addEventListener('click', async () => {
    errEl.textContent = '';
    try {
      const { url } = await api.post('/api/auth/sso/link');
      window.location.assign(url);
    } catch (err) { errEl.textContent = err.message; }
  });
  document.getElementById('ssoUnlinkBtn').addEventListener('click', async () => {
    if (!confirm('Délier votre compte du SSO ? Vous vous connecterez par mot de passe.')) return;
    errEl.textContent = '';
    try { ME = (await api.post('/api/auth/sso/unlink')).user; draw(); }
    catch (err) { errEl.textContent = err.message; }
  });
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
    // The declared type is only the file extension: check the real bytes and
    // that the browser can actually decode the picture before offering it.
    // (The server re-validates the full file structure regardless.)
    checkImageFile(f).then((problem) => {
      if (problem) {
        errEl.textContent = problem;
        e.target.value = '';
        return;
      }
      const reader = new FileReader();
      reader.onload = () => { avatarPending = reader.result; drawAvatarPreview(); };
      reader.readAsDataURL(f);
    });
  });

  document.getElementById('pmRemove').addEventListener('click', () => {
    avatarPending = null;
    document.getElementById('pmFile').value = '';
    drawAvatarPreview();
  });

  document.getElementById('pmSave').addEventListener('click', saveAppearance);
}

const MAX_AVATAR_SIDE = 8192; // same cap as the server (lib/image.js)

// Returns null when the file starts with a PNG/JPEG signature and decodes as
// an image within the size cap, otherwise the message to show.
async function checkImageFile(f) {
  const invalid = "Fichier invalide : ce n'est pas une image JPEG ou PNG valide.";
  try {
    const b = new Uint8Array(await f.slice(0, 8).arrayBuffer());
    const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((v, i) => b[i] === v);
    const jpeg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
    if (!png && !jpeg) return invalid;
    const bmp = await createImageBitmap(f);
    const { width, height } = bmp;
    bmp.close();
    if (!width || !height) return invalid;
    if (width > MAX_AVATAR_SIDE || height > MAX_AVATAR_SIDE) {
      return `Image trop grande (${width}×${height} px, max ${MAX_AVATAR_SIDE} px de côté).`;
    }
    return null;
  } catch (_) {
    return invalid;
  }
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
