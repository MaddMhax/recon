// ====================================================================
// Profil utilisateur partagé (app + admin) : helpers couleur/avatar et
// menu "Personnaliser" (couleur + photo de profil).
// ====================================================================

let PROFILE_USER = null;     // current user object ({ _id, email, color, hasAvatar, updatedAt })
let PROFILE_ON_SAVE = null;  // optional callback(updatedUser) after a successful save
let profileMenuBuilt = false;
let profilePending;          // undefined = unchanged, null = remove, string = new data URL

// ---- Color / avatar helpers (shared with presence rendering) ----
function shortName(email) { return String(email || '').split('@')[0]; }
function initials(email) {
  const n = shortName(email).replace(/[^a-zA-Z0-9]/g, '');
  return (n.slice(0, 2) || '?').toUpperCase();
}
function colorFor(email) {
  let h = 0;
  for (let i = 0; i < String(email).length; i++) h = (h * 31 + email.charCodeAt(i)) % 360;
  return `hsl(${h} 60% 45%)`;
}
function avatarVersionOf(u) {
  return u.avatarVersion || (u.updatedAt ? Date.parse(u.updatedAt) : 0) || 0;
}
function avatarUrlOf(u) {
  return `/api/users/${u.id || u._id}/avatar?v=${avatarVersionOf(u)}`;
}
// Renders a presence/profile chip: avatar image when present, else colored initials.
function chipHtml(u, cls) {
  const title = esc(u.email || '');
  if (u.hasAvatar) {
    return `<img class="${cls}" src="${avatarUrlOf(u)}" alt="" title="${title}" loading="lazy" />`;
  }
  const c = u.color || colorFor(u.email || '');
  return `<span class="${cls}" style="background:${c}" title="${title}">${esc(initials(u.email || ''))}</span>`;
}

// Wire the header user button + build the "Personnaliser" popover. Call once the
// current user is known (both on the app page and the admin page).
function initProfileMenu(user, onSave) {
  PROFILE_USER = user;
  PROFILE_ON_SAVE = onSave || null;
  renderHeaderUser();
  buildProfileMenu();
}

function renderHeaderUser() {
  const nu = document.getElementById('navUser');
  const na = document.getElementById('navAvatar');
  if (nu) nu.textContent = PROFILE_USER.email;
  if (na) na.innerHTML = chipHtml(PROFILE_USER, 'pchip pchip-sm');
}

function buildProfileMenu() {
  if (profileMenuBuilt) return;
  profileMenuBuilt = true;

  const menu = document.createElement('div');
  menu.id = 'profileMenu';
  menu.className = 'popover hidden';
  menu.innerHTML = `
    <h3>Personnaliser</h3>
    <label>Couleur</label>
    <div class="row"><input type="color" id="pmColor" /><span class="muted small" id="pmColorHex"></span></div>
    <label>Photo de profil <span class="muted">(JPEG / PNG, max 2 Mo)</span></label>
    <div class="row">
      <span id="pmPreview" class="pchip pchip-lg"></span>
      <input type="file" id="pmFile" accept="image/png,image/jpeg" />
    </div>
    <div class="row" style="margin-top:12px">
      <button id="pmSave" type="button">Enregistrer</button>
      <button class="secondary" id="pmRemove" type="button">Retirer la photo</button>
    </div>
    <div class="error" id="pmError"></div>`;
  document.body.appendChild(menu);

  const btn = document.getElementById('profileBtn');
  if (btn) {
    btn.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); toggleProfileMenu(); });
  }
  document.addEventListener('click', (e) => {
    if (!menu.classList.contains('hidden') && !menu.contains(e.target) && (!btn || !btn.contains(e.target))) {
      menu.classList.add('hidden');
    }
  });

  const colorInput = menu.querySelector('#pmColor');
  colorInput.addEventListener('input', () => {
    menu.querySelector('#pmColorHex').textContent = colorInput.value;
    updateProfilePreview();
  });

  menu.querySelector('#pmFile').addEventListener('change', (e) => {
    const errEl = menu.querySelector('#pmError');
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
    reader.onload = () => { profilePending = reader.result; updateProfilePreview(); };
    reader.readAsDataURL(f);
  });

  menu.querySelector('#pmRemove').addEventListener('click', () => {
    profilePending = null;
    menu.querySelector('#pmFile').value = '';
    updateProfilePreview();
  });

  menu.querySelector('#pmSave').addEventListener('click', saveProfile);
}

function toggleProfileMenu() {
  const menu = document.getElementById('profileMenu');
  if (!menu) return;
  if (menu.classList.contains('hidden')) openProfileMenu();
  else menu.classList.add('hidden');
}

function openProfileMenu() {
  const menu = document.getElementById('profileMenu');
  profilePending = undefined;
  menu.querySelector('#pmError').textContent = '';
  menu.querySelector('#pmFile').value = '';
  const color = PROFILE_USER.color || colorFor(PROFILE_USER.email);
  const hex = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#4ade80';
  menu.querySelector('#pmColor').value = hex;
  menu.querySelector('#pmColorHex').textContent = hex;
  updateProfilePreview();
  menu.classList.remove('hidden');
}

function updateProfilePreview() {
  const menu = document.getElementById('profileMenu');
  const p = menu.querySelector('#pmPreview');
  const color = menu.querySelector('#pmColor').value;
  let url = null;
  if (typeof profilePending === 'string') url = profilePending;
  else if (profilePending === undefined && PROFILE_USER.hasAvatar) url = avatarUrlOf(PROFILE_USER);
  if (url) {
    p.style.backgroundImage = `url("${url}")`;
    p.style.backgroundColor = '';
    p.textContent = '';
  } else {
    p.style.backgroundImage = '';
    p.style.backgroundColor = color;
    p.textContent = initials(PROFILE_USER.email);
  }
}

async function saveProfile() {
  const menu = document.getElementById('profileMenu');
  const errEl = menu.querySelector('#pmError');
  errEl.textContent = '';
  const body = { color: menu.querySelector('#pmColor').value };
  if (profilePending !== undefined) body.avatar = profilePending; // string (new) or null (remove)
  try {
    const { user } = await api.patch('/api/auth/me', body);
    PROFILE_USER = user;
    renderHeaderUser();
    if (PROFILE_ON_SAVE) PROFILE_ON_SAVE(user);
    menu.classList.add('hidden');
    toast('Profil mis à jour');
  } catch (err) {
    errEl.textContent = err.message;
  }
}
