// ====================================================================
// Profil utilisateur partagé (app + admin) : helpers couleur/avatar et
// câblage du bouton d'en-tête vers la page /profile.
// ====================================================================

let PROFILE_USER = null;     // current user object ({ _id, email, color, hasAvatar, updatedAt })

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

// Render the header user chip and point the header button at the /profile page.
// Call once the current user is known (on both the app and admin pages). The
// optional second argument is kept for backwards compatibility and ignored.
function initProfileMenu(user) {
  PROFILE_USER = user;
  renderHeaderUser();
  const btn = document.getElementById('profileBtn');
  if (btn) {
    btn.title = 'Mon profil';
    btn.addEventListener('click', (e) => { e.preventDefault(); window.location.href = '/profile'; });
  }
}

function renderHeaderUser() {
  const nu = document.getElementById('navUser');
  const na = document.getElementById('navAvatar');
  if (nu) nu.textContent = PROFILE_USER.email;
  if (na) na.innerHTML = chipHtml(PROFILE_USER, 'pchip pchip-sm');
}
