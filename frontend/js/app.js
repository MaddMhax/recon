// ====================================================================
// Recon — application principale (gestion des projets)
// ====================================================================

let currentUser = null;
const main = () => document.getElementById('appMain');

// ---- Realtime collaboration state ----
let socket = null;
let currentProject = null;     // the project currently open (in-memory copy)
let currentProjectId = null;
let presenceUsers = [];        // [{ socketId, id, email, focus }]
let pendingRedraw = false;     // a remote change arrived while we were typing

// ---- Bootstrap : vérifie la session ----
async function init() {
  try {
    const { user } = await api.get('/api/auth/me');
    currentUser = user;
    showApp();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  document.getElementById('loginView').classList.remove('hidden');
  document.getElementById('appView').classList.add('hidden');
  loadSsoButton();
  showSsoError();
}

// Show a "Login with SSO" button (with the provider logo) when SSO is enabled.
async function loadSsoButton() {
  const area = document.getElementById('ssoArea');
  if (!area) return;
  try {
    const s = await api.get('/api/auth/sso/status');
    if (!s || !s.enabled) { area.classList.add('hidden'); area.innerHTML = ''; return; }
    area.innerHTML = `
      <div class="sso-divider"><span>ou</span></div>
      <a class="sso-btn" href="/api/auth/sso/login">${ssoLogo(s.provider)}<span>${esc(s.label || 'Se connecter via SSO')}</span></a>`;
    area.classList.remove('hidden');
  } catch (_) {
    area.classList.add('hidden');
  }
}

// Surface an SSO error handed back as ?sso_error=... on the login screen.
function showSsoError() {
  const err = new URLSearchParams(window.location.search).get('sso_error');
  if (!err) return;
  const el = document.getElementById('loginError');
  if (el) el.textContent = err;
  window.history.replaceState({}, '', window.location.pathname); // clean the URL
}

function showApp() {
  document.getElementById('loginView').classList.add('hidden');
  document.getElementById('appView').classList.remove('hidden');
  if (currentUser.role === 'admin') {
    document.getElementById('navAdmin').classList.remove('hidden');
  }
  // Shared "Personnaliser" menu (profile.js). Keep currentUser in sync and
  // push the change to collaborators in real time.
  initProfileMenu(currentUser, (user) => {
    currentUser = user;
    if (socket) socket.emit('profile', { color: user.color, hasAvatar: user.hasAvatar });
  });
  connectRealtime();
  renderProjectList();
}

// ---- Connexion ----
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errEl = document.getElementById('loginError');
  errEl.textContent = '';
  try {
    const { user } = await api.post('/api/auth/login', {
      email: document.getElementById('email').value,
      password: document.getElementById('password').value,
    });
    currentUser = user;
    showApp();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api.post('/api/auth/logout');
  currentUser = null;
  showLogin();
});

document.getElementById('navProjects').addEventListener('click', (e) => {
  e.preventDefault();
  renderProjectList();
});

// Brand (RECON_) in the top-left returns to the project list (SPA, no reload).
document.getElementById('brandHome').addEventListener('click', (e) => {
  e.preventDefault();
  renderProjectList();
});

// ====================================================================
// Liste des projets
// ====================================================================
async function renderProjectList() {
  currentProjectId = null;
  currentProject = null;
  presenceUsers = [];
  if (socket) socket.emit('leave');
  const { projects } = await api.get('/api/projects');
  main().innerHTML = `
    <div class="row">
      <h1>Projets d'audit</h1>
      <div class="spacer"></div>
      <button id="newProjectBtn">+ Nouveau projet</button>
    </div>
    <p class="subtitle">Suivez l'avancement des vérifications de vulnérabilités pour chaque mission.</p>
    <div id="newProjectForm" class="panel hidden">
      <h2>Nouveau projet</h2>
      <label>Nom du projet *</label>
      <input id="npName" placeholder="Audit application X" />
      <label>Périmètre (cibles, URLs, IPs)</label>
      <textarea id="npScope" placeholder="https://app.exemple.com&#10;192.168.1.0/24"></textarea>
      <label>Notes</label>
      <textarea id="npNotes"></textarea>
      <div class="row" style="margin-top:12px">
        <button id="npCreate">Créer le projet</button>
        <button class="secondary" id="npCancel">Annuler</button>
      </div>
      <div class="error" id="npError"></div>
    </div>
    <div class="grid" id="projectGrid"></div>
  `;

  const grid = document.getElementById('projectGrid');
  if (!projects.length) {
    grid.innerHTML = `<p class="muted">Aucun projet pour le moment. Créez-en un pour commencer.</p>`;
  } else {
    grid.innerHTML = projects.map((p) => {
      const pct = p.progress.total ? Math.round((p.progress.done / p.progress.total) * 100) : 0;
      return `
        <div class="project-card" data-id="${p._id}">
          <div class="row">
            <h3>${esc(p.name)}</h3>
            <div class="spacer"></div>
            <span class="badge status-${p.status === 'completed' ? 'pass' : 'in_progress'}">
              ${esc(PROJECT_STATUS_LABELS[p.status] || p.status)}
            </span>
          </div>
          <div class="meta">${p.progress.done}/${p.progress.total} vérifiés · ${p.progress.findings} vulnérabilité(s)</div>
          <div class="progress-bar"><span style="width:${pct}%"></span></div>
        </div>`;
    }).join('');
    grid.querySelectorAll('.project-card').forEach((c) =>
      c.addEventListener('click', () => renderProjectDetail(c.dataset.id))
    );
  }

  // Form toggling
  const form = document.getElementById('newProjectForm');
  document.getElementById('newProjectBtn').addEventListener('click', () => form.classList.toggle('hidden'));
  document.getElementById('npCancel').addEventListener('click', () => form.classList.add('hidden'));
  document.getElementById('npCreate').addEventListener('click', async () => {
    const errEl = document.getElementById('npError');
    errEl.textContent = '';
    try {
      await api.post('/api/projects', {
        name: document.getElementById('npName').value,
        scope: document.getElementById('npScope').value,
        notes: document.getElementById('npNotes').value,
      });
      renderProjectList();
    } catch (err) {
      errEl.textContent = err.message;
    }
  });
}

// ====================================================================
// Détail d'un projet + checklist
// ====================================================================
async function renderProjectDetail(id) {
  currentProjectId = id;
  if (socket) socket.emit('join', id);
  const { project } = await api.get(`/api/projects/${id}`);
  currentProject = project;

  main().innerHTML = `
    <div class="row">
      <a href="#" id="backLink">← Projets</a>
    </div>
    <div class="row" style="margin-top:8px">
      <h1>${esc(project.name)}</h1>
      <div class="spacer"></div>
      <button class="secondary small" id="editProjectBtn">Modifier</button>
      <button class="secondary small" id="resyncBtn">Synchroniser le référentiel</button>
      <button class="danger small" id="deleteProjectBtn">Supprimer</button>
    </div>
    <p class="subtitle">${esc(PROJECT_STATUS_LABELS[project.status] || project.status)}</p>

    <div class="presence" id="presenceBar"></div>

    <div id="editProjectForm" class="panel hidden">
      <label>Nom</label>
      <input id="epName" value="${esc(project.name)}" />
      <label>Statut</label>
      <select id="epStatus">
        ${Object.entries(PROJECT_STATUS_LABELS).map(([k, v]) =>
          `<option value="${k}" ${project.status === k ? 'selected' : ''}>${v}</option>`).join('')}
      </select>
      <label>Périmètre</label>
      <textarea id="epScope">${esc(project.scope)}</textarea>
      <label>Notes</label>
      <textarea id="epNotes">${esc(project.notes)}</textarea>
      <div class="row" style="margin-top:12px">
        <button id="epSave">Enregistrer</button>
        <button class="secondary" id="epCancel">Annuler</button>
      </div>
    </div>

    <div class="stats" id="statsRow"></div>

    <div class="panel" id="varsPanel">
      <div class="row">
        <h2 style="margin:0">Variables</h2>
        <div class="spacer"></div>
        <button class="secondary small" id="varAdd">+ Ajouter</button>
      </div>
      <p class="muted small">Réutilisables dans les commandes via <code>$NOM</code> ou <code>\${NOM}</code> (ex. <code>$SCOPE</code>).</p>
      <div id="varRows"></div>
      <div class="row" style="margin-top:8px"><button class="small" id="varSave">Enregistrer les variables</button></div>
    </div>

    <div id="checklist" style="margin-top:16px"></div>
  `;
  project.variables = project.variables || [];
  renderStats(project);
  renderVariables(id, project);
  renderPresence();

  document.getElementById('backLink').addEventListener('click', (e) => { e.preventDefault(); renderProjectList(); });
  document.getElementById('deleteProjectBtn').addEventListener('click', async () => {
    if (!confirm('Supprimer définitivement ce projet ?')) return;
    await api.del(`/api/projects/${id}`);
    renderProjectList();
  });
  document.getElementById('resyncBtn').addEventListener('click', async () => {
    const r = await api.post(`/api/projects/${id}/resync`);
    toast(`${r.added} nouvel(le)(s) vérification(s) ajoutée(s)`);
    renderProjectDetail(id);
  });

  // Edit form
  const ef = document.getElementById('editProjectForm');
  document.getElementById('editProjectBtn').addEventListener('click', () => ef.classList.toggle('hidden'));
  document.getElementById('epCancel').addEventListener('click', () => ef.classList.add('hidden'));
  document.getElementById('epSave').addEventListener('click', async () => {
    await api.patch(`/api/projects/${id}`, {
      name: document.getElementById('epName').value,
      status: document.getElementById('epStatus').value,
      scope: document.getElementById('epScope').value,
      notes: document.getElementById('epNotes').value,
    });
    renderProjectDetail(id);
  });

  drawChecklist(id, project);
}

// Top summary numbers (recomputed in place, no full re-render).
function renderStats(project) {
  const total = project.checklist.length;
  const done = project.checklist.filter((c) => c.verified).length;
  const vuln = project.checklist.filter((c) => c.verified && c.vulnerable).length;
  const pct = total ? Math.round((done / total) * 100) : 0;
  document.getElementById('statsRow').innerHTML = `
    <div class="stat"><div class="n">${pct}%</div><div class="l">Avancement</div></div>
    <div class="stat"><div class="n">${vuln}</div><div class="l">Vulnérables</div></div>
    <div class="stat"><div class="n">${done}/${total}</div><div class="l">Vérifiées</div></div>
    <div class="stat"><div class="n">${total - done}</div><div class="l">Restantes</div></div>`;
}

// ---- Variables (encart projet) ----

// Build a { NAME: value } map from the project's variables (named entries only).
function buildVarMap(project) {
  const map = {};
  for (const v of (project.variables || [])) {
    if (v.name && v.name.trim()) map[v.name.trim()] = v.value || '';
  }
  return map;
}

// Replace $NAME and ${NAME} with their value; unknown variables are left as-is.
function applyVars(text, map) {
  if (!text) return text || '';
  return text.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, a, b) => {
    const key = a || b;
    return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : m;
  });
}

function renderVariables(projectId, project) {
  const rows = document.getElementById('varRows');
  rows.innerHTML = (project.variables.length ? project.variables : []).map((v, i) => `
    <div class="row var-row" data-i="${i}">
      <input class="var-name" placeholder="SCOPE" value="${esc(v.name)}" />
      <span class="muted">=</span>
      <input class="var-value" placeholder="https://mon.scope.fr" value="${esc(v.value)}" />
      <button class="danger small var-del" title="Supprimer">✕</button>
    </div>`).join('') || '<p class="muted small" style="margin:0">Aucune variable. Cliquez sur « + Ajouter ».</p>';

  rows.querySelectorAll('.var-row').forEach((row) => {
    const i = Number(row.dataset.i);
    row.querySelector('.var-name').addEventListener('input', (e) => {
      project.variables[i].name = e.target.value;
      refreshPreviews(project);
    });
    row.querySelector('.var-value').addEventListener('input', (e) => {
      project.variables[i].value = e.target.value;
      refreshPreviews(project);
    });
    row.querySelector('.var-del').addEventListener('click', () => {
      project.variables.splice(i, 1);
      renderVariables(projectId, project);
      refreshPreviews(project);
    });
  });

  document.getElementById('varAdd').onclick = () => {
    project.variables.push({ name: '', value: '' });
    renderVariables(projectId, project);
  };
  document.getElementById('varSave').onclick = async () => {
    const cleaned = project.variables.filter((v) => v.name && v.name.trim());
    await api.patch(`/api/projects/${projectId}`, { variables: cleaned });
    toast('Variables enregistrées');
  };
}

// Re-render only the command previews in place (keeps open panels open).
function refreshPreviews(project) {
  const map = buildVarMap(project);
  document.querySelectorAll('#checklist .check-item').forEach((el) => {
    const it = project.checklist.find((c) => c._id === el.dataset.itemId);
    const prev = el.querySelector('.cmd-preview');
    if (it && prev) prev.innerHTML = renderCommand(applyVars(it.command, map));
  });
}

function drawChecklist(projectId, project) {
  const container = document.getElementById('checklist');
  const items = project.checklist;

  if (!items.length) {
    container.innerHTML = `<p class="muted">Référentiel vide. Ajoutez des vulnérabilités dans l'administration.</p>`;
    return;
  }

  const vars = buildVarMap(project);

  // Group by category. The checklist array stays in the admin-defined order, so
  // items keep that order within each group; the categories themselves are
  // sorted alphabetically, with the catch-all "Autres" group last.
  const groups = [];
  const byCat = new Map();
  for (const it of items) {
    const cat = (it.category || '').trim() || 'Autres';
    let g = byCat.get(cat);
    if (!g) { g = { category: cat, items: [] }; byCat.set(cat, g); groups.push(g); }
    g.items.push(it);
  }
  groups.sort((a, b) => {
    if (a.category === 'Autres') return 1;
    if (b.category === 'Autres') return -1;
    return a.category.localeCompare(b.category, 'fr', { sensitivity: 'base' });
  });

  // Within each category, only checks marked "verified + not vulnerable" sink to
  // the bottom. Unverified, verified-but-undecided and vulnerable stay on top.
  const isSettled = (it) => it.verified && it.vulnerable === false;

  container.innerHTML = groups.map((g) => {
    const ordered = [
      ...g.items.filter((it) => !isSettled(it)),
      ...g.items.filter((it) => isSettled(it)),
    ];
    return `<section class="category-group">
      <h3>${esc(g.category)}</h3>
      ${ordered.map((it) => checkItemHTML(it, vars)).join('')}
    </section>`;
  }).join('');

  container.querySelectorAll('.check-item').forEach((el) => wireCheckItem(el, projectId, project));
  updateFocusBadges();
}

// Wire one check-item DOM node (shared by full render and single-node updates).
function wireCheckItem(el, projectId, project) {
  const itemId = el.dataset.itemId;
  // Re-sort + re-render the list and refresh the stats after a state change.
  const refresh = () => { renderStats(project); drawChecklist(projectId, project); };

  // Chevron: open / close "more details".
  el.querySelector('.ci-toggle').addEventListener('click', () => el.classList.toggle('expanded'));

  // "Verified" checkbox.
  el.querySelector('.chk-verified').addEventListener('change', async (e) => {
    await updateItem(projectId, project, itemId, { verified: e.target.checked });
    refresh();
  });

  // "Vulnerable / not vulnerable" segmented buttons (only when verified).
  el.querySelectorAll('.seg-vuln button').forEach((b) => {
    b.addEventListener('click', async () => {
      await updateItem(projectId, project, itemId, { vulnerable: b.dataset.v === '1' });
      refresh();
    });
  });

  // Copy the command with the project variables substituted in.
  const it = project.checklist.find((c) => c._id === itemId);
  el.querySelector('.cmd-copy').addEventListener('click', () =>
    copyText(applyVars(it.command, buildVarMap(project))));

  // Save notes (does not reorder the list).
  el.querySelector('.save-details').addEventListener('click', () =>
    updateItem(projectId, project, itemId, {
      notes: el.querySelector('.ta-notes').value,
    }, true));
}

function checkItemHTML(it, vars) {
  const safe = it.verified && it.vulnerable === false;
  const hit = it.verified && it.vulnerable === true;
  const stateClass = hit ? 'is-vuln' : (safe ? 'is-safe' : '');
  return `
    <div class="check-item ${stateClass}" data-item-id="${it._id}">
      <div class="ci-head">
        <label class="chk" title="Vérifiée ?">
          <input type="checkbox" class="chk-verified" ${it.verified ? 'checked' : ''} />
          <span class="chk-lbl">Vérifiée</span>
        </label>
        ${it.code ? `<span class="ci-code">${esc(it.code)}</span>` : ''}
        <span class="ci-name${safe ? ' struck' : ''}">${esc(it.name)}</span>
        <div class="spacer"></div>
        ${it.verified ? `
          <div class="seg seg-vuln${it.vulnerable === null ? ' undecided' : ''}">
            <button data-v="1" class="${it.vulnerable === true ? 'active danger' : ''}">Vulnérable</button>
            <button data-v="0" class="${it.vulnerable === false ? 'active ok' : ''}">Non vulnérable</button>
          </div>` : ''}
        <button class="chevron ci-toggle" title="Plus de détails">▾</button>
      </div>
      <div class="ci-extra">
        ${it.description ? `<p class="ci-desc">${esc(it.description)}</p>` : ''}
        ${it.reference ? `<a href="${esc(it.reference)}" target="_blank" rel="noopener" class="small">Référence externe ↗</a>` : ''}
        <div class="cmd-bar"><span class="muted small">Commande de vérification</span><button type="button" class="secondary small cmd-copy">Copier</button></div>
        <div class="cmd-preview">${renderCommand(applyVars(it.command, vars))}</div>
        <label>Notes (optionnel)</label>
        <textarea class="ta-notes" placeholder="Observations, payloads, captures…">${esc(it.notes)}</textarea>
        <div style="margin-top:8px"><button class="small save-details">Enregistrer</button></div>
      </div>
    </div>`;
}

async function updateItem(projectId, project, itemId, patch, isDetails) {
  const { item } = await api.patch(`/api/projects/${projectId}/checklist/${itemId}`, patch);
  // keep local copy in sync
  const local = project.checklist.find((c) => c._id === itemId);
  Object.assign(local, item);
  if (isDetails) toast('Détails enregistrés');
}

// ====================================================================
// Rendu markdown + coloration syntaxique des commandes (sans dépendance)
// ====================================================================

// Render a command as a markdown code block with light shell highlighting.
// Supports an optional ```lang fenced block; otherwise treated as shell.
function renderCommand(text) {
  const raw = (text || '').trim();
  if (!raw) return '<p class="muted small" style="margin:0">Aucune commande renseignée.</p>';
  let lang = 'bash';
  let body = raw;
  const fence = raw.match(/^```([\w+-]*)\n([\s\S]*?)\n?```$/);
  if (fence) { lang = fence[1] || 'bash'; body = fence[2]; }
  return `<pre class="md-code"><code class="lang-${esc(lang)}">${highlightShell(body)}</code></pre>`;
}

function highlightShell(src) {
  return src.split('\n').map(highlightShellLine).join('\n');
}

// Tiny shell tokenizer: colours the command name, flags, strings, variables,
// operators and comments. Operates on raw text and escapes each token, so it
// never produces broken markup.
function highlightShellLine(line) {
  if (line.trimStart().startsWith('#')) {
    return `<span class="tok-comment">${esc(line)}</span>`;
  }
  const OPS = '|&;><';
  const BREAK = ['"', "'", '$', '|', '&', ';', '>', '<'];
  const isWS = (c) => c === ' ' || c === '\t';
  let i = 0;
  const n = line.length;
  let out = '';
  let expectCmd = true; // first word, or first word after an operator
  while (i < n) {
    const ch = line[i];
    if (isWS(ch)) { let j = i; while (j < n && isWS(line[j])) j++; out += esc(line.slice(i, j)); i = j; continue; }
    if (ch === '"' || ch === "'") {
      let j = i + 1; while (j < n && line[j] !== ch) j++; j = Math.min(j + 1, n);
      out += `<span class="tok-str">${esc(line.slice(i, j))}</span>`; i = j; expectCmd = false; continue;
    }
    if (ch === '$') {
      let j = i + 1;
      if (line[j] === '{') { while (j < n && line[j] !== '}') j++; j = Math.min(j + 1, n); }
      else { while (j < n && /\w/.test(line[j])) j++; }
      out += `<span class="tok-var">${esc(line.slice(i, j))}</span>`; i = j; expectCmd = false; continue;
    }
    if (OPS.includes(ch)) {
      let j = i; while (j < n && OPS.includes(line[j])) j++;
      out += `<span class="tok-op">${esc(line.slice(i, j))}</span>`; i = j; expectCmd = true; continue;
    }
    let j = i; while (j < n && !isWS(line[j]) && !BREAK.includes(line[j])) j++;
    const word = line.slice(i, j);
    if (/^-{1,2}[^\s]/.test(word)) {
      out += `<span class="tok-flag">${esc(word)}</span>`; // flag: keep expectCmd as-is
    } else if (expectCmd) {
      out += `<span class="tok-cmd">${esc(word)}</span>`; expectCmd = false;
    } else {
      out += esc(word);
    }
    i = j;
  }
  return out;
}

function copyText(t) {
  if (navigator.clipboard && t) {
    navigator.clipboard.writeText(t).then(() => toast('Commande copiée')).catch(() => {});
  }
}

// ====================================================================
// Collaboration temps réel (WebSocket) — sync + présence
// ====================================================================

function connectRealtime() {
  if (socket || typeof io === 'undefined') return;
  socket = io();

  socket.on('connect', () => {
    SOCKET_ID = socket.id;
    if (currentProjectId) socket.emit('join', currentProjectId);
  });

  socket.on('presence', (users) => {
    presenceUsers = Array.isArray(users) ? users : [];
    renderPresence();
  });

  socket.on('item:update', (msg) => {
    if (!msg || msg.originSocketId === SOCKET_ID) return;
    if (msg.projectId !== currentProjectId || !currentProject) return;
    const local = currentProject.checklist.find((c) => c._id === msg.item._id);
    if (!local) { drawChecklist(currentProjectId, currentProject); return; }
    Object.assign(local, msg.item);
    renderStats(currentProject);
    if (!isEditingDetail()) {
      drawChecklist(currentProjectId, currentProject);
      return;
    }
    // Someone is typing: update the changed item in place unless it is the very
    // item being edited (then defer to avoid stealing the caret).
    const el = document.querySelector(`#checklist .check-item[data-item-id="${local._id}"]`);
    if (el && el.contains(document.activeElement)) { pendingRedraw = true; return; }
    updateItemNode(currentProject, local);
  });

  socket.on('project:update', (msg) => {
    if (!msg || msg.originSocketId === SOCKET_ID) return;
    if (msg.projectId !== currentProjectId || !currentProject) return;
    const f = msg.fields || {};
    if (f.status) currentProject.status = f.status;
    if (Array.isArray(f.variables)) {
      currentProject.variables = f.variables;
      if (isEditingDetail()) { pendingRedraw = true; }
      else { renderVariables(currentProjectId, currentProject); refreshPreviews(currentProject); }
    }
  });

  socket.on('project:reload', (msg) => {
    if (msg && msg.projectId === currentProjectId) renderProjectDetail(currentProjectId);
  });

  socket.on('project:deleted', (msg) => {
    if (msg && msg.projectId === currentProjectId) {
      toast('Projet supprimé par un autre auditeur');
      renderProjectList();
    }
  });
}

// Replace a single check-item node in place (preserves other items' carets).
function updateItemNode(project, item) {
  const el = document.querySelector(`#checklist .check-item[data-item-id="${item._id}"]`);
  if (!el) { drawChecklist(currentProjectId, project); return; }
  const tmp = document.createElement('div');
  tmp.innerHTML = checkItemHTML(item, buildVarMap(project));
  const fresh = tmp.firstElementChild;
  if (el.classList.contains('expanded')) fresh.classList.add('expanded');
  el.replaceWith(fresh);
  wireCheckItem(fresh, currentProjectId, project);
  updateFocusBadges();
}

// True if the user is actively editing a field in the project detail.
function isEditingDetail() {
  const a = document.activeElement;
  return !!(a && (a.tagName === 'TEXTAREA' || a.tagName === 'INPUT') &&
    (a.closest('#checklist') || a.closest('#varsPanel')));
}

// Apply a deferred redraw once the user stops editing.
function flushPending() {
  if (!pendingRedraw || !currentProject) return;
  pendingRedraw = false;
  renderStats(currentProject);
  renderVariables(currentProjectId, currentProject);
  drawChecklist(currentProjectId, currentProject);
}

function emitFocus(field) {
  if (socket) socket.emit('focus', field);
}

// ---- Presence rendering ---- (shortName/initials/colorFor/chipHtml in profile.js)
function renderPresence() {
  const bar = document.getElementById('presenceBar');
  if (!bar) return;
  if (presenceUsers.length <= 1) { bar.innerHTML = ''; updateFocusBadges(); return; }
  const chips = presenceUsers.map((u) => chipHtml(u, 'pchip')).join('');
  bar.innerHTML = `${chips}<span class="muted small">${presenceUsers.length} en ligne</span>`;
  updateFocusBadges();
}

// Show a "✎ name" badge on items another auditor is currently editing.
function updateFocusBadges() {
  document.querySelectorAll('#checklist .check-item').forEach((el) => {
    const editors = presenceUsers.filter(
      (u) => u.focus === 'item:' + el.dataset.itemId && u.socketId !== SOCKET_ID);
    let badge = el.querySelector('.editing-badge');
    if (editors.length) {
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'editing-badge';
        el.querySelector('.ci-head').appendChild(badge);
      }
      badge.textContent = '✎ ' + editors.map((u) => shortName(u.email)).join(', ');
      badge.title = editors.map((u) => u.email).join(', ');
    } else if (badge) {
      badge.remove();
    }
  });
}

// Broadcast which field the user focuses, and flush deferred redraws on blur.
const appMainEl = main();
appMainEl.addEventListener('focusin', (e) => {
  const t = e.target;
  if (t.matches && t.matches('#checklist .ta-notes')) {
    const item = t.closest('.check-item');
    if (item) emitFocus('item:' + item.dataset.itemId);
  } else if (t.closest && t.closest('#varsPanel')) {
    emitFocus('variables');
  }
});
appMainEl.addEventListener('focusout', () => {
  setTimeout(() => {
    if (!isEditingDetail()) { emitFocus(null); flushPending(); }
  }, 0);
});

init();
