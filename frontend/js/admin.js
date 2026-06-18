// ====================================================================
// Administration : référentiel de vulnérabilités, import/export, users
// ====================================================================

let me = null;
let vulnCatFilter = 'all'; // referential category filter ('all' or a category name)

// Group a flat (order-sorted) vuln list into category sections, preserving the
// referential order. Items without a category fall into a trailing "Autres".
function groupByCategory(list) {
  const groups = [];
  const map = new Map();
  for (const v of list) {
    const cat = (v.category || '').trim() || 'Autres';
    let g = map.get(cat);
    if (!g) { g = { category: cat, items: [] }; map.set(cat, g); groups.push(g); }
    g.items.push(v);
  }
  return groups;
}

async function init() {
  try {
    const { user } = await api.get('/api/auth/me');
    me = user;
  } catch (_) {
    window.location.href = '/';
    return;
  }
  if (me.role !== 'admin') {
    document.getElementById('adminMain').innerHTML =
      '<h1>Accès refusé</h1><p class="muted">Cette page est réservée aux administrateurs.</p>';
    return;
  }
  initProfileMenu(me, (user) => { me = user; });
  setupTabs();
  renderVulns();
  renderImportExport();
  renderUsers();
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api.post('/api/auth/logout');
  window.location.href = '/';
});

function setupTabs() {
  document.querySelectorAll('.tabs button').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tabs button').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      ['vulns', 'import', 'users'].forEach((t) =>
        document.getElementById('tab-' + t).classList.toggle('hidden', t !== btn.dataset.tab));
    });
  });
}

// ====================================================================
// Référentiel des vulnérabilités (CRUD)
// ====================================================================
async function renderVulns() {
  const { vulns } = await api.get('/api/admin/vulns');
  const el = document.getElementById('tab-vulns');

  const groups = groupByCategory(vulns);
  // Sort categories alphabetically (catch-all "Autres" last) so the admin list,
  // the filter dropdown and the persisted order match the project view.
  groups.sort((a, b) => {
    if (a.category === 'Autres') return 1;
    if (b.category === 'Autres') return -1;
    return a.category.localeCompare(b.category, 'fr', { sensitivity: 'base' });
  });
  // Reset the filter if the selected category no longer exists.
  if (vulnCatFilter !== 'all' && !groups.some((g) => g.category === vulnCatFilter)) vulnCatFilter = 'all';

  el.innerHTML = `
    <div class="panel">
      <h2>Ajouter une vulnérabilité</h2>
      <div class="grid cols-2">
        <div><label>Code</label><input id="vCode" placeholder="WSTG-XXXX-00 (facultatif)" /></div>
        <div><label>Catégorie</label><input id="vCategory" placeholder="Authentification (facultatif)" /></div>
      </div>
      <label>Intitulé *</label><input id="vName" />
      <label>Description</label><textarea id="vDesc"></textarea>
      <label>Référence externe (URL)</label><input id="vRef" />
      <label>Commande de vérification (outil, markdown / shell)</label>
      <textarea id="vCmd" class="mono" placeholder="ex: nmap -sV --script ssl-enum-ciphers -p 443 cible.tld"></textarea>
      <label>Notes par défaut (optionnel)</label>
      <textarea id="vNotes"></textarea>
      <div class="row" style="margin-top:12px">
        <button id="vAdd">Ajouter</button>
      </div>
      <div class="error" id="vError"></div>
    </div>

    <h2>Référentiel (${vulns.length})</h2>
    <div class="panel" style="overflow-x:auto">
      <div class="row" style="gap:8px; margin-bottom:12px; align-items:center">
        <label style="margin:0">Filtrer par catégorie</label>
        <select id="catFilter" style="width:auto">
          <option value="all">Toutes les catégories (${vulns.length})</option>
          ${groups.map((g) => `<option value="${esc(g.category)}"${vulnCatFilter === g.category ? ' selected' : ''}>${esc(g.category)} (${g.items.length})</option>`).join('')}
        </select>
      </div>
      <table>
        <thead><tr><th>Code</th><th>Intitulé</th><th>Cmd</th><th></th></tr></thead>
        <tbody id="vulnRows"></tbody>
      </table>
    </div>

    <div class="panel danger-zone">
      <h2>Zone de danger</h2>
      <p class="muted">Supprime <strong>toutes</strong> les vulnérabilités du référentiel (${vulns.length}). Action irréversible — exportez d'abord en JSON.</p>
      <button class="danger" id="deleteAllBtn" ${vulns.length ? '' : 'disabled'}>Supprimer tout le référentiel</button>
    </div>
  `;

  const rows = document.getElementById('vulnRows');
  // Render one section per category (header row + its items). When a filter is
  // active, only that category is shown. Up/down are bounded within a category.
  const visibleGroups = vulnCatFilter === 'all' ? groups : groups.filter((g) => g.category === vulnCatFilter);
  rows.innerHTML = visibleGroups.map((g) => {
    const header = `<tr class="cat-header"><td colspan="4">${esc(g.category)} <span class="muted">(${g.items.length})</span></td></tr>`;
    const items = g.items.map((v, i) => `
    <tr data-id="${v._id}">
      <td><span class="ci-code">${esc(v.code) || '—'}</span></td>
      <td>${esc(v.name)}</td>
      <td title="Commande renseignée">${v.command ? '✓' : '—'}</td>
      <td>
        <div class="row" style="gap:8px">
          <button class="secondary small btn-up" title="Monter" ${i === 0 ? 'disabled' : ''}>▲</button>
          <button class="secondary small btn-down" title="Descendre" ${i === g.items.length - 1 ? 'disabled' : ''}>▼</button>
          <button class="secondary small btn-edit">Modifier</button>
          <button class="danger small btn-del">Suppr.</button>
        </div>
      </td>
    </tr>`).join('');
    return header + items;
  }).join('') || '<tr><td colspan="4" class="muted">Aucune vulnérabilité.</td></tr>';

  // Move a vuln up (-1) or down (+1) within its category, persist the new global
  // order, then re-render. The order is reflected in new projects' checklists.
  const move = async (id, dir) => {
    for (const g of groups) {
      const i = g.items.findIndex((x) => x._id === id);
      if (i === -1) continue;
      const j = i + dir;
      if (j < 0 || j >= g.items.length) return;
      [g.items[i], g.items[j]] = [g.items[j], g.items[i]];
      break;
    }
    // Flatten all categories back to a single ordered id list (keeps categories
    // grouped so the order stays stable across reloads and in project views).
    const ids = groups.flatMap((g) => g.items.map((x) => x._id));
    try {
      await api.post('/api/admin/vulns/reorder', { ids });
      renderVulns();
    } catch (err) {
      alert(err.message);
      renderVulns();
    }
  };

  rows.querySelectorAll('tr[data-id]').forEach((tr) => {
    const id = tr.dataset.id;
    const v = vulns.find((x) => x._id === id);
    const up = tr.querySelector('.btn-up');
    const down = tr.querySelector('.btn-down');
    if (up && !up.disabled) up.addEventListener('click', () => move(id, -1));
    if (down && !down.disabled) down.addEventListener('click', () => move(id, 1));
    tr.querySelector('.btn-del').addEventListener('click', async () => {
      if (!confirm(`Supprimer ${v.code} du référentiel ?`)) return;
      await api.del(`/api/admin/vulns/${id}`);
      renderVulns();
    });
    tr.querySelector('.btn-edit').addEventListener('click', () => openEditRow(tr, v));
  });

  const catFilter = document.getElementById('catFilter');
  if (catFilter) catFilter.addEventListener('change', () => { vulnCatFilter = catFilter.value; renderVulns(); });

  document.getElementById('vAdd').addEventListener('click', async () => {
    const errEl = document.getElementById('vError');
    errEl.textContent = '';
    try {
      await api.post('/api/admin/vulns', {
        code: document.getElementById('vCode').value,
        category: document.getElementById('vCategory').value,
        name: document.getElementById('vName').value,
        description: document.getElementById('vDesc').value,
        reference: document.getElementById('vRef').value,
        command: document.getElementById('vCmd').value,
        notes: document.getElementById('vNotes').value,
      });
      renderVulns();
    } catch (err) {
      errEl.textContent = err.message;
    }
  });

  const delAllBtn = document.getElementById('deleteAllBtn');
  if (delAllBtn && !delAllBtn.disabled) {
    delAllBtn.addEventListener('click', () => openDeleteAllModal(vulns.length));
  }
}

// Destructive confirmation: reminds to export, requires typing "supprimer".
function openDeleteAllModal(count) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <h2 class="danger-title">⚠ Supprimer tout le référentiel</h2>
      <p>Vous allez supprimer <strong>${count}</strong> vulnérabilité(s). Cette action est <strong>irréversible</strong>.</p>
      <p class="muted">Pensez à sauvegarder avant : exportez le référentiel au format JSON.</p>
      <button class="secondary small" id="modalExport" type="button">⬇ Exporter le JSON maintenant</button>
      <label style="margin-top:14px">Tapez <code>supprimer</code> pour confirmer</label>
      <input id="modalConfirmInput" autocomplete="off" placeholder="supprimer" />
      <div class="row" style="margin-top:14px; justify-content:flex-end">
        <button class="secondary" id="modalCancel" type="button">Annuler</button>
        <button class="danger" id="modalConfirm" type="button" disabled>Supprimer tout</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const input = overlay.querySelector('#modalConfirmInput');
  const confirmBtn = overlay.querySelector('#modalConfirm');
  const close = () => overlay.remove();
  const matches = () => input.value.trim().toLowerCase() === 'supprimer';

  input.addEventListener('input', () => { confirmBtn.disabled = !matches(); });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && matches()) confirmBtn.click(); });
  overlay.querySelector('#modalExport').addEventListener('click', () => { window.location.href = '/api/admin/vulns/export'; });
  overlay.querySelector('#modalCancel').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
  });
  confirmBtn.addEventListener('click', async () => {
    if (!matches()) return;
    try {
      const r = await api.del('/api/admin/vulns');
      close();
      toast(`${r.deleted} vulnérabilité(s) supprimée(s)`);
      renderVulns();
    } catch (err) {
      alert(err.message);
    }
  });
  input.focus();
}

function openEditRow(tr, v) {
  tr.innerHTML = `
    <td colspan="4">
      <div class="grid cols-2">
        <div><label>Code</label><input class="e-code" value="${esc(v.code)}" /></div>
        <div><label>Catégorie</label><input class="e-cat" value="${esc(v.category)}" /></div>
      </div>
      <label>Intitulé</label><input class="e-name" value="${esc(v.name)}" />
      <label>Description</label><textarea class="e-desc">${esc(v.description)}</textarea>
      <label>Référence externe</label><input class="e-ref" value="${esc(v.reference)}" />
      <label>Commande de vérification (outil, markdown / shell)</label>
      <textarea class="e-cmd mono">${esc(v.command || '')}</textarea>
      <label>Notes par défaut (optionnel)</label>
      <textarea class="e-notes">${esc(v.notes || '')}</textarea>
      <div class="row" style="margin-top:10px">
        <button class="e-save small">Enregistrer</button>
        <button class="secondary small e-cancel">Annuler</button>
      </div>
    </td>`;
  tr.querySelector('.e-cancel').addEventListener('click', renderVulns);
  tr.querySelector('.e-save').addEventListener('click', async () => {
    try {
      await api.patch(`/api/admin/vulns/${v._id}`, {
        code: tr.querySelector('.e-code').value,
        category: tr.querySelector('.e-cat').value,
        name: tr.querySelector('.e-name').value,
        description: tr.querySelector('.e-desc').value,
        reference: tr.querySelector('.e-ref').value,
        command: tr.querySelector('.e-cmd').value,
        notes: tr.querySelector('.e-notes').value,
      });
      renderVulns();
    } catch (err) {
      alert(err.message);
    }
  });
}

// ====================================================================
// Import / Export JSON
// ====================================================================
function renderImportExport() {
  const el = document.getElementById('tab-import');
  el.innerHTML = `
    <div class="panel">
      <h2>Exporter le référentiel</h2>
      <p class="muted">Téléchargez l'ensemble du référentiel au format JSON
        (sauvegarde / transfert). Chaque vulnérabilité embarque :
        <code>code</code>, <code>category</code>, <code>name</code>,
        <code>description</code>, <code>reference</code>, <code>command</code>,
        <code>notes</code> (et <code>order</code>).</p>
      <button id="exportBtn">Télécharger le JSON</button>
    </div>

    <div class="panel">
      <h2>Importer un référentiel</h2>
      <p class="muted">Collez un JSON ou sélectionnez un fichier. Format attendu :
        <code>{ "vulns": [ { "code", "category", "name", "description", "reference", "command", "notes" } ] }</code></p>
      <label>Mode d'import</label>
      <select id="importMode" style="width:auto">
        <option value="merge">Fusionner (met à jour / ajoute par code)</option>
        <option value="replace">Remplacer (efface puis recrée tout)</option>
      </select>
      <label>Fichier JSON</label>
      <input type="file" id="importFile" accept="application/json,.json" />
      <label>… ou coller le JSON</label>
      <textarea id="importText" placeholder='{ "vulns": [ ... ] }' style="min-height:140px"></textarea>
      <div class="row" style="margin-top:12px">
        <button id="importBtn">Importer</button>
      </div>
      <div class="error" id="importError"></div>
      <div id="importResult" class="muted"></div>
    </div>
  `;

  document.getElementById('exportBtn').addEventListener('click', () => {
    // hits the export endpoint which sets a download disposition
    window.location.href = '/api/admin/vulns/export';
  });

  const fileInput = document.getElementById('importFile');
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { document.getElementById('importText').value = reader.result; };
    reader.readAsText(f);
  });

  document.getElementById('importBtn').addEventListener('click', async () => {
    const errEl = document.getElementById('importError');
    const resEl = document.getElementById('importResult');
    errEl.textContent = '';
    resEl.textContent = '';
    let payload;
    try {
      payload = JSON.parse(document.getElementById('importText').value);
    } catch (_) {
      errEl.textContent = 'JSON invalide.';
      return;
    }
    const vulns = Array.isArray(payload) ? payload : payload.vulns;
    try {
      const r = await api.post('/api/admin/vulns/import', {
        vulns,
        mode: document.getElementById('importMode').value,
      });
      resEl.textContent =
        `Import terminé (${r.mode}) : ${r.created} créée(s), ${r.updated} mise(s) à jour, ${r.errors.length} erreur(s).`;
      renderVulns();
    } catch (err) {
      errEl.textContent = err.message;
    }
  });
}

// ====================================================================
// Utilisateurs
// ====================================================================
async function renderUsers() {
  const { users } = await api.get('/api/admin/users');
  const el = document.getElementById('tab-users');
  el.innerHTML = `
    <div class="panel">
      <h2>Ajouter un utilisateur</h2>
      <div class="grid cols-2">
        <div><label>E-mail *</label><input id="uEmail" type="email" /></div>
        <div><label>Mot de passe *</label><input id="uPass" type="text" /></div>
      </div>
      <label>Rôle</label>
      <select id="uRole" style="width:auto">
        <option value="auditor">Auditeur</option>
        <option value="admin">Administrateur</option>
      </select>
      <div class="row" style="margin-top:12px"><button id="uAdd">Créer</button></div>
      <div class="error" id="uError"></div>
    </div>

    <h2>Utilisateurs (${users.length})</h2>
    <div class="panel" style="overflow-x:auto">
      <table>
        <thead><tr><th>E-mail</th><th>Rôle</th><th>Créé le</th><th></th></tr></thead>
        <tbody id="userRows"></tbody>
      </table>
    </div>
  `;

  const rows = document.getElementById('userRows');
  rows.innerHTML = users.map((u) => {
    const isSelf = u._id === me._id;
    return `
    <tr data-id="${u._id}">
      <td>${esc(u.email)}${isSelf ? ' <span class="muted">(vous)</span>' : ''}</td>
      <td>
        <select class="u-role" style="width:auto" ${isSelf ? 'disabled title="Vous ne pouvez pas changer votre propre rôle"' : ''}>
          <option value="auditor" ${u.role === 'auditor' ? 'selected' : ''}>Auditeur</option>
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Administrateur</option>
        </select>
      </td>
      <td class="muted">${new Date(u.createdAt).toLocaleDateString('fr-FR')}</td>
      <td>
        <div class="row" style="gap:8px">
          <button class="secondary small u-reset">Lien de réinit.</button>
          <button class="danger small u-del" ${isSelf ? 'disabled' : ''}>Suppr.</button>
        </div>
      </td>
    </tr>`;
  }).join('');

  rows.querySelectorAll('tr').forEach((tr) => {
    const id = tr.dataset.id;
    const roleSel = tr.querySelector('.u-role');
    if (!roleSel.disabled) {
      roleSel.addEventListener('change', async (e) => {
        try {
          await api.patch(`/api/admin/users/${id}`, { role: e.target.value });
          toast('Rôle mis à jour');
        } catch (err) {
          alert(err.message);
          renderUsers();
        }
      });
    }
    tr.querySelector('.u-reset').addEventListener('click', async () => {
      try {
        const link = await api.post(`/api/admin/users/${id}/reset-link`);
        openResetLinkModal(link);
      } catch (err) {
        alert(err.message);
      }
    });
    const delBtn = tr.querySelector('.u-del');
    if (!delBtn.disabled) {
      delBtn.addEventListener('click', async () => {
        if (!confirm('Supprimer cet utilisateur ?')) return;
        await api.del(`/api/admin/users/${id}`);
        renderUsers();
      });
    }
  });

  document.getElementById('uAdd').addEventListener('click', async () => {
    const errEl = document.getElementById('uError');
    errEl.textContent = '';
    try {
      await api.post('/api/admin/users', {
        email: document.getElementById('uEmail').value,
        password: document.getElementById('uPass').value,
        role: document.getElementById('uRole').value,
      });
      renderUsers();
    } catch (err) {
      errEl.textContent = err.message;
    }
  });
}

// Show the generated secure reset link for the admin to copy and send.
function openResetLinkModal({ url, email, expiresAt }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  const exp = expiresAt ? new Date(expiresAt).toLocaleString('fr-FR') : '';
  overlay.innerHTML = `
    <div class="modal">
      <h2>Lien de réinitialisation</h2>
      <p class="muted">Transmettez ce lien à <strong>${esc(email)}</strong> (par un canal sûr).
        Il permet de définir un nouveau mot de passe et expire le <strong>${esc(exp)}</strong>.</p>
      <input id="resetLinkInput" readonly value="${esc(url)}" />
      <div class="row" style="margin-top:12px; justify-content:flex-end">
        <button class="secondary" id="resetLinkCopy" type="button">Copier le lien</button>
        <button id="resetLinkClose" type="button">Fermer</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  const input = overlay.querySelector('#resetLinkInput');
  input.focus();
  input.select();
  overlay.querySelector('#resetLinkCopy').addEventListener('click', () => {
    input.select();
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url).then(() => toast('Lien copié')).catch(() => {});
    } else {
      document.execCommand('copy');
      toast('Lien copié');
    }
  });
  overlay.querySelector('#resetLinkClose').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

init();
