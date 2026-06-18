// ====================================================================
// Administration : référentiel de vulnérabilités, import/export, users
// ====================================================================

let me = null;
let vulnCatFilter = 'all'; // category filter within the active referential
let currentReferentialId = null; // active referential in the admin vulns tab

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
  renderSso();
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
      ['vulns', 'import', 'users', 'sso'].forEach((t) =>
        document.getElementById('tab-' + t).classList.toggle('hidden', t !== btn.dataset.tab));
    });
  });
}

// ====================================================================
// Référentiel des vulnérabilités (CRUD)
// ====================================================================
async function renderVulns() {
  const { referentials } = await api.get('/api/admin/referentials');
  // Resolve the active referential (kept in a module var across re-renders).
  if (!referentials.some((r) => r._id === currentReferentialId)) {
    const def = referentials.find((r) => r.isDefault) || referentials[0];
    currentReferentialId = def ? def._id : null;
  }
  const currentRef = referentials.find((r) => r._id === currentReferentialId) || null;

  const { vulns } = await api.get('/api/admin/vulns?referentialId=' + encodeURIComponent(currentReferentialId || ''));
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
      <div class="row" style="gap:10px; align-items:flex-end; flex-wrap:wrap">
        <div>
          <label style="margin:0">Référentiel actif</label>
          <select id="refSelect" style="width:auto">
            ${referentials.map((r) => `<option value="${r._id}" ${r._id === currentReferentialId ? 'selected' : ''}>${esc(r.name)}${r.isDefault ? ' (défaut)' : ''}</option>`).join('')}
          </select>
        </div>
        <button class="secondary small" id="refNew" type="button">+ Référentiel</button>
        <button class="secondary small" id="refRename" type="button">Renommer</button>
        <button class="secondary small" id="refDefault" type="button" ${currentRef && currentRef.isDefault ? 'disabled' : ''}>Définir par défaut</button>
        <button class="danger small" id="refDelete" type="button" ${referentials.length <= 1 ? 'disabled' : ''}>Supprimer</button>
      </div>
      <p class="muted" style="margin:10px 0 0">Les vulnérabilités ci-dessous appartiennent au référentiel
        <strong>${esc(currentRef ? currentRef.name : '—')}</strong>. Un projet copie le référentiel choisi à sa création.</p>
    </div>

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

    <h2>Vulnérabilités — ${esc(currentRef ? currentRef.name : '')} (${vulns.length})</h2>
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
        referentialId: currentReferentialId,
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
    delAllBtn.addEventListener('click', () => openDeleteAllModal(vulns.length, currentReferentialId));
  }

  // --- Referential management ---
  document.getElementById('refSelect').addEventListener('change', (e) => {
    currentReferentialId = e.target.value; vulnCatFilter = 'all'; renderVulns();
  });
  document.getElementById('refNew').addEventListener('click', async () => {
    const name = prompt('Nom du nouveau référentiel :');
    if (!name || !name.trim()) return;
    try {
      const { referential } = await api.post('/api/admin/referentials', { name: name.trim() });
      currentReferentialId = referential._id; vulnCatFilter = 'all'; renderVulns();
    } catch (err) { alert(err.message); }
  });
  document.getElementById('refRename').addEventListener('click', async () => {
    if (!currentRef) return;
    const name = prompt('Nouveau nom du référentiel :', currentRef.name);
    if (!name || !name.trim() || name.trim() === currentRef.name) return;
    try { await api.patch(`/api/admin/referentials/${currentRef._id}`, { name: name.trim() }); renderVulns(); }
    catch (err) { alert(err.message); }
  });
  const refDefault = document.getElementById('refDefault');
  if (refDefault && !refDefault.disabled) refDefault.addEventListener('click', async () => {
    try { await api.patch(`/api/admin/referentials/${currentRef._id}`, { isDefault: true }); renderVulns(); }
    catch (err) { alert(err.message); }
  });
  const refDelete = document.getElementById('refDelete');
  if (refDelete && !refDelete.disabled) refDelete.addEventListener('click', async () => {
    if (!confirm(`Supprimer le référentiel « ${currentRef.name} » et toutes ses vulnérabilités ?`)) return;
    try {
      await api.del(`/api/admin/referentials/${currentRef._id}`);
      currentReferentialId = null; vulnCatFilter = 'all'; renderVulns();
    } catch (err) { alert(err.message); }
  });
}

// Destructive confirmation: reminds to export, requires typing "supprimer".
// Scoped to one referential.
function openDeleteAllModal(count, referentialId) {
  const refQuery = '?referentialId=' + encodeURIComponent(referentialId || '');
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
  overlay.querySelector('#modalExport').addEventListener('click', () => { window.location.href = '/api/admin/vulns/export' + refQuery; });
  overlay.querySelector('#modalCancel').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
  document.addEventListener('keydown', function esc(e) {
    if (e.key === 'Escape') { close(); document.removeEventListener('keydown', esc); }
  });
  confirmBtn.addEventListener('click', async () => {
    if (!matches()) return;
    try {
      const r = await api.del('/api/admin/vulns' + refQuery);
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
async function renderImportExport() {
  const el = document.getElementById('tab-import');
  const { referentials } = await api.get('/api/admin/referentials');
  const refOptions = referentials
    .map((r) => `<option value="${r._id}" ${r.isDefault ? 'selected' : ''}>${esc(r.name)}</option>`)
    .join('');
  el.innerHTML = `
    <div class="panel">
      <label>Référentiel ciblé (export / import)</label>
      <select id="ieReferential" style="width:auto">${refOptions}</select>
      <p class="muted" style="margin:8px 0 0">L'export et l'import portent sur le référentiel sélectionné ci-dessus.</p>
    </div>

    <div class="panel">
      <h2>Exporter le référentiel</h2>
      <p class="muted">Téléchargez le référentiel sélectionné au format JSON
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
    const rid = document.getElementById('ieReferential').value;
    window.location.href = '/api/admin/vulns/export?referentialId=' + encodeURIComponent(rid);
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
        referentialId: document.getElementById('ieReferential').value,
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
        <thead><tr><th>E-mail</th><th>Type</th><th>Rôle</th><th>Créé le</th><th></th></tr></thead>
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
      <td>${u.ssoProvider
        ? `<span class="badge tag-sso" title="Compte provisionné via SSO (${esc(u.ssoProvider)})">SSO</span>`
        : '<span class="badge tag-local">Local</span>'}</td>
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

// ====================================================================
// SSO (OAuth2 / OIDC)
// ====================================================================

// Endpoint presets per provider. Selecting a provider fills these in; the
// client id/secret are always entered by hand. Self-hosted GitLab/Keycloak:
// edit the URLs after selecting the preset (replace the host / realm).
const SSO_PRESETS = {
  google: { label: 'Se connecter avec Google', authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth', tokenUrl: 'https://oauth2.googleapis.com/token', userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo', scopes: 'openid email profile', emailField: 'email', nameField: 'name' },
  github: { label: 'Se connecter avec GitHub', authorizationUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', userinfoUrl: 'https://api.github.com/user', scopes: 'read:user user:email', emailField: 'email', nameField: 'name' },
  gitlab: { label: 'Se connecter avec GitLab', authorizationUrl: 'https://gitlab.com/oauth/authorize', tokenUrl: 'https://gitlab.com/oauth/token', userinfoUrl: 'https://gitlab.com/oauth/userinfo', scopes: 'openid email profile', emailField: 'email', nameField: 'name' },
  keycloak: { label: 'Se connecter avec Keycloak', authorizationUrl: 'https://KEYCLOAK_HOST/realms/REALM/protocol/openid-connect/auth', tokenUrl: 'https://KEYCLOAK_HOST/realms/REALM/protocol/openid-connect/token', userinfoUrl: 'https://KEYCLOAK_HOST/realms/REALM/protocol/openid-connect/userinfo', scopes: 'openid email profile', emailField: 'email', nameField: 'name' },
  microsoft: { label: 'Se connecter avec Microsoft', authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', userinfoUrl: 'https://graph.microsoft.com/oidc/userinfo', scopes: 'openid email profile', emailField: 'email', nameField: 'name' },
  custom: { label: 'Se connecter via SSO', authorizationUrl: '', tokenUrl: '', userinfoUrl: '', scopes: 'openid email profile', emailField: 'email', nameField: 'name' },
};

const PROVIDER_LABELS = { google: 'Google', github: 'GitHub', gitlab: 'GitLab', keycloak: 'Keycloak', microsoft: 'Microsoft', custom: 'Personnalisé (OAuth2 / OIDC)' };

async function renderSso() {
  const { sso } = await api.get('/api/admin/sso');
  const el = document.getElementById('tab-sso');
  const redirectUri = `${window.location.origin}/api/auth/sso/callback`;
  const provOptions = Object.keys(PROVIDER_LABELS)
    .map((k) => `<option value="${k}" ${sso.provider === k ? 'selected' : ''}>${esc(PROVIDER_LABELS[k])}</option>`)
    .join('');

  el.innerHTML = `
    <div class="panel">
      <div class="row" style="justify-content:space-between; align-items:center">
        <h2 style="margin:0">Authentification unique (SSO)</h2>
        <button class="secondary small" id="ssoHelp" type="button">❔ Aide</button>
      </div>
      <p class="muted">Connexion via un fournisseur OAuth2 / OIDC. Renseignez l'application
        créée chez le fournisseur, puis activez le SSO. Le bouton apparaîtra sur la page de connexion.</p>

      <label class="chk" style="margin-top:6px">
        <input type="checkbox" id="ssoEnabled" ${sso.enabled ? 'checked' : ''} />
        <span>Activer le SSO</span>
      </label>

      <div class="grid cols-2" style="margin-top:10px">
        <div><label>Fournisseur</label><select id="ssoProvider">${provOptions}</select></div>
        <div><label>Texte du bouton</label><input id="ssoLabel" value="${esc(sso.label)}" /></div>
      </div>

      <label>URI de redirection (à enregistrer chez le fournisseur)</label>
      <div class="row" style="gap:8px">
        <input id="ssoRedirect" readonly value="${esc(redirectUri)}" />
        <button class="secondary small" id="ssoCopyRedirect" type="button">Copier</button>
      </div>

      <div class="grid cols-2" style="margin-top:10px">
        <div><label>Client ID</label><input id="ssoClientId" value="${esc(sso.clientId)}" /></div>
        <div>
          <label>Client Secret</label>
          <input id="ssoClientSecret" type="password" placeholder="${sso.hasSecret ? '•••••••• (laisser vide pour conserver)' : ''}" />
        </div>
      </div>

      <label>Authorization URL</label><input id="ssoAuthUrl" value="${esc(sso.authorizationUrl)}" />
      <label>Token URL</label><input id="ssoTokenUrl" value="${esc(sso.tokenUrl)}" />
      <label>Userinfo URL</label><input id="ssoUserinfoUrl" value="${esc(sso.userinfoUrl)}" />
      <label>Scopes (séparés par des espaces)</label><input id="ssoScopes" value="${esc(sso.scopes)}" />

      <div class="grid cols-2" style="margin-top:10px">
        <div><label>Champ e-mail (userinfo)</label><input id="ssoEmailField" value="${esc(sso.emailField)}" /></div>
        <div><label>Champ nom (userinfo)</label><input id="ssoNameField" value="${esc(sso.nameField)}" /></div>
      </div>

      <label class="chk" style="margin-top:12px">
        <input type="checkbox" id="ssoAutoCreate" ${sso.autoCreateUsers ? 'checked' : ''} />
        <span>Créer automatiquement les comptes à la première connexion</span>
      </label>
      <div style="margin-top:8px"><label>Rôle par défaut des comptes créés</label>
        <select id="ssoDefaultRole" style="width:auto">
          <option value="auditor" ${sso.defaultRole === 'auditor' ? 'selected' : ''}>Auditeur</option>
          <option value="admin" ${sso.defaultRole === 'admin' ? 'selected' : ''}>Administrateur</option>
        </select>
      </div>

      <div class="row" style="margin-top:14px; gap:8px">
        <button id="ssoSave">Enregistrer</button>
        <button class="secondary" id="ssoTest" type="button">Tester les URL</button>
      </div>
      <div id="ssoTestResults" style="margin-top:10px"></div>
      <div class="error" id="ssoError"></div>
      <div class="muted" id="ssoOk"></div>
    </div>
  `;

  // Provider preset: fill the endpoint fields (keep client id/secret untouched).
  document.getElementById('ssoProvider').addEventListener('change', (e) => {
    const p = SSO_PRESETS[e.target.value] || SSO_PRESETS.custom;
    document.getElementById('ssoLabel').value = p.label;
    document.getElementById('ssoAuthUrl').value = p.authorizationUrl;
    document.getElementById('ssoTokenUrl').value = p.tokenUrl;
    document.getElementById('ssoUserinfoUrl').value = p.userinfoUrl;
    document.getElementById('ssoScopes').value = p.scopes;
    document.getElementById('ssoEmailField').value = p.emailField;
    document.getElementById('ssoNameField').value = p.nameField;
  });

  document.getElementById('ssoCopyRedirect').addEventListener('click', () => {
    if (navigator.clipboard) navigator.clipboard.writeText(redirectUri).then(() => toast('URI copiée')).catch(() => {});
  });

  document.getElementById('ssoHelp').addEventListener('click', () =>
    openSsoHelpModal(document.getElementById('ssoProvider').value, redirectUri));

  document.getElementById('ssoSave').addEventListener('click', async () => {
    const errEl = document.getElementById('ssoError');
    const okEl = document.getElementById('ssoOk');
    errEl.textContent = '';
    okEl.textContent = '';
    try {
      await api.request('PUT', '/api/admin/sso', {
        enabled: document.getElementById('ssoEnabled').checked,
        provider: document.getElementById('ssoProvider').value,
        label: document.getElementById('ssoLabel').value,
        clientId: document.getElementById('ssoClientId').value,
        clientSecret: document.getElementById('ssoClientSecret').value, // blank → keep existing
        authorizationUrl: document.getElementById('ssoAuthUrl').value,
        tokenUrl: document.getElementById('ssoTokenUrl').value,
        userinfoUrl: document.getElementById('ssoUserinfoUrl').value,
        scopes: document.getElementById('ssoScopes').value,
        emailField: document.getElementById('ssoEmailField').value,
        nameField: document.getElementById('ssoNameField').value,
        autoCreateUsers: document.getElementById('ssoAutoCreate').checked,
        defaultRole: document.getElementById('ssoDefaultRole').value,
      });
      okEl.textContent = 'Configuration SSO enregistrée.';
      renderSso();
    } catch (err) {
      errEl.textContent = err.message;
    }
  });

  // Test the endpoints without saving. Sends the current form values; a blank
  // secret falls back to the stored one (same rule as save).
  document.getElementById('ssoTest').addEventListener('click', async () => {
    const btn = document.getElementById('ssoTest');
    const out = document.getElementById('ssoTestResults');
    document.getElementById('ssoError').textContent = '';
    document.getElementById('ssoOk').textContent = '';
    btn.disabled = true;
    out.innerHTML = '<span class="muted">Test en cours…</span>';
    try {
      const { checks } = await api.request('POST', '/api/admin/sso/test', {
        clientId: document.getElementById('ssoClientId').value,
        clientSecret: document.getElementById('ssoClientSecret').value,
        authorizationUrl: document.getElementById('ssoAuthUrl').value,
        tokenUrl: document.getElementById('ssoTokenUrl').value,
        userinfoUrl: document.getElementById('ssoUserinfoUrl').value,
      });
      out.innerHTML = checks
        .map((c) => `<div class="row" style="gap:8px; align-items:baseline">
          <span>${c.ok ? '✅' : '❌'}</span>
          <span><strong>${esc(c.name)}</strong> — ${esc(c.message)}</span>
        </div>`)
        .join('');
    } catch (err) {
      out.innerHTML = `<span class="error">${esc(err.message)}</span>`;
    } finally {
      btn.disabled = false;
    }
  });
}

// Step-by-step help, tailored to the selected provider.
function openSsoHelpModal(provider, redirectUri) {
  const consoles = {
    google: 'Google Cloud Console → APIs &amp; Services → Identifiants → « Créer des identifiants » → ID client OAuth → Application Web.',
    github: 'GitHub → Settings → Developer settings → OAuth Apps → « New OAuth App ».',
    gitlab: 'GitLab → User Settings (ou Group/Admin) → Applications → « Add new application ».',
    keycloak: 'Keycloak Admin → votre Realm → Clients → « Create client » (type OpenID Connect, flux standard activé).',
    microsoft: 'Azure Portal → Microsoft Entra ID → App registrations → « New registration ».',
    custom: "La console d'administration de votre fournisseur OAuth2 / OIDC.",
  };
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" style="max-width:640px; text-align:left">
      <h2>Configurer le SSO — ${esc(PROVIDER_LABELS[provider] || 'OAuth2 / OIDC')}</h2>
      <ol class="sso-help">
        <li>Ouvrez ${consoles[provider] || consoles.custom}</li>
        <li>Créez une application <strong>Web / confidentielle</strong> (avec secret).</li>
        <li>Déclarez l'<strong>URI de redirection</strong> autorisée :
          <code>${esc(redirectUri)}</code></li>
        <li>Demandez les scopes <code>openid email profile</code> (ou équivalent) afin d'obtenir l'e-mail.</li>
        <li>Copiez le <strong>Client ID</strong> et le <strong>Client Secret</strong> dans le formulaire.</li>
        <li>Choisissez le fournisseur dans la liste : les URLs sont pré-remplies
          (pour GitLab / Keycloak auto-hébergés, remplacez l'hôte et le realm).</li>
        <li>Cochez « Activer le SSO » puis <strong>Enregistrez</strong>. Un bouton
          apparaît sur la page de connexion.</li>
        <li><em>Provisionnement</em> : sans création automatique, l'e-mail SSO doit
          déjà exister dans « Utilisateurs ». Avec, un compte est créé au premier
          login avec le rôle par défaut.</li>
      </ol>
      <div class="row" style="margin-top:14px; justify-content:flex-end">
        <button id="ssoHelpClose" type="button">Fermer</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const close = () => overlay.remove();
  overlay.querySelector('#ssoHelpClose').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

init();
