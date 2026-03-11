/* ============================================================
   Aegis Web Interface · aegis.js
   Speaks with SeQ API (OAuth 2.0 password grant)
   ============================================================ */

'use strict';

// ── Config ────────────────────────────────────────────────────
const API_BASE = 'http://localhost:5000';

// ── Auth helpers ──────────────────────────────────────────────
const Auth = {
  save(data) {
    sessionStorage.setItem('seq_access_token',  data.access_token);
    sessionStorage.setItem('seq_refresh_token', data.refresh_token || '');
    sessionStorage.setItem('seq_username',      data.username || '');
  },
  getToken()    { return sessionStorage.getItem('seq_access_token');  },
  getRefresh()  { return sessionStorage.getItem('seq_refresh_token'); },
  getUsername() { return sessionStorage.getItem('seq_username');      },
  clear() {
    ['seq_access_token','seq_refresh_token','seq_username']
      .forEach(k => sessionStorage.removeItem(k));
  },
  isLoggedIn() { return !!this.getToken(); },
};

// ── API ───────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = Auth.getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  // Auto-refresh on 401
  if (res.status === 401 && Auth.getRefresh()) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      headers.Authorization = `Bearer ${Auth.getToken()}`;
      return fetch(`${API_BASE}${path}`, { ...options, headers });
    } else {
      logout();
      return res;
    }
  }
  return res;
}

async function tryRefresh() {
  try {
    const res = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grantType: 'refresh_token', refresh_token: Auth.getRefresh() }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    Auth.save({ ...data, username: Auth.getUsername() });
    return true;
  } catch { return false; }
}

// ── UI helpers ────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function setPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('page--active'));
  $(`page-${name}`).classList.add('page--active');
}

function setView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('view--active'));
  $(`view-${name}`).classList.add('view--active');
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('nav-item--active', n.dataset.view === name);
  });
}

function switchView(name) { setView(name); }
window.switchView = switchView;

function setLoading(btnId, loading) {
  const btn  = $(btnId);
  if (!btn) return;
  const text = btn.querySelector('.btn-text');
  const spin = btn.querySelector('.btn-spinner');
  btn.disabled = loading;
  if (text) text.hidden = loading;
  if (spin) spin.hidden = !loading;
}

function showError(containerId, msgId, msg) {
  const el = $(containerId);
  if (el) el.hidden = false;
  const mel = $(msgId);
  if (mel) mel.textContent = msg;
}
function hideError(containerId) {
  const el = $(containerId);
  if (el) el.hidden = true;
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('es-ES', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    }).format(new Date(iso));
  } catch { return iso; }
}

// ── Login ─────────────────────────────────────────────────────
$('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  hideError('login-error');
  setLoading('btn-login', true);

  const username = $('username').value.trim();
  const password = $('password').value;

  try {
    const res = await fetch(`${API_BASE}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grantType: 'password', username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showError('login-error', 'login-error-msg',
        data.error_description || data.error || 'Credenciales incorrectas');
      return;
    }

    Auth.save({ ...data, username });
    initApp();
    setPage('app');
    loadDocuments();

  } catch (err) {
    showError('login-error', 'login-error-msg', 'No se pudo conectar con el servidor');
  } finally {
    setLoading('btn-login', false);
  }
});

// Toggle password visibility
$('toggle-pw').addEventListener('click', () => {
  const inp = $('password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  const icon = $('eye-icon');
  icon.innerHTML = inp.type === 'text'
    ? '<line x1="1" y1="1" x2="23" y2="23"/><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/>'
    + '<path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/>'
    + '<circle cx="12" cy="12" r="3"/>'
    : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8"/><circle cx="12" cy="12" r="3"/>';
});

// ── Init App (after login) ────────────────────────────────────
function initApp() {
  const uname = Auth.getUsername();
  $('user-name-display').textContent = uname || 'Usuario';
  $('user-avatar').textContent = (uname || 'U')[0].toUpperCase();
}

// ── Logout ────────────────────────────────────────────────────
async function logout() {
  try { await apiFetch('/oauth/revoke', { method: 'POST' }); } catch {}
  Auth.clear();
  setPage('login');
  clearDocs();
}
$('btn-logout').addEventListener('click', logout);

// ── Nav ───────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    setView(view);
    if (view === 'documents') loadDocuments();
  });
});

$('btn-refresh').addEventListener('click', loadDocuments);

// ── Documents ─────────────────────────────────────────────────
let docList = [];
let activeDocId = null;

function clearDocs() {
  docList = [];
  const grid = $('docs-grid');
  if (grid) { grid.innerHTML = ''; grid.hidden = true; }
}

async function loadDocuments() {
  const grid    = $('docs-grid');
  const loading = $('docs-loading');
  const empty   = $('docs-empty');
  const errEl   = $('docs-error');

  grid.hidden    = true;
  empty.hidden   = true;
  errEl.hidden   = true;
  loading.hidden = false;

  // Poll IDs from 1 upward until we get 404 (max 200)
  // since there is no "list all" endpoint, we fetch by id
  // and collect until we hit 5 consecutive 404s
  const docs = [];
  let consecutive404 = 0;
  for (let id = 1; id <= 200 && consecutive404 < 5; id++) {
    try {
      const res = await apiFetch(`/aegis/status?id=${id}`);
      if (res.status === 404) { consecutive404++; continue; }
      if (!res.ok) { consecutive404++; continue; }
      consecutive404 = 0;
      const doc = await res.json();
      docs.push(doc);
    } catch { consecutive404++; }
  }

  docList = docs;
  loading.hidden = true;

  if (docs.length === 0) {
    empty.hidden = false;
    return;
  }

  grid.innerHTML = '';
  docs.sort((a, b) => (b.id || 0) - (a.id || 0));
  docs.forEach(doc => grid.appendChild(buildDocCard(doc)));
  grid.hidden = false;

  hideError('docs-error');
}

function buildDocCard(doc) {
  const card = document.createElement('div');
  card.className = 'doc-card';
  card.dataset.docId = doc.id;

  const statusClass = doc.status === 'ready'
    ? 'doc-status--ready'
    : doc.status === 'pending' ? 'doc-status--pending' : 'doc-status--error';
  const statusLabel = doc.status === 'ready' ? 'Listo'
    : doc.status === 'pending' ? 'Generando…' : doc.status || 'Desconocido';

  card.innerHTML = `
    <div class="doc-card-header">
      <p class="doc-title">${escHtml(doc.title || 'Sin título')}</p>
      <span class="doc-status ${statusClass}">${escHtml(statusLabel)}</span>
    </div>
    <div class="doc-meta">
      <span class="doc-tag">ID: ${doc.id}</span>
      ${doc.topicId != null ? `<span class="doc-tag doc-tag--topic">Topic ${doc.topicId}</span>` : ''}
    </div>
    <p class="doc-date">${formatDate(doc.generatedAt)}</p>
  `;

  card.addEventListener('click', () => openDocModal(doc));
  return card;
}

function openDocModal(doc) {
  activeDocId = doc.id;
  $('modal-title').textContent = doc.title || `Documento #${doc.id}`;

  const statusClass = doc.status === 'ready'
    ? 'doc-status--ready'
    : doc.status === 'pending' ? 'doc-status--pending' : 'doc-status--error';
  const statusLabel = doc.status === 'ready' ? 'Listo'
    : doc.status === 'pending' ? 'Generando…' : doc.status || 'Desconocido';

  $('modal-body').innerHTML = `
    <div class="modal-detail-row"><strong>ID</strong><span>${doc.id}</span></div>
    <div class="modal-detail-row"><strong>Estado</strong>
      <span class="doc-status ${statusClass}">${escHtml(statusLabel)}</span>
    </div>
    <div class="modal-detail-row"><strong>Topic</strong><span>${doc.topicId ?? '—'}</span></div>
    <div class="modal-detail-row"><strong>Generado</strong><span>${formatDate(doc.generatedAt)}</span></div>
    <div class="modal-detail-row"><strong>Titulo</strong><span>${escHtml(doc.title || '—')}</span></div>
  `;

  $('btn-download-md').disabled = doc.status !== 'ready';
  $('doc-modal').hidden = false;
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  $('doc-modal').hidden = true;
  document.body.style.overflow = '';
  activeDocId = null;
}

$('modal-close').addEventListener('click', closeModal);
$('btn-modal-close-bottom').addEventListener('click', closeModal);
$('modal-backdrop').addEventListener('click', closeModal);

// ── Download MD ───────────────────────────────────────────────
$('btn-download-md').addEventListener('click', async () => {
  if (!activeDocId) return;
  try {
    const res = await apiFetch(`/aegis/download_as_md?id=${activeDocId}`);
    if (!res.ok) {
      alert('No se pudo descargar el documento.');
      return;
    }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `aegis_doc_${activeDocId}.md`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert('Error al descargar: ' + err.message);
  }
});

// ── Generate ──────────────────────────────────────────────────
$('gen-form').addEventListener('submit', async e => {
  e.preventDefault();
  const resultEl = $('gen-result');
  resultEl.hidden = true;
  resultEl.className = 'gen-result';
  setLoading('btn-gen', true);

  const topicId = parseInt($('topic-id').value) || 0;

  try {
    const res = await apiFetch('/aegis/generate', {
      method: 'POST',
      body: JSON.stringify({ topicId, tweaks: {} }),
    });
    const data = await res.json();

    if (!res.ok) {
      resultEl.className = 'gen-result gen-result--error';
      resultEl.textContent = data.message || data.error || 'Error al generar';
    } else {
      resultEl.className = 'gen-result gen-result--ok';
      resultEl.textContent =
        `✓ Generación iniciada. ID de documento: ${data.documentId}. "
        + Estado: ${data.status || 'pending'}.`;
      // Auto-refresh docs after a brief delay
      setTimeout(() => {
        setView('documents');
        loadDocuments();
      }, 2500);
    }
    resultEl.hidden = false;
  } catch (err) {
    resultEl.className = 'gen-result gen-result--error';
    resultEl.textContent = 'Error de red: ' + err.message;
    resultEl.hidden = false;
  } finally {
    setLoading('btn-gen', false);
  }
});

// ── Bootstrap ─────────────────────────────────────────────────
(function init() {
  if (Auth.isLoggedIn()) {
    initApp();
    setPage('app');
    loadDocuments();
  } else {
    setPage('login');
  }
})();

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
