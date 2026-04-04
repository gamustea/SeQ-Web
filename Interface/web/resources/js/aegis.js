/* ============================================================
   aegis.js — Lógica de la interfaz de píldoras Aegis
   ============================================================ */
'use strict';

/* ── CONFIG ── */
const API_BASE  = 'http://localhost:5000';
const LOGIN_URL = '../auth/login.html';

const POLL_INTERVAL_MS  = 2500;
const POLL_MAX_ATTEMPTS = 60;   // 2.5 min máx

/* ══════════════════════════════════════════════════════════════
   SESSION — gestión de token con refresco automático
   (mismo patrón que los demás módulos de SeQ)
══════════════════════════════════════════════════════════════ */
const Session = (() => {
  let data = null;

  function load() {
    const raw = sessionStorage.getItem('seq_session');
    if (!raw) return false;
    try { data = JSON.parse(raw); return !!data.accessToken; }
    catch { return false; }
  }

  function save() {
    sessionStorage.setItem('seq_session', JSON.stringify(data));
  }

  async function getToken() {
    if (!data) return null;
    // Renueva si queda menos de 60 s de vida
    if (Date.now() > data.expiresAt - 60_000) {
      const ok = await refresh();
      if (!ok) return null;
    }
    return data.accessToken;
  }

  async function refresh() {
    if (!data?.refreshToken) return false;
    try {
      const res = await fetch(`${API_BASE}/oauth/token`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ grantType: 'refresh_token', refreshToken: data.refreshToken }),
      });
      if (!res.ok) return false;
      const d = await res.json();
      data.accessToken = d.access_token;
      data.expiresAt   = Date.now() + d.expires_in * 1000;
      save();
      return true;
    } catch { return false; }
  }

  async function authHeaders() {
    const t = await getToken();
    if (!t) { logout(); return null; }
    return { 'Authorization': `Bearer ${t}`, 'Content-Type': 'application/json' };
  }

  function logout() {
    const token = data?.accessToken;
    data = null;
    sessionStorage.removeItem('seq_session');
    if (token) {
      fetch(`${API_BASE}/oauth/revoke`, {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      }).catch(() => {});
    }
    window.location.href = LOGIN_URL;
  }

  function username() {
    if (!data?.accessToken) return '';
    try {
      const payload = JSON.parse(atob(data.accessToken.split('.')[1]));
      return payload.username || payload.sub || '';
    } catch { return ''; }
  }

  return { load, authHeaders, logout, username };
})();

/* ── Guardia de sesión ── */
if (!Session.load()) window.location.href = LOGIN_URL;
document.getElementById('session-user').textContent = Session.username();
document.getElementById('btn-logout').addEventListener('click', Session.logout);

/* ══════════════════════════════════════════════════════════════
   API HELPER
══════════════════════════════════════════════════════════════ */
async function apiFetch(path, options = {}) {
  const authH = await Session.authHeaders();
  if (!authH) return null;                        // Session.logout ya redirige
  const headers = { ...authH, ...(options.headers || {}) };
  // Si options.body ya existe y no es JSON, quitar Content-Type
  if (options.body instanceof FormData) delete headers['Content-Type'];
  return fetch(`${API_BASE}${path}`, { ...options, headers });
}

/* ══════════════════════════════════════════════════════════════
   STATE
══════════════════════════════════════════════════════════════ */
let selectedTopicId   = null;
let currentDocumentId = null;
let pollTimer         = null;
let pollAttempts      = 0;
let allDocs           = [];
let sortMode          = 'date-desc';

/* ── DOM REFS ── */
const topicGrid     = document.getElementById('topic-grid');
const btnGenerate   = document.getElementById('btn-generate');
const progressBlock = document.getElementById('progress-block');
const progressBar   = document.getElementById('progress-bar');
const progressText  = document.getElementById('progress-text');
const viewerEmpty   = document.getElementById('viewer-empty');
const viewerContent = document.getElementById('viewer-content');
const historyList   = document.getElementById('history-list');
const historyEmpty  = document.getElementById('history-empty');
const toastEl       = document.getElementById('toast');

/* ══════════════════════════════════════════════════════════════
   TOAST
══════════════════════════════════════════════════════════════ */
let _toastTimer;
function toast(msg, type = '') {
  clearTimeout(_toastTimer);
  toastEl.textContent = msg;
  toastEl.className = `toast visible${type ? ' toast--' + type : ''}`;
  _toastTimer = setTimeout(() => toastEl.classList.remove('visible'), 3400);
}

/* ══════════════════════════════════════════════════════════════
   UTILS
══════════════════════════════════════════════════════════════ */
function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('es-ES', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function statusLabel(s) {
  return { done: 'Listo', pending: 'Generando', error: 'Error' }[s] ?? s;
}

/* ══════════════════════════════════════════════════════════════
   TOPICS — GET /aegis/topics
══════════════════════════════════════════════════════════════ */
async function loadTopics() {
  try {
    const res = await apiFetch('/aegis/topics');
    if (!res || !res.ok) throw new Error(res?.status ?? 'sin respuesta');
    const data   = await res.json();
    const topics = Array.isArray(data) ? data : (data.topics || []);
    renderTopics(topics);
  } catch (e) {
    topicGrid.innerHTML =
      `<p class="viewer-empty__text">Error al cargar temas: ${escHtml(e.message)}</p>`;
  }
}

function renderTopics(topics) {
  topicGrid.innerHTML = '';
  if (!topics.length) {
    topicGrid.innerHTML = '<p class="viewer-empty__text">Sin temas disponibles</p>';
    return;
  }
  topics.forEach(t => {
    const btn = document.createElement('button');
    btn.className  = 'topic-btn';
    btn.dataset.id = t.id;
    btn.innerHTML  = `
      <span class="topic-btn__id">#${String(t.id).padStart(2,'0')}</span>
      <span class="topic-btn__name">${escHtml(t.name || t.title || 'Sin nombre')}</span>
      ${t.description
        ? `<span class="topic-btn__desc">${escHtml(t.description)}</span>` : ''}`;
    btn.addEventListener('click', () => selectTopic(t.id, btn));
    topicGrid.appendChild(btn);
  });
}

function selectTopic(id, btn) {
  document.querySelectorAll('.topic-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  selectedTopicId    = id;
  btnGenerate.disabled = false;
}

/* ══════════════════════════════════════════════════════════════
   HISTORY — GET /aegis/documents
══════════════════════════════════════════════════════════════ */
const STATUS_ORDER = { done: 0, pending: 1, error: 2 };
const SORT_FNS = {
  'date-desc': (a,b) => new Date(b.generatedAt||0) - new Date(a.generatedAt||0),
  'date-asc':  (a,b) => new Date(a.generatedAt||0) - new Date(b.generatedAt||0),
  'name-asc':  (a,b) => (a.title||'').localeCompare(b.title||'','es'),
  'status':    (a,b) => (STATUS_ORDER[a.status]??9) - (STATUS_ORDER[b.status]??9)
                     || new Date(b.generatedAt||0) - new Date(a.generatedAt||0),
};

async function loadHistory() {
  try {
    const res = await apiFetch('/aegis/documents');
    if (!res || !res.ok) return;
    const data = await res.json();
    allDocs = data.documents || [];
    renderHistory();
  } catch { /* silent */ }
}

function renderHistory() {
  const countEl = document.getElementById('history-count');
  if (!allDocs.length) {
    historyEmpty.style.display = 'block';
    historyList.querySelectorAll('.history-item').forEach(el => el.remove());
    if (countEl) countEl.textContent = '';
    return;
  }
  historyEmpty.style.display = 'none';
  if (countEl) countEl.textContent = `${allDocs.length} doc${allDocs.length !== 1 ? 's' : ''}`;

  const sorted = [...allDocs].sort(SORT_FNS[sortMode] || SORT_FNS['date-desc']);
  const newIds = new Set(sorted.map(d => String(d.id)));
  historyList.querySelectorAll('.history-item').forEach(el => {
    if (!newIds.has(el.dataset.docId)) el.remove();
  });

  const frag = document.createDocumentFragment();
  sorted.forEach(doc => {
    let item = historyList.querySelector(`.history-item[data-doc-id="${doc.id}"]`);
    if (item) {
      const badge = item.querySelector('.history-item__status');
      if (badge) {
        badge.className   = `history-item__status status--${doc.status}`;
        badge.textContent = statusLabel(doc.status);
      }
    } else {
      item = document.createElement('div');
      item.className     = 'history-item';
      item.dataset.docId = doc.id;
      item.innerHTML = `
        <div class="history-item__header">
          <span class="history-item__title">${escHtml(doc.title || 'Sin título')}</span>
          <span class="history-item__status status--${doc.status}">${statusLabel(doc.status)}</span>
        </div>
        <div class="history-item__meta">
          <span class="history-item__topic">Tema #${doc.topicId ?? '—'}</span>
          <span class="history-item__date">${formatDate(doc.generatedAt)}</span>
        </div>
        <div class="history-item__actions">
          ${doc.status === 'done' ? `
            <button class="btn btn--sm btn--ghost" data-action="view"     data-id="${doc.id}">Ver</button>
            <button class="btn btn--sm btn--ghost" data-action="dl-md"    data-id="${doc.id}">MD</button>
            <button class="btn btn--sm btn--ghost" data-action="dl-json"  data-id="${doc.id}">JSON</button>
          ` : ''}
          <button class="btn btn--sm btn--ghost btn--danger" data-action="delete" data-id="${doc.id}">✕</button>
        </div>`;
      item.querySelectorAll('[data-action]').forEach(b =>
        b.addEventListener('click', handleHistoryAction));
    }
    frag.appendChild(item);
  });
  historyList.innerHTML = '';
  historyList.appendChild(frag);
}

function handleHistoryAction(e) {
  const btn    = e.currentTarget;
  const action = btn.dataset.action;
  const id     = parseInt(btn.dataset.id, 10);
  if (action === 'view')     loadAndShowDocument(id);
  if (action === 'dl-md')    downloadExport(id, 'md');
  if (action === 'dl-json')  downloadExport(id, 'json');
  if (action === 'delete')   confirmDelete(id);
}

document.getElementById('sort-select')?.addEventListener('change', e => {
  sortMode = e.target.value;
  renderHistory();
});

/* ══════════════════════════════════════════════════════════════
   GENERATE — POST /aegis/generate
══════════════════════════════════════════════════════════════ */
function buildTweaks() {
  const v = id => document.getElementById(id)?.value?.trim() ?? '';
  const brandsRaw = v('input-brands');
  return {
    company:          v('input-company')  || 'Empresa',
    language:         v('input-language') || 'es',
    tone:             v('input-tone')     || 'profesional',
    audienceLevel:    v('input-audience') || 'mixed',
    mentionContact:   v('input-contact')  || '',
    associatedBrands: brandsRaw
      ? brandsRaw.split(',').map(s => s.trim()).filter(Boolean) : [],
    sector:           v('input-sector')   || 'tecnología',
    topicFocus:       v('input-focus')    || '',
  };
}

btnGenerate?.addEventListener('click', startGenerate);

async function startGenerate() {
  if (!selectedTopicId) { toast('Selecciona un tema primero', 'warn'); return; }

  btnGenerate.disabled = true;
  showProgress(true);
  setProgress(0, 'Iniciando generación…');
  stopPolling();

  try {
    const res = await apiFetch('/aegis/generate', {
      method: 'POST',
      body:   JSON.stringify({ topicId: selectedTopicId, tweaks: buildTweaks() }),
    });
    if (!res) return;

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error_description || err.message || `HTTP ${res.status}`);
    }

    const data = await res.json();
    currentDocumentId = data.documentId;
    toast(`Generación iniciada (doc #${currentDocumentId})`, 'info');
    startPolling(currentDocumentId);
  } catch (e) {
    showProgress(false);
    btnGenerate.disabled = false;
    toast(`Error al generar: ${e.message}`, 'error');
  }
}

/* ══════════════════════════════════════════════════════════════
   POLLING — GET /aegis/status?id=N
══════════════════════════════════════════════════════════════ */
const STATUS_MSGS = [
  'Iniciando generación…', 'Buscando alertas de seguridad…',
  'Consultando INCIBE y CIRCL…', 'Generando contenido con IA…',
  'Validando estructura JSON…', 'Procesando consejos prácticos…',
  'Finalizando píldora…',
];

function startPolling(docId) {
  pollAttempts = 0;
  pollTimer    = setInterval(() => pollStatus(docId), POLL_INTERVAL_MS);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

async function pollStatus(docId) {
  pollAttempts++;
  if (pollAttempts > POLL_MAX_ATTEMPTS) {
    stopPolling(); showProgress(false); btnGenerate.disabled = false;
    toast('Tiempo de espera agotado', 'error');
    return;
  }

  const pct = Math.min(90, Math.round((pollAttempts / POLL_MAX_ATTEMPTS) * 90));
  setProgress(pct, STATUS_MSGS[Math.floor(pollAttempts / 5) % STATUS_MSGS.length]);

  try {
    const res = await apiFetch(`/aegis/status?id=${docId}`);
    if (!res || !res.ok) return;
    const data = await res.json();

    if (data.status === 'done') {
      stopPolling();
      setProgress(100, '¡Píldora generada!');
      setTimeout(async () => {
        showProgress(false);
        btnGenerate.disabled = false;
        await loadAndShowDocument(docId);
        await loadHistory();
      }, 600);
    } else if (data.status === 'error') {
      stopPolling(); showProgress(false); btnGenerate.disabled = false;
      toast('Error durante la generación', 'error');
    }
  } catch { /* err de red — seguir intentando */ }
}

/* ── Progress helpers ── */
function showProgress(visible) {
  if (progressBlock) progressBlock.style.display = visible ? 'flex' : 'none';
}
function setProgress(pct, msg) {
  if (progressBar)  progressBar.style.width   = `${pct}%`;
  if (progressText) progressText.textContent  = msg;
}

/* ══════════════════════════════════════════════════════════════
   DOCUMENT VIEWER — GET /aegis/document?id=N
══════════════════════════════════════════════════════════════ */
async function loadAndShowDocument(docId) {
  try {
    const res = await apiFetch(`/aegis/document?id=${docId}`);
    if (!res || !res.ok) { toast('No se pudo cargar el documento', 'error'); return; }
    const doc = await res.json();
    currentDocumentId = docId;
    renderDocument(doc);
    // Marcar activo en historial
    document.querySelectorAll('.history-item').forEach(el => {
      el.classList.toggle('active', parseInt(el.dataset.docId) === docId);
    });
  } catch (e) {
    toast(`Error al cargar documento: ${e.message}`, 'error');
  }
}

function renderDocument(doc) {
  const pill   = doc.pill   || {};
  const alerts = doc.alerts || [];

  viewerEmpty.style.display   = 'none';
  viewerContent.style.display = 'block';
  viewerContent.innerHTML     = '';

  /* ── Cabecera ── */
  const header = document.createElement('div');
  header.className = 'pill-header';
  header.innerHTML = `
    <div class="pill-header__meta">
      <span class="pill-header__id">Doc #${doc.id}</span>
      <span class="pill-header__topic">Tema #${doc.topicId ?? '—'}</span>
      <span class="pill-header__date">${formatDate(doc.generatedAt)}</span>
    </div>
    <h2 class="pill-header__title">${escHtml(pill.subtitle || doc.title || 'Sin título')}</h2>
    <div class="pill-header__actions">
      <button class="btn btn--sm btn--primary" id="btn-dl-md">⬇ Markdown</button>
      <button class="btn btn--sm btn--ghost"   id="btn-dl-json">⬇ JSON</button>
      <button class="btn btn--sm btn--ghost"   id="btn-preview-md">👁 Preview</button>
    </div>`;
  viewerContent.appendChild(header);
  header.querySelector('#btn-dl-md')
    .addEventListener('click', () => downloadExport(doc.id, 'md'));
  header.querySelector('#btn-dl-json')
    .addEventListener('click', () => downloadExport(doc.id, 'json'));
  header.querySelector('#btn-preview-md')
    .addEventListener('click', () => previewMarkdown(doc.id));

  /* ── Divisor ── */
  const div = document.createElement('div');
  div.className = 'pill-divider';
  viewerContent.appendChild(div);

  /* ── Intro ── */
  if (pill.intro) {
    const el = document.createElement('div');
    el.className = 'pill-intro';
    el.innerHTML = `<p>${escHtml(pill.intro)}</p>`;
    viewerContent.appendChild(el);
  }

  /* ── Tips ── */
  const tips = pill.tips || [];
  if (tips.length) {
    const section = document.createElement('div');
    section.className = 'pill-tips';
    section.innerHTML = '<p class="pill-tips__heading">💡 Consejos Prácticos</p>';
    tips.forEach((tip, i) => {
      const links = (tip.links || []).map(lk =>
        `<a href="${escHtml(lk.url)}" target="_blank" rel="noopener noreferrer">${escHtml(lk.text)}</a>`
      ).join(' · ');
      const el = document.createElement('div');
      el.className = 'pill-tip';
      el.innerHTML = `
        <div class="pill-tip__num">${i + 1}</div>
        <div class="pill-tip__body">
          <strong class="pill-tip__headline">${escHtml(tip.headline || '')}</strong>
          <p>${escHtml(tip.body || '')}</p>
          ${links ? `<div class="pill-tip__links">${links}</div>` : ''}
        </div>`;
      section.appendChild(el);
    });
    viewerContent.appendChild(section);
  }

  /* ── Closing ── */
  if (pill.closing) {
    const el = document.createElement('div');
    el.className = 'pill-closing';
    el.innerHTML = `<p>${escHtml(pill.closing)}</p>`;
    viewerContent.appendChild(el);
  }

  /* ── Alertas ── */
  if (alerts.length) {
    const section = document.createElement('div');
    section.className = 'pill-alerts';
    section.innerHTML = '<p class="pill-alerts__heading">🔴 Alertas de Seguridad</p>';
    const SEV_ICON = { crítica:'🔴', alta:'🟠', media:'🟡', baja:'🟢', informativa:'🔵' };
    alerts.forEach(a => {
      const icon   = SEV_ICON[(a.severity||'').toLowerCase()] ?? '⚪';
      const brands = (a.affectedBrands || a.brands || []).join(', ');
      const el = document.createElement('div');
      el.className = `pill-alert pill-alert--${(a.severity||'info').toLowerCase()}`;
      el.innerHTML = `
        <div class="pill-alert__header">
          <span class="pill-alert__icon">${icon}</span>
          <a class="pill-alert__title" href="${escHtml(a.url||'#')}"
             target="_blank" rel="noopener noreferrer">${escHtml(a.title||'Alerta')}</a>
          ${a.severity ? `<span class="pill-alert__severity">${escHtml(a.severity.toUpperCase())}</span>` : ''}
        </div>
        ${a.description ? `<p class="pill-alert__desc">${escHtml(a.description)}</p>` : ''}
        <div class="pill-alert__meta">
          <span>${escHtml(a.sourceLabel||a.source||'')}</span>
          ${a.published ? `<span>${escHtml(a.published)}</span>` : ''}
          ${brands       ? `<span>${escHtml(brands)}</span>`      : ''}
        </div>`;
      section.appendChild(el);
    });
    viewerContent.appendChild(section);
  }
}

/* ══════════════════════════════════════════════════════════════
   EXPORT / DOWNLOAD
══════════════════════════════════════════════════════════════ */

/* GET /aegis/export/<doc_id>/download?format=md&inline=false */
async function downloadExport(docId, format = 'md', inline = false) {
  try {
    const res = await apiFetch(
      `/aegis/export/${docId}/download?format=${format}&inline=${inline}`
    );
    if (!res || !res.ok) throw new Error(`HTTP ${res?.status ?? '?'}`);
    const blob     = await res.blob();
    const filename = extractFilename(res, `aegis_doc_${docId}.${format}`);
    triggerDownload(blob, filename);
    toast(`Descargando ${format.toUpperCase()}…`, 'info');
  } catch (e) {
    toast(`Error al descargar: ${e.message}`, 'error');
  }
}

/* GET /aegis/export/md/<doc_id>?inline=true */
async function previewMarkdown(docId) {
  try {
    const res = await apiFetch(`/aegis/export/md/${docId}?inline=true`);
    if (!res || !res.ok) throw new Error(`HTTP ${res?.status}`);
    const text = await res.text();
    openMarkdownPreview(text);
  } catch (e) {
    toast(`Error al previsualizar: ${e.message}`, 'error');
  }
}

function extractFilename(res, fallback) {
  const cd = res.headers.get('Content-Disposition') || '';
  const m  = cd.match(/filename="?([^";\n]+)"?/i);
  return m ? m[1] : fallback;
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}

function openMarkdownPreview(mdText) {
  const win = window.open('', '_blank');
  if (!win) { toast('Permite ventanas emergentes para el preview', 'warn'); return; }
  win.document.write(`<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Preview Markdown</title>
<style>body{font-family:monospace;max-width:820px;margin:2rem auto;padding:0 1rem;
background:#080c14;color:#e2e8f0;line-height:1.7}
pre{white-space:pre-wrap;word-break:break-word}</style>
</head><body><pre>${escHtml(mdText)}</pre></body></html>`);
  win.document.close();
}

/* ══════════════════════════════════════════════════════════════
   DELETE — DELETE /aegis/document?id=N
══════════════════════════════════════════════════════════════ */
function confirmDelete(docId) {
  if (!confirm(`¿Eliminar el documento #${docId}? Esta acción no se puede deshacer.`)) return;
  deleteDocument(docId);
}

async function deleteDocument(docId) {
  try {
    const res = await apiFetch(`/aegis/document?id=${docId}`, { method: 'DELETE' });
    if (!res || !res.ok) {
      const err = await res?.json().catch(() => ({}));
      throw new Error(err?.message || `HTTP ${res?.status}`);
    }
    toast(`Documento #${docId} eliminado`, 'info');
    allDocs = allDocs.filter(d => d.id !== docId);
    renderHistory();
    if (currentDocumentId === docId) {
      viewerContent.style.display = 'none';
      viewerContent.innerHTML     = '';
      viewerEmpty.style.display   = 'flex';
      currentDocumentId = null;
    }
  } catch (e) {
    toast(`Error al eliminar: ${e.message}`, 'error');
  }
}

/* ══════════════════════════════════════════════════════════════
   EXPORT FORMATS — GET /aegis/export/formats
══════════════════════════════════════════════════════════════ */
async function loadExportFormats() {
  try {
    const res  = await apiFetch('/aegis/export/formats');
    if (!res || !res.ok) return;
    const data = await res.json();
    const container = document.getElementById('export-formats');
    if (!container) return;
    container.innerHTML = (data.formats || [])
      .filter(f => !f.coming_soon)
      .map(f => `<span class="export-badge" title="${escHtml(f.description)}">${escHtml(f.name)}</span>`)
      .join('');
  } catch { /* no crítico */ }
}

/* ══════════════════════════════════════════════════════════════
   INIT
══════════════════════════════════════════════════════════════ */
(async function init() {
  btnGenerate.disabled = true;
  showProgress(false);
  await Promise.all([loadTopics(), loadHistory()]);
  loadExportFormats();
})();
