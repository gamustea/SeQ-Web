/* ============================================================
   aegis.js — Lógica específica del módulo Aegis
   Depende de: shared.js  (SeqSession, SeqUI, SeqToast, apiFetch)
   ============================================================ */
'use strict';

/* ── CONFIG local ── */
const POLL_INTERVAL_MS  = 60_000;   // 1 minuto
const POLL_MAX_ATTEMPTS = 30;       // 30 minutos máximo

/* ══════════════════════════════════════════════════════════════
   DOM ELEMENTS
══════════════════════════════════════════════════════════════ */
const topicGrid     = document.getElementById('topic-grid');
const btnGenerate   = document.getElementById('btn-generate');
const btnRefresh    = document.getElementById('btn-refresh-status');
const progressBlock = document.getElementById('progress-block');
const progressBar   = document.getElementById('progress-bar');
const progressText  = document.getElementById('progress-text');
const viewerEmpty   = document.getElementById('viewer-empty');
const viewerContent = document.getElementById('viewer-content');
const historyList   = document.getElementById('history-list');
const historyEmpty  = document.getElementById('history-empty');

/* ══════════════════════════════════════════════════════════════
   STATE
══════════════════════════════════════════════════════════════ */
let selectedTopicId   = null;
let currentDocumentId = null;
let pollTimer         = null;
let pollAttempts      = 0;
let isChecking        = false;
let allDocs           = [];
let sortMode          = 'date-desc';

/* ══════════════════════════════════════════════════════════════
   PROGRESS
══════════════════════════════════════════════════════════════ */
function showProgress(visible) {
  if (progressBlock) progressBlock.style.display = visible ? 'flex' : 'none';
}

function setProgress(pct, msg) {
  if (progressBar)  progressBar.style.width    = `${pct}%`;
  if (progressText) progressText.textContent   = msg;
}

/* ══════════════════════════════════════════════════════════════
   POLLING
══════════════════════════════════════════════════════════════ */
async function checkStatusNow(docId) {
  if (isChecking || !docId) return;
  isChecking = true;

  try {
    const res = await apiFetch(`/aegis/status?id=${docId}`);
    if (!res?.ok) return;
    const data = await res.json();
    await handleStatusUpdate(data, docId);
  } catch (e) {
    console.error('[Aegis] Error checking status:', e);
  } finally {
    isChecking = false;
  }
}

async function handleStatusUpdate(data, docId) {
  pollAttempts++;
  const estimatedPercent = Math.min(95, 10 + pollAttempts * 3);

  if (data.status === 'done') {
    stopPolling();
    localStorage.removeItem('aegis_pending_doc');
    setProgress(100, '¡Píldora completada!');
    SeqToast.show('Píldora generada correctamente', 'success');
    setTimeout(async () => {
      showProgress(false);
      if (btnGenerate) btnGenerate.disabled = false;
      await loadAndShowDocument(docId);
      await loadHistory();
    }, 800);

  } else if (data.status === 'error') {
    stopPolling();
    localStorage.removeItem('aegis_pending_doc');
    setProgress(0, 'Error en la generación');
    showProgress(false);
    if (btnGenerate) btnGenerate.disabled = false;
    SeqToast.show('Error durante la generación', 'error');

  } else {
    const STAGE_MSG = {
      researching: '🔍 Investigando alertas de seguridad…',
      analyzing:   '📊 Analizando vulnerabilidades…',
      writing:     '✍️ Redactando contenido…',
      reviewing:   '🔍 Revisando estructura…',
      finalizing:  '✅ Finalizando documento…',
    };
    const msg = (data.stage && STAGE_MSG[data.stage])
      || data.message
      || `Generando… (${pollAttempts} min)`;
    setProgress(estimatedPercent, msg);
  }
}

function startPolling(docId) {
  stopPolling();
  pollAttempts = 0;
  pollTimer = setInterval(() => {
    if (pollAttempts >= POLL_MAX_ATTEMPTS) {
      stopPolling();
      SeqToast.show('Tiempo máximo de espera agotado (30 min)', 'warn');
      if (btnGenerate) btnGenerate.disabled = false;
      return;
    }
    checkStatusNow(docId);
  }, POLL_INTERVAL_MS);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

/* ── Botón de actualización manual ── */
if (btnRefresh) {
  btnRefresh.addEventListener('click', async () => {
    if (!currentDocumentId || isChecking) return;
    btnRefresh.classList.add('spinning');
    progressText.classList.add('updating');
    progressText.textContent = 'Consultando estado…';
    await checkStatusNow(currentDocumentId);
    setTimeout(() => {
      btnRefresh.classList.remove('spinning');
      progressText.classList.remove('updating');
    }, 500);
  });
}

/* ══════════════════════════════════════════════════════════════
   TOPICS
══════════════════════════════════════════════════════════════ */
async function loadTopics() {
  try {
    const res = await apiFetch('/aegis/topics');
    if (!res?.ok) throw new Error(res?.status ?? 'sin respuesta');
    const data   = await res.json();
    const topics = Array.isArray(data) ? data : (data.topics || []);
    renderTopics(topics);
  } catch (e) {
    console.error('[Aegis] Error loading topics:', e);
    topicGrid.innerHTML = `<p class="viewer-empty__text">Error al cargar temas</p>`;
  }
}

function renderTopics(topics) {
  if (!topicGrid) return;
  topicGrid.innerHTML = '';
  if (!topics.length) { topicGrid.innerHTML = '<p class="viewer-empty__text">Sin temas disponibles</p>'; return; }

  topics.forEach(t => {
    const btn = document.createElement('button');
    btn.className  = 'topic-btn';
    btn.dataset.id = t.id;
    btn.innerHTML  = `
      <span class="topic-btn__id">#${String(t.id).padStart(2, '0')}</span>
      <span class="topic-btn__name">${SeqUI.escHtml(t.name || t.title || 'Sin nombre')}</span>
      ${t.description ? `<span class="topic-btn__desc">${SeqUI.escHtml(t.description)}</span>` : ''}`;
    btn.addEventListener('click', () => selectTopic(t.id, btn));
    topicGrid.appendChild(btn);
  });
}

function selectTopic(id, btn) {
  document.querySelectorAll('.topic-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  selectedTopicId = id;
  if (btnGenerate) btnGenerate.disabled = false;
}

/* ══════════════════════════════════════════════════════════════
   GENERATE
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
    associatedBrands: brandsRaw ? brandsRaw.split(',').map(s => s.trim()).filter(Boolean) : [],
    sector:           v('input-sector')   || 'tecnología',
    topicFocus:       v('input-focus')    || '',
  };
}

if (btnGenerate) {
  btnGenerate.addEventListener('click', async () => {
    if (!selectedTopicId) { SeqToast.show('Selecciona un tema primero', 'warn'); return; }

    btnGenerate.disabled = true;
    showProgress(true);
    setProgress(10, 'Generación iniciada…');
    stopPolling();

    try {
      const res = await apiFetch('/aegis/generate', {
        method: 'POST',
        body:   JSON.stringify({ topicId: selectedTopicId, tweaks: buildTweaks() }),
      });
      if (!res) throw new Error('No hay conexión con el servidor');
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error_description || err.message || `HTTP ${res.status}`);
      }

      const data = await res.json();
      currentDocumentId = data.documentId;

      localStorage.setItem('aegis_pending_doc', JSON.stringify({
        docId: currentDocumentId, startedAt: Date.now(), topicId: selectedTopicId,
      }));

      SeqToast.show(`Generación iniciada (doc #${currentDocumentId})`, 'success');
      await checkStatusNow(currentDocumentId);
      startPolling(currentDocumentId);

    } catch (e) {
      console.error('[Aegis] Generation error:', e);
      showProgress(false);
      btnGenerate.disabled = false;
      stopPolling();
      SeqToast.show(`Error al generar: ${e.message}`, 'error');
    }
  });
}

/* ══════════════════════════════════════════════════════════════
   RECOVERY
══════════════════════════════════════════════════════════════ */
async function checkPendingGeneration() {
  const pending = localStorage.getItem('aegis_pending_doc');
  if (!pending) return;
  try {
    const { docId, startedAt } = JSON.parse(pending);
    if (Date.now() - startedAt < 30 * 60 * 1000) {
      currentDocumentId = docId;
      if (btnGenerate) btnGenerate.disabled = true;
      showProgress(true);
      setProgress(10, 'Recuperando generación en curso…');
      await checkStatusNow(docId);
      startPolling(docId);
      SeqToast.show('Generación en curso recuperada', 'info');
    } else {
      localStorage.removeItem('aegis_pending_doc');
    }
  } catch {
    localStorage.removeItem('aegis_pending_doc');
  }
}

/* ══════════════════════════════════════════════════════════════
   HISTORY
══════════════════════════════════════════════════════════════ */
const STATUS_ORDER = { done: 0, pending: 1, error: 2 };
const SORT_FNS = {
  'date-desc': (a, b) => new Date(b.generatedAt || 0) - new Date(a.generatedAt || 0),
  'date-asc':  (a, b) => new Date(a.generatedAt || 0) - new Date(b.generatedAt || 0),
  'name-asc':  (a, b) => (a.title || '').localeCompare(b.title || '', 'es'),
  'status':    (a, b) => ((STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9))
                      || (new Date(b.generatedAt || 0) - new Date(a.generatedAt || 0)),
};

async function loadHistory() {
  const res = await apiFetch('/aegis/documents');
  if (!res?.ok) return;
  const data = await res.json();
  allDocs = data.documents || [];
  renderHistory();
}

function statusLabel(s) {
  return { done: 'Listo', pending: 'Generando', error: 'Error' }[s] ?? s;
}

function renderHistory() {
  const countEl = document.getElementById('history-count');
  if (!allDocs.length) {
    if (historyEmpty) historyEmpty.style.display = 'block';
    historyList.innerHTML = '';
    if (countEl) countEl.textContent = '';
    return;
  }
  if (historyEmpty) historyEmpty.style.display = 'none';
  if (countEl) countEl.textContent = `${allDocs.length} doc${allDocs.length !== 1 ? 's' : ''}`;

  const sorted = [...allDocs].sort(SORT_FNS[sortMode] || SORT_FNS['date-desc']);
  const newIds = new Set(sorted.map(d => String(d.id)));

  Array.from(historyList.children).forEach(el => { if (!newIds.has(el.dataset.docId)) el.remove(); });

  const frag = document.createDocumentFragment();
  sorted.forEach(doc => {
    let item = historyList.querySelector(`.history-item[data-doc-id="${doc.id}"]`);
    if (item) {
      const badge = item.querySelector('.history-item__status');
      if (badge && !badge.classList.contains(`status--${doc.status}`)) {
        badge.className = `history-item__status status--${doc.status}`;
        badge.textContent = statusLabel(doc.status);
      }
    } else {
      item = document.createElement('div');
      item.className = 'history-item';
      item.dataset.docId = doc.id;
      item.innerHTML = `
        <div class="history-item__header">
          <span class="history-item__title">${SeqUI.escHtml(doc.title || 'Sin título')}</span>
          <span class="history-item__status status--${doc.status}">${statusLabel(doc.status)}</span>
        </div>
        <div class="history-item__meta">
          <span class="history-item__topic">Tema #${doc.topicId ?? '—'}</span>
          <span class="history-item__date">${SeqUI.formatDate(doc.generatedAt)}</span>
        </div>
        <div class="history-item__actions">
          ${doc.status === 'done' ? `
            <button class="btn btn--sm btn--ghost" data-action="view"    data-id="${doc.id}">Ver</button>
            <button class="btn btn--sm btn--ghost" data-action="dl-md"   data-id="${doc.id}">MD</button>
            <button class="btn btn--sm btn--ghost" data-action="dl-json" data-id="${doc.id}">JSON</button>
          ` : ''}
          <button class="btn btn--sm btn--ghost btn--danger" data-action="delete" data-id="${doc.id}">✕</button>
        </div>`;
      item.querySelectorAll('[data-action]').forEach(b => b.addEventListener('click', handleHistoryAction));
    }
    frag.appendChild(item);
  });
  historyList.appendChild(frag);
}

function handleHistoryAction(e) {
  const { action, id } = e.currentTarget.dataset;
  const docId = parseInt(id, 10);
  if      (action === 'view')    loadAndShowDocument(docId);
  else if (action === 'dl-md')   downloadExport(docId, 'md');
  else if (action === 'dl-json') downloadExport(docId, 'json');
  else if (action === 'delete')  confirmDelete(docId);
}

document.getElementById('sort-select')?.addEventListener('change', e => {
  sortMode = e.target.value;
  renderHistory();
});

/* ══════════════════════════════════════════════════════════════
   DOCUMENT VIEWER
══════════════════════════════════════════════════════════════ */
async function loadAndShowDocument(docId) {
  const res = await apiFetch(`/aegis/document?id=${docId}`);
  if (!res?.ok) { SeqToast.show('No se pudo cargar el documento', 'error'); return; }
  const doc = await res.json();
  currentDocumentId = docId;
  renderDocument(doc);
  document.querySelectorAll('.history-item').forEach(el =>
    el.classList.toggle('active', parseInt(el.dataset.docId) === docId));
}

function renderDocument(doc) {
  const pill   = doc.pill   || {};
  const alerts = doc.alerts || [];

  viewerEmpty.style.display  = 'none';
  viewerContent.style.display = 'block';
  viewerContent.innerHTML     = '';

  /* Header */
  const header = document.createElement('div');
  header.className = 'pill-header';
  header.innerHTML = `
    <div class="pill-header__meta">
      <span class="pill-header__id">Doc #${doc.id}</span>
      <span class="pill-header__topic">Tema #${doc.topicId ?? '—'}</span>
      <span class="pill-header__date">${SeqUI.formatDate(doc.generatedAt)}</span>
    </div>
    <h2 class="pill-header__title">${SeqUI.escHtml(pill.subtitle || doc.title || 'Sin título')}</h2>
    <div class="pill-header__actions">
      <button class="btn btn--sm btn--primary" id="btn-dl-md">⬇ Markdown</button>
      <button class="btn btn--sm btn--ghost"   id="btn-dl-json">⬇ JSON</button>
      <button class="btn btn--sm btn--ghost"   id="btn-preview-md">👁 Preview</button>
    </div>`;
  viewerContent.appendChild(header);
  header.querySelector('#btn-dl-md')?.addEventListener('click',      () => downloadExport(doc.id, 'md'));
  header.querySelector('#btn-dl-json')?.addEventListener('click',    () => downloadExport(doc.id, 'json'));
  header.querySelector('#btn-preview-md')?.addEventListener('click', () => previewMarkdown(doc.id));

  /* Divider */
  const divEl = document.createElement('div');
  divEl.className = 'pill-divider';
  viewerContent.appendChild(divEl);

  /* Intro */
  if (pill.intro) {
    const el = document.createElement('div');
    el.className = 'pill-intro';
    el.innerHTML = `<p>${SeqUI.escHtml(pill.intro)}</p>`;
    viewerContent.appendChild(el);
  }

  /* Tips */
  if (pill.tips?.length) {
    const section = document.createElement('div');
    section.className = 'pill-tips';
    section.innerHTML = '<p class="pill-tips__heading">💡 Consejos Prácticos</p>';
    pill.tips.forEach((tip, i) => {
      const links = (tip.links || [])
        .map(lk => `<a href="${SeqUI.escHtml(lk.url)}" target="_blank" rel="noopener noreferrer">${SeqUI.escHtml(lk.text)}</a>`)
        .join(' · ');
      const el = document.createElement('div');
      el.className = 'pill-tip';
      el.innerHTML = `
        <div class="pill-tip__num">${i + 1}</div>
        <div class="pill-tip__body">
          <strong class="pill-tip__headline">${SeqUI.escHtml(tip.headline || '')}</strong>
          <p>${SeqUI.escHtml(tip.body || '')}</p>
          ${links ? `<div class="pill-tip__links">${links}</div>` : ''}
        </div>`;
      section.appendChild(el);
    });
    viewerContent.appendChild(section);
  }

  /* Closing */
  if (pill.closing) {
    const el = document.createElement('div');
    el.className = 'pill-closing';
    el.innerHTML = `<p>${SeqUI.escHtml(pill.closing)}</p>`;
    viewerContent.appendChild(el);
  }

  /* Alerts */
  if (alerts.length) {
    const section = document.createElement('div');
    section.className = 'pill-alerts';
    section.innerHTML = '<p class="pill-alerts__heading">🔴 Alertas de Seguridad</p>';
    const SEV_ICON = { crítica:'🔴', alta:'🟠', media:'🟡', baja:'🟢', informativa:'🔵' };
    alerts.forEach(a => {
      const icon   = SEV_ICON[(a.severity || '').toLowerCase()] ?? '⚪';
      const brands = (a.affectedBrands || a.brands || []).join(', ');
      const el = document.createElement('div');
      el.className = `pill-alert pill-alert--${(a.severity || 'info').toLowerCase()}`;
      el.innerHTML = `
        <div class="pill-alert__header">
          <span class="pill-alert__icon">${icon}</span>
          <a class="pill-alert__title" href="${SeqUI.escHtml(a.url || '#')}" target="_blank" rel="noopener noreferrer">${SeqUI.escHtml(a.title || 'Alerta')}</a>
          ${a.severity ? `<span class="pill-alert__severity">${SeqUI.escHtml(a.severity.toUpperCase())}</span>` : ''}
        </div>
        ${a.description ? `<p class="pill-alert__desc">${SeqUI.escHtml(a.description)}</p>` : ''}
        <div class="pill-alert__meta">
          <span>${SeqUI.escHtml(a.sourceLabel || a.source || '')}</span>
          ${a.published ? `<span>${SeqUI.escHtml(a.published)}</span>` : ''}
          ${brands       ? `<span>${SeqUI.escHtml(brands)}</span>`     : ''}
        </div>`;
      section.appendChild(el);
    });
    viewerContent.appendChild(section);
  }
}

/* ══════════════════════════════════════════════════════════════
   EXPORT / DOWNLOAD
══════════════════════════════════════════════════════════════ */
async function downloadExport(docId, format = 'md') {
  try {
    const res = await apiFetch(`/aegis/export/${docId}/download?format=${format}&inline=false`);
    if (!res?.ok) throw new Error(`HTTP ${res?.status ?? '?'}`);
    const blob = await res.blob();
    const cd   = res.headers.get('Content-Disposition') || '';
    const name = cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? `aegis_doc_${docId}.${format}`;
    _triggerDownload(blob, name);
    SeqToast.show(`Descargando ${format.toUpperCase()}…`, 'info');
  } catch (e) {
    SeqToast.show(`Error al descargar: ${e.message}`, 'error');
  }
}

async function previewMarkdown(docId) {
  try {
    const res = await apiFetch(`/aegis/export/md/${docId}?inline=true`);
    if (!res?.ok) throw new Error(`HTTP ${res?.status}`);
    const text = await res.text();
    const win  = window.open('', '_blank');
    if (!win) { SeqToast.show('Permite ventanas emergentes para el preview', 'warn'); return; }
    win.document.write(`<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Preview Markdown</title>
<style>body{font-family:monospace;max-width:820px;margin:2rem auto;padding:0 1rem;
background:#080c14;color:#e2e8f0;line-height:1.7}pre{white-space:pre-wrap;word-break:break-word}</style>
</head><body><pre>${SeqUI.escHtml(text)}</pre></body></html>`);
    win.document.close();
  } catch (e) {
    SeqToast.show(`Error al previsualizar: ${e.message}`, 'error');
  }
}

/* ══════════════════════════════════════════════════════════════
   DELETE
══════════════════════════════════════════════════════════════ */
function confirmDelete(docId) {
  if (!confirm(`¿Eliminar el documento #${docId}? Esta acción no se puede deshacer.`)) return;
  deleteDocument(docId);
}

async function deleteDocument(docId) {
  try {
    const res = await apiFetch(`/aegis/document?id=${docId}`, { method: 'DELETE' });
    if (!res?.ok) {
      const err = await res?.json().catch(() => ({}));
      throw new Error(err?.message || `HTTP ${res?.status}`);
    }
    SeqToast.show(`Documento #${docId} eliminado`, 'info');
    allDocs = allDocs.filter(d => d.id !== docId);
    renderHistory();
    if (currentDocumentId === docId) {
      viewerContent.style.display = 'none';
      viewerContent.innerHTML     = '';
      viewerEmpty.style.display   = 'flex';
      currentDocumentId = null;
    }
  } catch (e) {
    SeqToast.show(`Error al eliminar: ${e.message}`, 'error');
  }
}

/* ══════════════════════════════════════════════════════════════
   UTIL LOCAL
══════════════════════════════════════════════════════════════ */
function _triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}

/* ══════════════════════════════════════════════════════════════
   INIT
══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  if (!SeqUI.requireSession()) return;
  SeqUI.initTopbar();
  if (btnGenerate) btnGenerate.disabled = true;
  showProgress(false);

  await Promise.all([loadTopics(), loadHistory()]);
  await checkPendingGeneration();

  console.log('[Aegis] Initialized');
});
