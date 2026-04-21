/* ============================================================
   sentinel.js — Lógica específica del módulo Sentinel
   Depende de: shared.js  (SeqSession, SeqUI, SeqToast, apiFetch)
   ============================================================ */
'use strict';

const PAGE_SIZE = 10;
const POLL_INTERVAL_MS = 10_000;
const POLL_MAX_ATTEMPTS = 180;

const paginationState = {
  nmap:   { page: 1, total: 0 },
  nikto:  { page: 1, total: 0 },
  openvas:{ page: 1, total: 0 }
};

let pollTimer = null;
let pollAttempts = 0;

/* ── Guardia + UI inicial ── */
document.addEventListener('DOMContentLoaded', () => {
  if (!SeqUI.requireSession()) return;
  SeqUI.initTopbar();
  loadStats();
  loadScans('nmap');
  updateDownloadButtons();
});

/* ══════════════════════════════════════════════════════════════════════
    POLLING — Auto-refresh para escaneos en curso (ELIMINADO)
    ══════════════════════════════════════════════════════════════ */
function startPolling() {
  // Polling eliminado - ahora se actualiza manualmente con el botón
}

function stopPolling() {
  // Pollingeliminado
}

async function refreshCurrentTab() {
  const activeTab = document.querySelector('.tab.active')?.dataset?.panel;
  if (activeTab) {
    const page = paginationState[activeTab]?.page || 1;
    await loadScans(activeTab, page, true);
  }
  await loadStats();
  await updateDownloadButtons();
}

function refreshWithFeedback(btn) {
  const originalContent = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:12px;height:12px;animation:seq-spin 0.6s linear infinite">
    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
  </svg> Actualizando...`;

  refreshCurrentTab().then(() => {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = originalContent;
    }, 500);
  }).catch(() => {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = originalContent;
    }, 500);
  });
}

/* ══════════════════════════════════════════════════════════════
    TABS
    ══════════════════════════════════════════════════════════════ */
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab.${name}`)?.classList.add('active');
  document.getElementById(`panel-${name}`)?.classList.add('active');
  paginationState[name].page = 1;
  loadScans(name, 1);
}

/* ══════════════════════════════════════════════════════════════
   PANEL ALERTS (inline, no toast)
══════════════════════════════════════════════════════════════ */
function showPanelAlert(type, msg, kind = 'error') {
  const el = document.getElementById(`alert-${type}`);
  if (!el) return;
  el.className = `panel-alert visible ${kind}`;
  el.textContent = msg;
  if (kind === 'success') setTimeout(() => el.classList.remove('visible'), 4000);
}

/* ══════════════════════════════════════════════════════════════
    STATS
══════════════════════════════════════════════════════════════ */
async function loadStats() {
  try {
    const [nmapRes, niktoRes, openvasRes] = await Promise.all([
      apiFetch('/sentinel/results?type=nmap&per_page=1'),
      apiFetch('/sentinel/results?type=nikto&per_page=1'),
      apiFetch('/sentinel/results?type=openvas&per_page=1')
    ]);

    const nmapData = nmapRes?.ok ? await nmapRes.json() : { total: 0 };
    const niktoData = niktoRes?.ok ? await niktoRes.json() : { total: 0 };
    const openvasData = openvasRes?.ok ? await openvasRes.json() : { total: 0 };

    const total = (nmapData.total || 0) + (niktoData.total || 0) + (openvasData.total || 0);

    document.getElementById('stat-total').textContent   = total;
    document.getElementById('stat-nmap').textContent    = nmapData.total || 0;
    document.getElementById('stat-nikto').textContent   = niktoData.total || 0;
    document.getElementById('stat-openvas').textContent = openvasData.total || 0;
  } catch (e) {
    console.error('[Sentinel] Error loading stats:', e);
  }
}

/* ══════════════════════════════════════════════════════════════
     TABLA DE RESULTADOS + PAGINACIÓN
═════════════════════════════════════════════════════════════════════ */
async function loadScans(type, page = 1, showLoading = true) {
  const wrap = document.getElementById(`table-${type}`);
  const pagWrap = document.getElementById(`pagination-${type}`);
  if (!wrap) return;

  if (showLoading) {
    wrap.innerHTML = `
      <div class="empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
        </svg>
        <span>Cargando…</span>
      </div>`;
  }

  const perPage = PAGE_SIZE;
  const res = await apiFetch(`/sentinel/results?type=${type}&page=${page}&per_page=${perPage}`);
  if (!res?.ok) { wrap.innerHTML = '<div class="empty-state">Error al cargar los datos.</div>'; return; }

  const data = await res.json();
  const results = data.results || [];
  paginationState[type].total = data.total || results.length;
  paginationState[type].page = data.page || page;

  renderTable(type, results, wrap);
  renderPagination(type, pagWrap, paginationState[type].total, page);
  if (!showLoading) checkAllScansDocumentStatus();
}

function renderTable(type, rows, wrap) {
  if (!rows.length) {
    wrap.innerHTML = `
      <div class="empty-state">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2">
          <rect x="2" y="3" width="20" height="14" rx="2"/>
          <line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
        <span>No hay escaneos todavía. ¡Lanza el primero!</span>
      </div>`;
    return;
  }

  const page = paginationState[type].page;
  const start = (page - 1) * PAGE_SIZE;
  const paged = rows.slice(start, start + PAGE_SIZE);

  let html = '<table><thead><tr>';

  if (type === 'nmap') {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Puertos abiertos</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of paged) {
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalOpenPorts ?? 0} <span class="muted">puertos</span></td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status, 'nmap', r)}</td>
      </tr>`;
    }
  } else if (type === 'nikto') {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Incidencias</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of paged) {
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalIncidents ?? 0} <span class="muted">hallazgos</span></td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status, 'nikto', r)}</td>
      </tr>`;
    }
  } else {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Vulns</th><th>Críticas</th><th>Altas</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of paged) {
      const crit = r.criticalCount ?? 0;
      const high = r.highCount ?? 0;
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalVulnerabilities ?? 0}</td>
        <td class="sev-critical">${crit > 0 ? crit : '<span class="muted">0</span>'}</td>
        <td class="sev-high">${high > 0 ? high : '<span class="muted">0</span>'}</td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status, 'openvas', r)}</td>
      </tr>`;
    }
  }

  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function actionBtns(id, status, scanType = 'nmap', scan = null) {
  const st         = (status ?? '').toLowerCase();
  const isActive   = st === 'running' || st === 'pending';
  const isFinished = st === 'done'    || st === 'finished';

  const docId = scan?.documentId || null;
  const docStatus = scan?.documentStatus || null;
  const canDownload = docId && docStatus === 'done';

  const viewBtn = `
    <button class="action-btn" title="Ver detalles" onclick="viewScanDetails(${id}, '${scanType}')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    </button>`;

  const generateBtn = `
    <button class="action-btn" title="Generar PDF" onclick="generatePDF(${id}, '${scanType}')" ${isActive ? 'disabled style="opacity:0.35;cursor:not-allowed"' : ''}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="12" y1="18" x2="12" y2="12"/>
        <line x1="9" y1="15" x2="15" y2="15"/>
      </svg>
    </button>`;

  const downloadBtn = `
    <button class="action-btn" title="Descargar PDF" id="download-btn-${id}" data-doc-id="${docId || ''}" onclick="downloadDocument()" ${!canDownload ? 'disabled style="opacity:0.35;cursor:not-allowed"' : ''}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
    </button>`;

  const cancelBtn = isActive ? `
    <button class="action-btn" title="Cancelar escaneo" onclick="cancelScan(${id})" style="color:var(--warn)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
      </svg>
    </button>` : '';

  const deleteBtn = `
    <button class="action-btn" title="Eliminar" onclick="deleteScan(${id})" style="color:var(--danger)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polyline points="3 6 5 6 21 6"/>
        <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
        <path d="M10 11v6M14 11v6M9 6V4h6v2"/>
      </svg>
    </button>`;

  return viewBtn + generateBtn + downloadBtn + cancelBtn + deleteBtn;
}

/* ══════════════════════════════════════════════════════════════
   LANZADORES
══════════════════════════════════════════════════════════════ */
function setLaunching(btnId, on) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = on;
  btn.classList.toggle('loading', on);
}

async function launchNmap() {
  const target  = document.getElementById('nmap-target').value.trim();
  const ports   = document.getElementById('nmap-ports').value.trim();
  const timeout = parseInt(document.getElementById('nmap-timeout').value, 10);
  if (!target || !ports) { showPanelAlert('nmap', 'Rellena el target y los puertos.'); return; }
  if (!timeout || timeout <= 0) { showPanelAlert('nmap', 'El timeout debe ser un número positivo.'); return; }

  setLaunching('btn-nmap', true);
  try {
    const res  = await apiFetch('/sentinel/nmap', { method: 'POST', body: JSON.stringify({ target, ports, timeout }) });
    const data = await res.json();
    if (!res.ok) { showPanelAlert('nmap', data.error_description || data.message || 'Error al lanzar el escaneo.'); return; }
    showPanelAlert('nmap', `Escaneo Nmap iniciado (ID: ${(data.scanIds || []).join(', ')}) — timeout: ${timeout}s`, 'success');
    try { await refreshCurrentTab(); } catch (e) { console.error('Error refresh:', e); }
  } catch { showPanelAlert('nmap', 'No se pudo conectar con la API.'); }
  finally   { setLaunching('btn-nmap', false); }
}

async function launchNikto() {
  const target  = document.getElementById('nikto-target').value.trim();
  const timeout = parseInt(document.getElementById('nikto-timeout').value, 10);
  if (!target) { showPanelAlert('nikto', 'Introduce una URL de destino.'); return; }

  setLaunching('btn-nikto', true);
  try {
    const res  = await apiFetch('/sentinel/nikto', { method: 'POST', body: JSON.stringify({ target, timeout }) });
    const data = await res.json();
    if (!res.ok) { showPanelAlert('nikto', data.error_description || data.message || 'Error al lanzar el escaneo.'); return; }
    showPanelAlert('nikto', `Escaneo Nikto iniciado (ID: ${data.scanId})`, 'success');
    try { await refreshCurrentTab(); } catch (e) { console.error('Error refresh:', e); }
  } catch { showPanelAlert('nikto', 'No se pudo conectar con la API.'); }
  finally   { setLaunching('btn-nikto', false); }
}

async function launchOpenvas() {
  const target = document.getElementById('openvas-target').value.trim();
  const config = document.getElementById('openvas-config').value;
  if (!target) { showPanelAlert('openvas', 'Introduce una IP de destino.'); return; }

  setLaunching('btn-openvas', true);
  try {
    const res  = await apiFetch('/sentinel/openvas', { method: 'POST', body: JSON.stringify({ target, scanConfig: config }) });
    const data = await res.json();
    if (!res.ok) { showPanelAlert('openvas', data.error_description || data.message || 'Error al lanzar el escaneo.'); return; }
    showPanelAlert('openvas', `Escaneo OpenVAS iniciado (ID: ${data.scanId}). Puede tardar varios minutos.`, 'info');
    try { await refreshCurrentTab(); } catch (e) { console.error('Error refresh:', e); }
  } catch { showPanelAlert('openvas', 'No se pudo conectar con la API.'); }
  finally   { setLaunching('btn-openvas', false); }
}

/* ══════════════════════════════════════════════════════════════
    ACCIONES DE FILA
    ══════════════════════════════════════════════════════════════ */
// Legacy - kept for backwards compatibility
async function downloadPDF(id) {
  // Now redirects to the new async flow
  const res = await apiFetch(`/sentinel/results/${id}`);
  if (!res?.ok) { SeqToast.show('Error al cargar el escaneo.', 'error'); return; }
  const data = await res.json();
  const scanData = data.result || data;
  const type = scanData.scanType || 'nmap';
  viewScanDetails(id, type);
}

async function deleteScan(id) {
  if (!confirm(`¿Eliminar el escaneo #${id}? Esta acción no se puede deshacer.`)) return;
  const res = await apiFetch(`/sentinel/${id}`, { method: 'DELETE' });
  if (res?.ok) {
    loadStats();
    const active = document.querySelector('.tab.active')?.dataset?.panel;
    if (active) loadScans(active);
  } else {
    SeqToast.show('No se pudo eliminar el escaneo.', 'error');
  }
}

async function cancelScan(id) {
  if (!confirm(`¿Cancelar el escaneo #${id}?`)) return;
  const res = await apiFetch(`/sentinel/scans/${id}/cancel`, { method: 'POST' });
  if (res?.ok) {
    const active = document.querySelector('.tab.active')?.dataset?.panel;
    if (active) loadScans(active);
  } else {
    const data = await res?.json().catch(() => ({}));
    SeqToast.show(data.message || 'No se pudo cancelar el escaneo.', 'error');
  }
}

/* ══════════════════════════════════════════════════════════════
    DETALLES DEL ESCANEO + GENERACIÓN DE PDF
    ══════════════════════════════════════════════════════════════ */
let currentScanId = null;
let documentPollTimer = null;

async function viewScanDetails(scanId, scanType) {
  currentScanId = scanId;
  const modal = document.getElementById('scan-details-modal');
  const body = document.getElementById('scan-details-body');
  
  body.innerHTML = `
    <div class="empty-state">
      <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:24px;height:24px">
        <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
      </svg>
      <span>Cargando detalles...</span>
    </div>`;
  
  modal.classList.add('visible');
  
  try {
    const res = await apiFetch(`/sentinel/results/${scanId}`);
    if (!res?.ok) { body.innerHTML = '<div class="empty-state">Error al cargar los detalles.</div>'; return; }

    const data = await res.json();
    const scanData = data.result || data;
    if (scanData.documentId) {
      currentDocumentId = scanData.documentId;
    }
    renderScanDetails(scanData, scanType);
    if (currentDocumentId) {
      checkDocumentStatus(scanId, currentDocumentId);
    }
  } catch (e) {
    body.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

function renderScanDetails(scan, type) {
  const body = document.getElementById('scan-details-body');
  const started = scan.startedAt ? new Date(scan.startedAt).toLocaleString() : 'N/A';
  const finished = scan.finishedAt ? new Date(scan.finishedAt).toLocaleString() : 'En curso';
  
  let detailsHtml = `
    <div class="detail-section">
      <h3>Información General</h3>
      <div class="detail-grid">
        <span class="detail-label">ID:</span>
        <span class="detail-value">#${scan.id}</span>
        <span class="detail-label">Target:</span>
        <span class="detail-value">${scan.target}</span>
        <span class="detail-label">Estado:</span>
        <span class="detail-value">${SeqUI.statusBadge(scan.status)}</span>
        <span class="detail-label">Iniciado:</span>
        <span class="detail-value">${started}</span>
        <span class="detail-label">Finalizado:</span>
        <span class="detail-value">${finished}</span>
      </div>
    </div>`;
  
  if (type === 'nmap' && scan.openPorts?.length) {
    detailsHtml += `
      <div class="detail-section">
        <h3>Puertos Abiertos (${scan.openPorts.length})</h3>
        <table class="ports-table">
          <thead><tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Versión</th></tr></thead>
          <tbody>
            ${scan.openPorts.map(p => `
              <tr>
                <td>${p.port || '-'}</td>
                <td>${p.port?.split('/')[1] || '-'}</td>
                <td>${p.product || '-'}</td>
                <td>${p.product || '-'}${p.version ? ' ' + p.version : ''}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>`;
  } else if (type === 'nikto' && scan.incidents?.length) {
    detailsHtml += `
      <div class="detail-section">
        <h3>Incidencias (${scan.incidents.length})</h3>
        ${scan.incidents.map(inc => `
          <div class="incident-card">
            <div class="incident-header">
              <span class="incident-title">${inc.method || 'GET'} ${inc.url || ''}</span>
              <span class="severity-badge ${(inc.severity || 'medium').toLowerCase()}">${inc.severity || 'MEDIUM'}</span>
            </div>
            <div class="incident-desc">${inc.description || ''}</div>
          </div>
        `).join('')}
      </div>`;
  } else if (type === 'openvas' && scan.vulnerabilities?.length) {
    detailsHtml += `
      <div class="detail-section">
        <h3>Vulnerabilidades (${scan.vulnerabilities.length})</h3>
        ${scan.vulnerabilities.slice(0, 10).map(v => `
          <div class="incident-card">
            <div class="incident-header">
              <span class="incident-title">${v.name}</span>
              <span class="severity-badge ${getSeverityClass(v.severityClass)}">${v.severityClass || 'Unknown'}</span>
            </div>
            <div class="incident-desc">${v.description || ''}</div>
          </div>
        `).join('')}
        ${scan.vulnerabilities.length > 10 ? `<p style="color:var(--text-muted)">...y ${scan.vulnerabilities.length - 10} más</p>` : ''}
      </div>`;
  }
  
  detailsHtml += `
    <div class="detail-section document-generator-card">
      <div class="doc-gen-header">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/>
          <line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/>
          <polyline points="10 9 9 9 8 9"/>
        </svg>
        <h3>Generar Informe PDF</h3>
        <button class="doc-refresh-btn" onclick="refreshDocStatusInModal(${scan.id})" title="Actualizar estado">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
          </svg>
        </button>
      </div>
      <div class="doc-gen-content">
        <div class="doc-gen-options">
          <label class="doc-checkbox">
            <input type="checkbox" id="ai-report-check" />
            <span class="doc-checkmark"></span>
            <span class="doc-checklabel">Análisis IA con Ollama</span>
          </label>
        </div>
        <button class="doc-gen-btn" onclick="generatePDF(${scan.id}, '${type}')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
            <polyline points="14 2 14 8 20 8"/>
            <line x1="12" y1="18" x2="12" y2="12"/>
            <line x1="9" y1="15" x2="15" y2="15"/>
          </svg>
          Generar PDF
        </button>
      </div>
      <div class="doc-status-track" id="document-status-container">
        <div class="doc-status-empty">Genera un documento para descargar el informe</div>
      </div>
    </div>`;

  body.innerHTML = detailsHtml;
}

function getSeverityClass(severity) {
  if (!severity) return 'low';
  const s = severity.toLowerCase();
  if (s.includes('crit')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('med')) return 'medium';
  return 'low';
}

function closeScanDetailsModal() {
  document.getElementById('scan-details-modal').classList.remove('visible');
  stopDocumentPolling();
  currentScanId = null;
  currentDocumentId = null;
}

async function generatePDF(scanId, scanType) {
  const aiReport = document.getElementById('ai-report-check')?.checked || false;
  const statusContainer = document.getElementById('document-status-container');

  statusContainer.innerHTML = `
    <div class="doc-progress">
      <div class="doc-progress-bar">
        <div class="doc-progress-fill spin"></div>
      </div>
      <div class="doc-progress-text">
        <span class="doc-spinner"></span>
        Solicitando generación...
      </div>
    </div>`;

  try {
    const url = `/sentinel/generate-pdf?id=${scanId}${aiReport ? '&aiReport=true' : ''}`;
    const res = await apiFetch(url);
    const data = await res.json();

    if (!res.ok) {
      statusContainer.innerHTML = `
        <div class="doc-result error">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
          <span>${data.message || 'Error al generar'}</span>
          <button class="doc-retry-btn" onclick="generatePDF(${scanId}, '${scanType}')">Reintentar</button>
        </div>`;
      return;
    }

    const docId = data.documentId;
    startDocumentPolling(scanId, docId);

  } catch (e) {
    statusContainer.innerHTML = `
      <div class="doc-result error">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <span>Error: ${e.message}</span>
      </div>`;
  }
}

function startDocumentPolling(scanId, docId) {
  stopDocumentPolling();
  documentPollTimer = setInterval(() => checkDocumentStatus(scanId, docId), 3000);
}

async function refreshDocStatusInModal(scanId) {
  const statusContainer = document.getElementById('document-status-container');
  if (!statusContainer) return;

  statusContainer.innerHTML = `
    <div class="doc-progress">
      <div class="doc-progress-bar">
        <div class="doc-progress-fill spin"></div>
      </div>
      <div class="doc-progress-text">
        <span class="doc-spinner"></span>
        Verificando...
      </div>
    </div>`;

  await checkDocumentStatus(scanId);
}

function stopDocumentPolling() {
  if (documentPollTimer) { clearInterval(documentPollTimer); documentPollTimer = null; }
}

async function checkDocumentStatus(scanId, docId = null) {
  const statusContainer = document.getElementById('document-status-container');
  if (!statusContainer) return;

  try {
    const url = docId
      ? `/sentinel/document-status?document_id=${docId}`
      : `/sentinel/document-status?scan_id=${scanId}`;
    const res = await apiFetch(url);

    if (!res?.ok) return;
    const data = await res.json();

    const statusConfig = {
      pending: {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
        text: 'Pendiente...',
        cls: 'pending'
      },
      running: {
        icon: `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`,
        text: 'Generando documento...',
        cls: 'processing'
      },
      done: {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
        text: 'Documento listo',
        cls: 'success'
      },
      error: {
        icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
        text: 'Error en generación',
        cls: 'error'
      }
    };

    const status = statusConfig[data.status] || statusConfig.pending;

    if (data.status === 'done' && data.downloadUrl) {
      stopDocumentPolling();
      currentDocumentId = docId || data.documentId;
      const downloadBtn = document.getElementById(`download-btn-${scanId}`);
      if (downloadBtn) {
        downloadBtn.disabled = false;
        downloadBtn.style.opacity = '1';
        downloadBtn.style.cursor = 'pointer';
      }

      statusContainer.innerHTML = `
        <div class="doc-result success">
          <div class="doc-result-icon">${status.icon}</div>
          <div class="doc-result-text">
            <span class="doc-result-title">${status.text}</span>
            <button class="doc-download-btn" onclick="downloadDocument(${currentDocumentId})">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Descargar PDF
            </button>
          </div>
        </div>`;
      return;
    }

    if (data.status === 'error') {
      stopDocumentPolling();
      statusContainer.innerHTML = `
        <div class="doc-result error">
          <div class="doc-result-icon">${status.icon}</div>
          <div class="doc-result-text">
            <span class="doc-result-title">${status.text}</span>
            <button class="doc-retry-btn" onclick="generatePDF(${scanId}, '${docId ? '' : ''}')">Reintentar</button>
          </div>
        </div>`;
      return;
    }

    statusContainer.innerHTML = `
      <div class="doc-progress">
        <div class="doc-progress-bar">
          <div class="doc-progress-fill ${data.status === 'running' ? 'spin' : ''}"></div>
        </div>
        <div class="doc-progress-text">
          ${status.icon}
          ${status.text}
        </div>
      </div>`;

  } catch (e) {
    console.error('Error checking document status:', e);
  }
}

let currentDocumentId = null;

async function downloadDocument(docId = null) {
  const documentId = docId || currentDocumentId;
  if (!documentId) {
    const actionBtn = document.querySelector('.action-btn[id^="download-btn-"]');
    const btnDocId = actionBtn?.dataset?.docId;
    if (btnDocId) {
      currentDocumentId = btnDocId;
    }
  }

  const finalDocId = documentId || currentDocumentId;
  if (!finalDocId) {
    SeqToast.show('Documento no disponible.', 'error');
    return;
  }

  try {
    const res = await apiFetch(`/sentinel/document/${finalDocId}/download`);
    if (!res?.ok) { SeqToast.show('No se pudo descargar el documento.', 'error'); return; }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') || '';
    const name = cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? `scan_${finalDocId}.pdf`;
    _triggerDownload(blob, name);
    SeqToast.show('Documento descargado correctamente', 'success');
  } catch (e) {
    SeqToast.show('Error al descargar: ' + e.message, 'error');
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
    PAGINATION
    ══════════════════════════════════════════════════════════════ */
function renderPagination(type, container, total, currentPage) {
  const totalPages = Math.ceil(total / PAGE_SIZE);
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  const state = paginationState[type];
  let html = '';

  html += `<button class="pagination-btn" onclick="goToPage('${type}', ${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>‹</button>`;

  const maxVisible = 5;
  let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
  let end = Math.min(totalPages, start + maxVisible - 1);
  if (end - start < maxVisible - 1) start = Math.max(1, end - maxVisible + 1);

  for (let i = start; i <= end; i++) {
    html += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" onclick="goToPage('${type}', ${i})">${i}</button>`;
  }

  html += `<button class="pagination-btn" onclick="goToPage('${type}', ${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>›</button>`;
  html += `<span class="pagination-info">${currentPage}/${totalPages}</span>`;

  container.innerHTML = html;
}

function goToPage(type, page) {
  if (page < 1) return;
  const total = paginationState[type].total;
  const maxPage = Math.ceil(total / PAGE_SIZE);
  if (page > maxPage) return;
  paginationState[type].page = page;
  loadScans(type, page);
}
