/* ============================================================
   sentinel.js — Lógica específica del módulo Sentinel
   Depende de: shared.js  (SeqSession, SeqUI, SeqToast, apiFetch)
   ============================================================ */
'use strict';

/* ── Guardia + UI inicial ── */
document.addEventListener('DOMContentLoaded', () => {
  if (!SeqUI.requireSession()) return;
  SeqUI.initTopbar();
  loadStats();
  loadScans('nmap');
});

/* ══════════════════════════════════════════════════════════════
   TABS
══════════════════════════════════════════════════════════════ */
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelector(`.tab.${name}`)?.classList.add('active');
  document.getElementById(`panel-${name}`)?.classList.add('active');
  loadScans(name);
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
  const res = await apiFetch('/sentinel/results');
  if (!res?.ok) return;
  const { results = [] } = await res.json();
  document.getElementById('stat-total').textContent   = results.length;
  document.getElementById('stat-nmap').textContent    = results.filter(r => r.scanType === 'nmap').length;
  document.getElementById('stat-nikto').textContent   = results.filter(r => r.scanType === 'nikto').length;
  document.getElementById('stat-openvas').textContent = results.filter(r => r.scanType === 'openvas').length;
}

/* ══════════════════════════════════════════════════════════════
   TABLA DE RESULTADOS
══════════════════════════════════════════════════════════════ */
async function loadScans(type) {
  const wrap = document.getElementById(`table-${type}`);
  if (!wrap) return;

  wrap.innerHTML = `
    <div class="empty-state">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
      </svg>
      <span>Cargando…</span>
    </div>`;

  const res = await apiFetch(`/sentinel/results?type=${type}`);
  if (!res?.ok) { wrap.innerHTML = '<div class="empty-state">Error al cargar los datos.</div>'; return; }

  const { results = [] } = await res.json();
  renderTable(type, results, wrap);
  loadStats();
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

  let html = '<table><thead><tr>';

  if (type === 'nmap') {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Puertos abiertos</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of rows) {
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalOpenPorts ?? 0} <span class="muted">puertos</span></td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status)}</td>
      </tr>`;
    }
  } else if (type === 'nikto') {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Incidencias</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of rows) {
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalIncidents ?? 0} <span class="muted">hallazgos</span></td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status)}</td>
      </tr>`;
    }
  } else {
    html += '<th>ID</th><th>Target</th><th>Estado</th><th>Vulns</th><th>Críticas</th><th>Altas</th><th>Fecha</th><th>Acciones</th></tr></thead><tbody>';
    for (const r of rows) {
      const crit = r.criticalCount ?? 0;
      const high = r.highCount ?? 0;
      html += `<tr>
        <td>#${r.id}</td><td>${r.target}</td>
        <td>${SeqUI.statusBadge(r.status)}</td>
        <td>${r.totalVulnerabilities ?? 0}</td>
        <td class="sev-critical">${crit > 0 ? crit : '<span class="muted">0</span>'}</td>
        <td class="sev-high">${high > 0 ? high : '<span class="muted">0</span>'}</td>
        <td>${SeqUI.formatDate(r.startedAt)}</td>
        <td>${actionBtns(r.id, r.status)}</td>
      </tr>`;
    }
  }

  html += '</tbody></table>';
  wrap.innerHTML = html;
}

function actionBtns(id, status) {
  const st         = (status ?? '').toLowerCase();
  const isActive   = st === 'running' || st === 'pending';
  const isFinished = st === 'done'    || st === 'finished';

  const pdfBtn = `
    <button class="action-btn"
      title="${isFinished ? 'Descargar PDF' : 'PDF disponible al finalizar'}"
      onclick="${isFinished ? `downloadPDF(${id})` : ''}"
      style="${!isFinished ? 'opacity:0.35;cursor:not-allowed' : ''}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="12" y1="18" x2="12" y2="12"/>
        <line x1="9" y1="15" x2="15" y2="15"/>
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

  return pdfBtn + cancelBtn + deleteBtn;
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
    setTimeout(() => loadScans('nmap'), 1200);
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
    setTimeout(() => loadScans('nikto'), 1200);
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
    setTimeout(() => loadScans('openvas'), 1200);
  } catch { showPanelAlert('openvas', 'No se pudo conectar con la API.'); }
  finally   { setLaunching('btn-openvas', false); }
}

/* ══════════════════════════════════════════════════════════════
   ACCIONES DE FILA
══════════════════════════════════════════════════════════════ */
async function downloadPDF(id) {
  const res = await apiFetch(`/sentinel/generate-pdf?id=${id}`);
  if (!res?.ok) { SeqToast.show('No se pudo generar el PDF.', 'error'); return; }
  const blob = await res.blob();
  const cd   = res.headers.get('Content-Disposition') || '';
  const name = cd.match(/filename="?([^";\n]+)"?/i)?.[1] ?? `scan_${id}.pdf`;
  _triggerDownload(blob, name);
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
   UTIL LOCAL
══════════════════════════════════════════════════════════════ */
function _triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}
