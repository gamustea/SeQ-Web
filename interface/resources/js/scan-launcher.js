/**
 * SCAN LAUNCHER
 * Maneja los formularios de escaneo Nmap y Nikto
 */

const API_BASE_URL = 'http://127.0.0.1:5000';

// ===== UTILIDADES =====

function showStatus(elementId, message, type = 'info') {
    const statusElement = document.getElementById(elementId);
    statusElement.textContent = message;
    statusElement.className = `form-status ${type}`;
    statusElement.style.display = 'block';
    
    setTimeout(() => {
        statusElement.style.display = 'none';
    }, 8000);
}

function setButtonLoading(button, isLoading) {
    if (isLoading) {
        button.dataset.originalText = button.innerHTML;
        button.innerHTML = '<span class="spinner"></span> Iniciando...';
        button.disabled = true;
    } else {
        button.innerHTML = button.dataset.originalText;
        button.disabled = false;
    }
}

// ===== MANEJADOR NMAP =====

document.getElementById('nmapScanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const submitButton = e.target.querySelector('button[type="submit"]');
    setButtonLoading(submitButton, true);
    
    const host = document.getElementById('nmapHost').value.trim();
    const ports = document.getElementById('nmapPorts').value.trim();
    
    try {
        const response = await fetch(`${API_BASE_URL}/scans/nmap/start`, {
            method: 'POST',
            headers: {
                'X-Target-Host': host,
                'X-Target-Ports': ports
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus(
                'nmapStatus', 
                `✅ Escaneo iniciado correctamente (ID: ${data.scanId})`, 
                'success'
            );
            e.target.reset();
        } else {
            showStatus(
                'nmapStatus', 
                `❌ Error: ${data.error || 'Error desconocido'}`, 
                'error'
            );
        }
        
    } catch (error) {
        console.error('Error al conectar con la API:', error);
        showStatus(
            'nmapStatus', 
            '❌ No se pudo conectar con el servidor. Verifica que Flask esté corriendo.', 
            'error'
        );
    } finally {
        setButtonLoading(submitButton, false);
    }
});

// ===== MANEJADOR NIKTO =====

document.getElementById('niktoScanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const submitButton = e.target.querySelector('button[type="submit"]');
    setButtonLoading(submitButton, true);
    
    const target = document.getElementById('niktoTarget').value.trim();
    const timeout = document.getElementById('niktoTimeout').value;
    
    try {
        const response = await fetch(`${API_BASE_URL}/scans/nikto/start?timeout=${timeout}`, {
            method: 'POST',
            headers: {
                'X-Target': target
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus(
                'niktoStatus', 
                `✅ Escaneo iniciado correctamente (ID: ${data.scanId})`, 
                'success'
            );
            e.target.reset();
            document.getElementById('niktoTimeout').value = '180';
        } else {
            showStatus(
                'niktoStatus', 
                `❌ Error: ${data.error || 'Error desconocido'}`, 
                'error'
            );
        }
        
    } catch (error) {
        console.error('Error al conectar con la API:', error);
        showStatus(
            'niktoStatus', 
            '❌ No se pudo conectar con el servidor. Verifica que Flask esté corriendo.', 
            'error'
        );
    } finally {
        setButtonLoading(submitButton, false);
    }
});

// ===== GESTIÓN DE HISTORIAL (SIN POLLING AUTOMÁTICO) =====

/**
 * Verifica el estado de un escaneo específico
 */
async function checkScanStatus(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/is-finished?id=${scanId}`);
        const data = await response.json();
        
        const statusCell = document.getElementById(`status-${scanId}`);
        const downloadBtn = document.getElementById(`download-${scanId}`);
        
        if (statusCell && downloadBtn) {
            if (data.existe) {
                statusCell.innerHTML = '<span class="status-finished">✓ Terminado</span>';
                downloadBtn.disabled = false;
                downloadBtn.classList.add('enabled');
            } else {
                statusCell.innerHTML = '<span class="status-running">⟳ En proceso</span>';
                downloadBtn.disabled = true;
            }
        }
        
    } catch (error) {
        console.error(`Error verificando estado del escaneo ${scanId}:`, error);
    }
}

/**
 * Carga y actualiza toda la tabla de escaneos
 */
async function loadScanHistory() {
    const tbody = document.getElementById('scanHistoryBody');
    const refreshBtn = document.getElementById('refreshHistoryBtn');
    
    // Mostrar loading en el botón
    const originalBtnText = refreshBtn.innerHTML;
    refreshBtn.innerHTML = '⟳ Actualizando...';
    refreshBtn.disabled = true;
    
    // Mostrar loading en la tabla
    tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Cargando escaneos...</td></tr>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/scans/results?type=all`);
        
        if (!response.ok) {
            throw new Error('Error al obtener los escaneos');
        }
        
        const data = await response.json();
        const scans = data.results || [];
        
        // Ordenar por ID descendente (más recientes primero)
        scans.sort((a, b) => b.id - a.id);
        
        // Limpiar tabla
        tbody.innerHTML = '';
        
        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No hay escaneos registrados todavía.</td></tr>';
            return;
        }
        
        // Crear filas para cada escaneo
        for (const scan of scans) {
            const row = createScanRow(scan);
            tbody.appendChild(row);
            
            // Verificar estado de cada escaneo
            await checkScanStatus(scan.id);
        }
        
    } catch (error) {
        console.error('Error cargando historial:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="error-cell">
                    ❌ Error al cargar los escaneos. Verifica que Flask esté corriendo en el puerto 5000.
                </td>
            </tr>
        `;
    } finally {
        // Restaurar botón
        refreshBtn.innerHTML = originalBtnText;
        refreshBtn.disabled = false;
    }
}

/**
 * Crea una fila de la tabla para un escaneo
 */
function createScanRow(scan) {
    const row = document.createElement('tr');
    row.dataset.scanId = scan.id;
    
    const date = new Date(scan.startedAt);
    const dateStr = date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
    
    const typeClass = scan.scanType === 'nmap' ? 'badge-nmap' : 'badge-nikto';
    const typeBadge = `<span class="scan-badge ${typeClass}">${scan.scanType.toUpperCase()}</span>`;
    
    row.innerHTML = `
        <td><span class="scan-id">#${scan.id}</span></td>
        <td>${typeBadge}</td>
        <td class="target-cell">${scan.target}</td>
        <td>${dateStr}</td>
        <td class="status-cell" id="status-${scan.id}">
            <span class="status-checking">⏳ Verificando...</span>
        </td>
        <td>
            <button 
                class="btn-download" 
                id="download-${scan.id}" 
                onclick="downloadPDF(${scan.id})"
                disabled>
                📄 PDF
            </button>
        </td>
    `;
    
    return row;
}

/**
 * Descarga el PDF de un escaneo
 */
window.downloadPDF = async function(scanId) {
    const button = document.getElementById(`download-${scanId}`);
    const originalText = button.innerHTML;
    
    try {
        button.innerHTML = '⏳ Generando...';
        button.disabled = true;
        
        window.location.href = `${API_BASE_URL}/scans/generate-pdf?id=${scanId}`;
        
        setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
        }, 2000);
        
    } catch (error) {
        console.error('Error descargando PDF:', error);
        alert('Error al descargar el PDF');
        button.innerHTML = originalText;
        button.disabled = false;
    }
};

// ===== EVENTOS =====

// Cargar tabla inicial cuando carga la página
document.addEventListener('DOMContentLoaded', () => {
    loadScanHistory();
});

// Botón de actualizar manual
document.getElementById('refreshHistoryBtn').addEventListener('click', () => {
    loadScanHistory();
});
