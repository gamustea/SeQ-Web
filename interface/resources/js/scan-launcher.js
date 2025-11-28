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
                `✅ Escaneo iniciado correctamente`, 
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

/**
 * SISTEMA DE PAGINACIÓN PARA HISTORIAL DE ESCANEOS
 * Añadir al final de scan-launcher.js
 */

// ===== CONFIGURACIÓN DE PAGINACIÓN =====

const PAGINATION_CONFIG = {
    itemsPerPage: 10,
    currentPage: 1,
    totalItems: 0,
    totalPages: 0,
    allScans: [] // Almacena todos los escaneos cargados
};

/**
 * Actualiza la configuración de paginación
 */
function updatePaginationConfig(scans) {
    PAGINATION_CONFIG.allScans = scans;
    PAGINATION_CONFIG.totalItems = scans.length;
    PAGINATION_CONFIG.totalPages = Math.ceil(scans.length / PAGINATION_CONFIG.itemsPerPage);
    
    // Si la página actual excede el total, resetear a 1
    if (PAGINATION_CONFIG.currentPage > PAGINATION_CONFIG.totalPages) {
        PAGINATION_CONFIG.currentPage = 1;
    }
}

/**
 * Obtiene los escaneos de la página actual
 */
function getCurrentPageScans() {
    const startIndex = (PAGINATION_CONFIG.currentPage - 1) * PAGINATION_CONFIG.itemsPerPage;
    const endIndex = startIndex + PAGINATION_CONFIG.itemsPerPage;
    return PAGINATION_CONFIG.allScans.slice(startIndex, endIndex);
}

/**
 * Cambia a una página específica
 */
function goToPage(pageNumber) {
    if (pageNumber < 1 || pageNumber > PAGINATION_CONFIG.totalPages) {
        return;
    }
    
    PAGINATION_CONFIG.currentPage = pageNumber;
    renderCurrentPage();
    updatePaginationControls();
    
    // Scroll suave a la tabla
    document.querySelector('.scan-history-section').scrollIntoView({ 
        behavior: 'smooth',
        block: 'start'
    });
}

/**
 * Renderiza los escaneos de la página actual
 */
async function renderCurrentPage() {
    const tbody = document.getElementById('scanHistoryBody');
    const pageScans = getCurrentPageScans();
    
    if (pageScans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No hay escaneos en esta página.</td></tr>';
        return;
    }
    
    // Limpiar tabla
    tbody.innerHTML = '';
    
    // Crear filas para cada escaneo de la página
    for (const scan of pageScans) {
        const row = createScanRow(scan);
        tbody.appendChild(row);
        
        // Verificar estado asíncronamente
        await checkScanStatus(scan.id);
    }
}

/**
 * Crea los controles de paginación
 */
function createPaginationControls() {
    const { currentPage, totalPages, totalItems, itemsPerPage } = PAGINATION_CONFIG;
    
    if (totalPages <= 1) {
        return ''; // No mostrar paginación si solo hay una página
    }
    
    // Calcular rango de items mostrados
    const startItem = (currentPage - 1) * itemsPerPage + 1;
    const endItem = Math.min(currentPage * itemsPerPage, totalItems);
    
    let html = '<div class="pagination-container">';
    
    // Información de items
    html += `
        <div class="pagination-info">
            Mostrando <strong>${startItem}-${endItem}</strong> de <strong>${totalItems}</strong> escaneos
        </div>
    `;
    
    // Controles de navegación
    html += '<div class="pagination-controls">';
    
    // Botón Primera página
    html += `
        <button 
            class="pagination-btn ${currentPage === 1 ? 'disabled' : ''}" 
            onclick="goToPage(1)"
            ${currentPage === 1 ? 'disabled' : ''}>
            ⟨⟨
        </button>
    `;
    
    // Botón Anterior
    html += `
        <button 
            class="pagination-btn ${currentPage === 1 ? 'disabled' : ''}" 
            onclick="goToPage(${currentPage - 1})"
            ${currentPage === 1 ? 'disabled' : ''}>
            ⟨ Anterior
        </button>
    `;
    
    // Números de página (mostrar máximo 7 páginas)
    const pageNumbers = generatePageNumbers(currentPage, totalPages);
    
    pageNumbers.forEach(pageNum => {
        if (pageNum === '...') {
            html += '<span class="pagination-ellipsis">...</span>';
        } else {
            html += `
                <button 
                    class="pagination-btn page-number ${pageNum === currentPage ? 'active' : ''}" 
                    onclick="goToPage(${pageNum})">
                    ${pageNum}
                </button>
            `;
        }
    });
    
    // Botón Siguiente
    html += `
        <button 
            class="pagination-btn ${currentPage === totalPages ? 'disabled' : ''}" 
            onclick="goToPage(${currentPage + 1})"
            ${currentPage === totalPages ? 'disabled' : ''}>
            Siguiente ⟩
        </button>
    `;
    
    // Botón Última página
    html += `
        <button 
            class="pagination-btn ${currentPage === totalPages ? 'disabled' : ''}" 
            onclick="goToPage(${totalPages})"
            ${currentPage === totalPages ? 'disabled' : ''}>
            ⟩⟩
        </button>
    `;
    
    html += '</div>'; // pagination-controls
    
    // Selector de items por página
    html += `
        <div class="pagination-selector">
            <label for="itemsPerPageSelect">Items por página:</label>
            <select id="itemsPerPageSelect" onchange="changeItemsPerPage(this.value)">
                <option value="5" ${itemsPerPage === 5 ? 'selected' : ''}>5</option>
                <option value="10" ${itemsPerPage === 10 ? 'selected' : ''}>10</option>
                <option value="20" ${itemsPerPage === 20 ? 'selected' : ''}>20</option>
                <option value="50" ${itemsPerPage === 50 ? 'selected' : ''}>50</option>
            </select>
        </div>
    `;
    
    html += '</div>'; // pagination-container
    
    return html;
}

/**
 * Genera array de números de página a mostrar
 */
function generatePageNumbers(currentPage, totalPages) {
    const pages = [];
    
    if (totalPages <= 7) {
        // Mostrar todas las páginas si son 7 o menos
        for (let i = 1; i <= totalPages; i++) {
            pages.push(i);
        }
    } else {
        // Lógica compleja para mostrar: 1 ... 4 5 6 ... 10
        if (currentPage <= 3) {
            // Al inicio
            for (let i = 1; i <= 5; i++) pages.push(i);
            pages.push('...');
            pages.push(totalPages);
        } else if (currentPage >= totalPages - 2) {
            // Al final
            pages.push(1);
            pages.push('...');
            for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i);
        } else {
            // En medio
            pages.push(1);
            pages.push('...');
            for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i);
            pages.push('...');
            pages.push(totalPages);
        }
    }
    
    return pages;
}

/**
 * Actualiza los controles de paginación en el DOM
 */
function updatePaginationControls() {
    let paginationContainer = document.getElementById('paginationContainer');
    
    if (!paginationContainer) {
        // Crear contenedor si no existe
        paginationContainer = document.createElement('div');
        paginationContainer.id = 'paginationContainer';
        
        const tableWrapper = document.querySelector('.table-wrapper');
        tableWrapper.appendChild(paginationContainer);
    }
    
    paginationContainer.innerHTML = createPaginationControls();
}

/**
 * Cambia el número de items por página
 */
window.changeItemsPerPage = function(newValue) {
    PAGINATION_CONFIG.itemsPerPage = parseInt(newValue);
    PAGINATION_CONFIG.currentPage = 1; // Resetear a primera página
    
    // Recalcular páginas
    PAGINATION_CONFIG.totalPages = Math.ceil(
        PAGINATION_CONFIG.totalItems / PAGINATION_CONFIG.itemsPerPage
    );
    
    renderCurrentPage();
    updatePaginationControls();
};

/**
 * Función loadScanHistory MODIFICADA para usar paginación
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
        
        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No hay escaneos registrados todavía.</td></tr>';
            
            // Limpiar paginación
            const paginationContainer = document.getElementById('paginationContainer');
            if (paginationContainer) {
                paginationContainer.innerHTML = '';
            }
            
            return;
        }
        
        // Actualizar configuración de paginación
        updatePaginationConfig(scans);
        
        // Renderizar primera página
        await renderCurrentPage();
        
        // Crear/actualizar controles de paginación
        updatePaginationControls();
        
    } catch (error) {
        console.error('Error cargando historial:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="error-cell">
                    ❌ Error al cargar los escaneos. Verifica que Flask esté corriendo en el puerto 5000.
                </td>
            </tr>
        `;
        
        // Limpiar paginación en caso de error
        const paginationContainer = document.getElementById('paginationContainer');
        if (paginationContainer) {
            paginationContainer.innerHTML = '';
        }
    } finally {
        // Restaurar botón
        refreshBtn.innerHTML = originalBtnText;
        refreshBtn.disabled = false;
    }
}

// Exponer función goToPage globalmente
window.goToPage = goToPage;

// ===== EVENTOS =====

// Cargar tabla inicial cuando carga la página
document.addEventListener('DOMContentLoaded', () => {
    loadScanHistory();
});

// Botón de actualizar manual
document.getElementById('refreshHistoryBtn').addEventListener('click', () => {
    loadScanHistory();
});
