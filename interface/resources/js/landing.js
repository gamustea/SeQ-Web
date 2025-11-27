const API_URL = "http://127.0.0.1:5000";

document.addEventListener('DOMContentLoaded', () => {
    checkConnection();
    loadResults();

    // --- NMAP Handler ---
    document.getElementById('nmapForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = e.target.querySelector('button');
        setLoading(btn, true);

        const host = document.getElementById('nmapHost').value;
        const ports = document.getElementById('nmapPorts').value;

        try {
            // API Requirement: Headers for host/ports
            const res = await fetch(`${API_URL}/scans/nmap/start`, {
                method: 'POST',
                headers: { 'host': host, 'ports': ports }
            });
            const data = await res.json();
            
            if(res.ok) {
                alert(`✅ Nmap iniciado (ID: ${data.scanId})`);
                e.target.reset();
                loadResults();
            } else {
                alert(`⚠️ Error: ${data.error || 'Desconocido'}`);
            }
        } catch (err) {
            alert("Error de conexión con el servidor.");
        } finally {
            setLoading(btn, false);
        }
    });

    // --- NIKTO Handler ---
    document.getElementById('niktoForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const btn = e.target.querySelector('button');
        setLoading(btn, true);

        const target = document.getElementById('niktoTarget').value;
        const timeout = document.getElementById('niktoTimeout').value;

        try {
            // API Requirement: Header for target, Query param for timeout
            const res = await fetch(`${API_URL}/scans/nikto/start?timeout=${timeout}`, {
                method: 'POST',
                headers: { 'target': target }
            });
            const data = await res.json();

            if(res.ok) {
                alert(`✅ Nikto iniciado (ID: ${data.scanId})`);
                e.target.reset();
                loadResults();
            } else {
                alert(`⚠️ Error: ${data.error}`);
            }
        } catch (err) {
            alert("Error de conexión con el servidor.");
        } finally {
            setLoading(btn, false);
        }
    });

    // Refresh Button
    document.getElementById('refreshBtn').addEventListener('click', loadResults);

    // Modal Close
    document.querySelector('.close-modal').addEventListener('click', () => {
        document.getElementById('pdfModal').classList.remove('active');
    });
});

// --- FUNCIONES AUXILIARES ---

async function checkConnection() {
    const dot = document.getElementById('apiStatusDot');
    const txt = document.getElementById('apiStatusText');
    try {
        const res = await fetch(`${API_URL}/say-hello`);
        if(res.ok) {
            dot.classList.add('active');
            txt.textContent = "API Conectada";
            txt.style.color = "#66bb6a";
        }
    } catch(e) {
        dot.classList.remove('active');
        txt.textContent = "Sin conexión";
        txt.style.color = "#ef5350";
    }
}

async function loadResults() {
    const tbody = document.getElementById('resultsTableBody');
    
    try {
        const res = await fetch(`${API_URL}/scans/results?type=all`);
        const data = await res.json();

        if(!res.ok) throw new Error("Error fetching data");

        const scans = data.results.sort((a, b) => b.id - a.id); // Ordenar DESC
        tbody.innerHTML = '';

        if(scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:30px; opacity:0.5">No hay escaneos recientes.</td></tr>';
            return;
        }

        for(let scan of scans) {
            const tr = document.createElement('tr');
            const dateStr = new Date(scan.startedAt).toLocaleString();
            const typeClass = scan.scanType === 'nmap' ? 'tag-nmap' : 'tag-nikto';
            
            // Placeholder para estado
            const statusId = `status-${scan.id}`;

            tr.innerHTML = `
                <td><span style="font-family:monospace; opacity:0.7">#${scan.id}</span></td>
                <td><span class="tag ${typeClass}">${scan.scanType}</span></td>
                <td style="font-family:monospace">${scan.target}</td>
                <td style="font-size:0.85rem; color:#888">${dateStr}</td>
                <td id="${statusId}" style="font-size:0.85rem">...</td>
                <td>
                    <button class="btn-outlined btn-sm" onclick="openPdf(${scan.id})">📄 Ver PDF</button>
                </td>
            `;
            tbody.appendChild(tr);
            
            // Checkear estado individualmente
            checkStatus(scan.id, statusId);
        }

    } catch(e) {
        console.error(e);
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#ef5350">Error cargando datos. Verifica que la API corre en puerto 5000.</td></tr>';
    }
}

async function checkStatus(id, domId) {
    try {
        const res = await fetch(`${API_URL}/is-finished?id=${id}`);
        const data = await res.json();
        const el = document.getElementById(domId);
        if(el) {
            if(data.existe) {
                el.innerHTML = '<span style="color: #66bb6a">● Terminado</span>';
            } else {
                el.innerHTML = '<span style="color: #ffb300">● En proceso</span>';
            }
        }
    } catch(e) {}
}

window.openPdf = async (id) => {
    const modal = document.getElementById('pdfModal');
    const frame = document.getElementById('pdfFrame');
    const link = document.getElementById('downloadLink');
    
    modal.classList.add('active');
    frame.src = "about:blank"; 

    try {
        const res = await fetch(`${API_URL}/scans/generate-pdf-base64?id=${id}`);
        const data = await res.json();

        if(data.pdfBase64) {
            const src = `data:application/pdf;base64,${data.pdfBase64}`;
            frame.src = src;
            link.href = src;
            link.download = data.filename || `scan_${id}.pdf`;
        } else {
            alert("No se pudo generar el PDF (quizás el scan falló o no terminó).");
            modal.classList.remove('active');
        }
    } catch(e) {
        alert("Error al solicitar el PDF.");
        modal.classList.remove('active');
    }
};

function setLoading(btn, isLoading) {
    if(isLoading) {
        btn.dataset.text = btn.textContent;
        btn.textContent = "Iniciando...";
        btn.disabled = true;
        btn.style.opacity = 0.7;
    } else {
        btn.textContent = btn.dataset.text;
        btn.disabled = false;
        btn.style.opacity = 1;
    }
}
