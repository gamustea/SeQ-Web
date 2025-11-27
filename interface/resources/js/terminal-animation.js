/**
 * TERMINAL ANIMATION
 * Simula la interacción con la API Flask usando los endpoints reales
 * Efecto typewriter con velocidades diferenciadas
 */

const terminalOutput = document.getElementById('terminalOutput');

const apiDemoSteps = [
    {
        text: '> curl -X POST /scans/nmap/start \n -H "host: 10.0.0.5" \n  -H "ports: 22,80"',
        delay: 800,
        isCommand: true
    },
    {
        text: `HTTP/1.1 201 CREATED
{
    "message": "Escaneo Nmap iniciado correctamente",
    "scanId": 104,
    "target": {
        "host": "10.0.0.5",
        "ports": "22,80"
    }
}`,
        cssClass: 'api-response',
        delay: 2000,
        isCommand: false
    },
    {
        text: '> curl -X GET /scans/generate-pdf-base64?id=104',
        delay: 6000,
        isCommand: true
    },
    {
        text: `HTTP/1.1 200 OK
{
  "filename": "nmap_scan_104.pdf",
  "pdfBase64": "JVBERi0xLjQKJ..."
}`,
        cssClass: 'api-response',
        delay: 7000,
        isCommand: false
    }
];

/**
 * Efecto Typewriter: escribe carácter por carácter
 * @param {HTMLElement} element - Elemento donde escribir
 * @param {string} text - Texto a escribir
 * @param {number} speed - Milisegundos entre cada carácter
 */
async function typewriterEffect(element, text, speed) {
    let currentText = '';

    for (let char of text) {
        currentText += char;

        if (element.classList.contains('cmd-line')) {
            // Para comandos, mantener el prompt visible
            element.innerHTML = `<span class="prompt">$</span> ${currentText}`;
        } else {
            element.textContent = currentText;
        }

        // Pequeña pausa entre caracteres
        await new Promise(resolve => setTimeout(resolve, speed));
    }
}

async function runTerminalAnimation() {
    // Velocidades (en milisegundos por carácter)
    const COMMAND_SPEED = 50;    // Más lento (simula escritura humana)
    const RESPONSE_SPEED = 8;    // Más rápido (simula salida de máquina)

    for (let step of apiDemoSteps) {
        // Calcular tiempo de espera antes de mostrar este paso
        const previousDelay = apiDemoSteps[apiDemoSteps.indexOf(step) - 1]?.delay || 0;
        const waitTime = step.delay - previousDelay;

        await new Promise(resolve => setTimeout(resolve, waitTime));

        // Crear elemento de línea
        const lineElement = document.createElement('div');
        lineElement.className = step.cssClass || 'cmd-line';
        terminalOutput.appendChild(lineElement);

        // Elegir velocidad según tipo
        const speed = step.isCommand ? COMMAND_SPEED : RESPONSE_SPEED;

        // Aplicar efecto typewriter
        await typewriterEffect(lineElement, step.text, speed);

        // Auto-scroll
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }

    // Añadir cursor final parpadeante
    const cursorLine = document.createElement('div');
    cursorLine.className = 'cmd-line';
    cursorLine.innerHTML = `<span class="prompt">$</span> <span class="cursor"></span>`;
    terminalOutput.appendChild(cursorLine);
}

// Ejecutar cuando la página cargue completamente
window.addEventListener('load', runTerminalAnimation);
