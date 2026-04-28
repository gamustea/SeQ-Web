/* =====================================================
resources/js/config.js — Configuración de SecOps
Carga y guardado de la configuración
===================================================== */

const API_BASE = '';
const API_URL = {
config: `${API_BASE}/system`
};

/* ─── SESSION GUARD ─── */
(function () {
const raw = sessionStorage.getItem('seq_session');
if (!raw) { window.location.href = '/pages/login.html'; return; }
try {
const s = JSON.parse(raw);
if (!s.accessToken || Date.now() > s.expiresAt) {
sessionStorage.removeItem('seq_session');
window.location.href = '/pages/login.html';
}
} catch {
window.location.href = '/pages/login.html';
}
})();

/* ─── STARFIELD ─── */
(function () {
const container = document.getElementById('stars');
if (!container) return;
for (let i = 0; i < 120; i++) {
const star = document.createElement('div');
star.className = 'star';
star.style.left = Math.random() * 100 + '%';
star.style.top = Math.random() * 100 + '%';
const size = Math.random() * 2 + 1;
star.style.width = size + 'px';
star.style.height = size + 'px';
star.style.animationDelay = Math.random() * 4 + 's';
star.style.animationDuration = (Math.random() * 3 + 2) + 's';
container.appendChild(star);
}
})();

/* ─── TOAST NOTIFICATIONS ─── */
function showToast(message, type = 'info') {
const toast = document.getElementById('toast');
if (!toast) return;

toast.textContent = message;
toast.className = `toast toast--${type} visible`;

setTimeout(() => {
toast.classList.remove('visible');
}, 3000);
}

/* ─── GET NESTED VALUE ─── */
function getNestedValue(obj, path) {
return path.split('.').reduce((current, key) => current && current[key], obj);
}

/* ─── SET NESTED VALUE ─── */
function setNestedValue(obj, path, value) {
const keys = path.split('.');
let current = obj;
for (let i = 0; i < keys.length - 1; i++) {
const key = keys[i];
if (!(key in current)) {
current[key] = {};
}
current = current[key];
}
current[keys[keys.length - 1]] = value;
}

/* ─── LOAD CONFIG ─── */
let originalConfig = null;

async function loadConfig() {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.config, {
headers: {
'Authorization': `Bearer ${session.accessToken}`,
'Content-Type': 'application/json'
}
});

if (!response.ok) {
if (response.status === 401) {
sessionStorage.removeItem('seq_session');
window.location.href = '/pages/login.html';
return;
}
throw new Error('Error al cargar la configuración');
}

originalConfig = await response.json();
fillForm(originalConfig);

} catch (error) {
console.error('Error loading config:', error);
showToast('Error al cargar la configuración', 'error');
}
}

/* ─── FILL FORM ─── */
function fillForm(config) {
const form = document.getElementById('config-form');
if (!form) return;

const inputs = form.querySelectorAll('input, textarea');
inputs.forEach(input => {
const name = input.name;
if (!name) return;

const value = getNestedValue(config, name);
if (value === undefined) return;

if (input.type === 'checkbox') {
input.checked = value === true;
} else if (input.type === 'color') {
input.value = value;
} else {
input.value = value;
}
});
}

/* ─── SAVE CONFIG ─── */
async function saveConfig(formData) {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.config, {
method: 'PUT',
headers: {
'Authorization': `Bearer ${session.accessToken}`,
'Content-Type': 'application/json'
},
body: JSON.stringify(formData)
});

if (!response.ok) {
const error = await response.json();
throw new Error(error.error_description || 'Error al guardar la configuración');
}

const data = await response.json();
originalConfig = data;
return { success: true, data };

} catch (error) {
console.error('Error saving config:', error);
throw error;
}
}

/* ─── DEEP MERGE ─── */
function deepMerge(target, source) {
  const result = JSON.parse(JSON.stringify(target));
  for (const key in source) {
    if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      result[key] = deepMerge(result[key] || {}, source[key]);
    } else if (source[key] !== '') {
      result[key] = source[key];
    }
  }
  return result;
}

/* ─── EXTRACT FORM DATA ─── */
function extractFormData() {
  const form = document.getElementById('config-form');
  if (!form || !originalConfig) {
    showToast('La configuración no ha cargado aún. Intenta de nuevo.', 'error');
    return null;
  }

  const formDelta = {};
  const inputs = form.querySelectorAll('input, textarea');
  inputs.forEach(input => {
    const name = input.name;
    if (!name) return;

    let value;
    if (input.type === 'checkbox') {
      value = input.checked;
    } else if (input.type === 'color' || input.type === 'text') {
      value = input.value;
    } else {
      value = input.value;
    }

    if (value !== '') {
      setNestedValue(formDelta, name, value);
    }
  });

  return deepMerge(originalConfig, formDelta);
}

/* ─── INITIALIZATION ─── */
document.addEventListener('DOMContentLoaded', () => {
loadConfig();

const configForm = document.getElementById('config-form');
const btnReset = document.getElementById('btn-reset');

btnReset?.addEventListener('click', () => {
if (originalConfig) {
fillForm(originalConfig);
showToast('Configuración restablecida', 'info');
} else {
loadConfig();
}
});

configForm?.addEventListener('submit', async (e) => {
  e.preventDefault();

  const formData = extractFormData();
  if (!formData) return;

  try {
    await saveConfig(formData);
    showToast('Configuración guardada correctamente', 'success');
  } catch (error) {
    showToast('Error al guardar la configuración', 'error');
  }
});
});