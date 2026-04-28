/* =====================================================
resources/js/profile.js — Perfil de Usuario
Carga y edición del perfil del usuario autenticado
===================================================== */

const API_BASE = '';
const API_URL = {
profile: `${API_BASE}/users/me`,
changePassword: `${API_BASE}/users/change-password`
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

/* ─── LOAD PROFILE ─── */
async function loadProfile() {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.profile, {
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
throw new Error('Error al cargar el perfil');
}

const data = await response.json();

// Header
document.getElementById('profile-name').textContent = `${data.first_name} ${data.last_name}`;
document.getElementById('profile-username').textContent = `@${data.username}`;

// Form
document.getElementById('first-name').value = data.first_name;
document.getElementById('last-name').value = data.last_name;
document.getElementById('email').value = data.email;
document.getElementById('username').value = data.username;

} catch (error) {
console.error('Error loading profile:', error);
showToast('Error al cargar el perfil', 'error');
}
}

/* ─── UPDATE PROFILE ─── */
async function updateProfile(formData) {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.profile, {
method: 'PUT',
headers: {
'Authorization': `Bearer ${session.accessToken}`,
'Content-Type': 'application/json'
},
body: JSON.stringify(formData)
});

if (!response.ok) {
const error = await response.json();
throw new Error(error.error_description || 'Error al actualizar el perfil');
}

const data = await response.json();

// Update header con nuevos datos
document.getElementById('profile-name').textContent = `${data.first_name} ${data.last_name}`;

return { success: true, data };

} catch (error) {
console.error('Error updating profile:', error);
throw error;
}
}

/* ─── CHANGE PASSWORD ─── */
async function changePassword(currentPassword, newPassword) {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.changePassword, {
method: 'PUT',
headers: {
'Authorization': `Bearer ${session.accessToken}`,
'Content-Type': 'application/json'
},
body: JSON.stringify({ newPassword })
});

if (!response.ok) {
const error = await response.json();
throw new Error(error.error_description || 'Error al cambiar la contraseña');
}

return { success: true };

} catch (error) {
console.error('Error changing password:', error);
throw error;
}
}

/* ─── INITIALIZATION ─── */
document.addEventListener('DOMContentLoaded', () => {
// Cargar perfil
loadProfile();

// Profile form
const profileForm = document.getElementById('profile-form');
const btnCancel = document.getElementById('btn-cancel');

btnCancel?.addEventListener('click', () => {
window.location.href = '/pages/hub.html';
});

profileForm?.addEventListener('submit', async (e) => {
e.preventDefault();

const formData = {
first_name: document.getElementById('first-name').value.trim(),
last_name: document.getElementById('last-name').value.trim()
};

try {
await updateProfile(formData);
showToast('Perfil actualizado correctamente', 'success');
} catch (error) {
showToast('Error al actualizar el perfil', 'error');
}
});

// Password form
const passwordForm = document.getElementById('password-form');

passwordForm?.addEventListener('submit', async (e) => {
e.preventDefault();

const currentPassword = document.getElementById('current-password').value;
const newPassword = document.getElementById('new-password').value;
const confirmPassword = document.getElementById('confirm-password').value;

// Validaciones
if (newPassword.length < 8) {
showToast('La contraseña debe tener al menos 8 caracteres', 'error');
return;
}

if (newPassword !== confirmPassword) {
showToast('Las contraseñas no coinciden', 'error');
return;
}

if (currentPassword === newPassword) {
showToast('La nueva contraseña debe ser diferente', 'error');
return;
}

try {
await changePassword(currentPassword, newPassword);
passwordForm.reset();
showToast('Contraseña cambiada correctamente. Inicie sesión de nuevo.', 'success');
setTimeout(() => {
sessionStorage.removeItem('seq_session');
window.location.href = '/pages/login.html';
}, 2000);
} catch (error) {
showToast('Error al cambiar la contraseña', 'error');
}
});
});
