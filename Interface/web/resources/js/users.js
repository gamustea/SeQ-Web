/* =====================================================
resources/js/users.js — Gestión de Usuarios
Lista usuarios del sistema
===================================================== */

const API_BASE = '';
const API_URL = {
users: `${API_BASE}/users`
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

/* ─── LOAD USERS ─── */
async function loadUsers() {
const session = JSON.parse(sessionStorage.getItem('seq_session'));
if (!session) return;

try {
const response = await fetch(API_URL.users, {
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
if (response.status === 403) {
showToast('No tienes permisos para ver usuarios', 'error');
return;
}
throw new Error('Error al cargar usuarios');
}

const users = await response.json();
renderUsers(users);

} catch (error) {
console.error('Error loading users:', error);
showToast('Error al cargar usuarios', 'error');
}
}

/* ─── RENDER USERS ─── */
function renderUsers(users) {
const tbody = document.getElementById('users-tbody');
if (!tbody) return;

if (!users || users.length === 0) {
tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No hay usuarios registrados</td></tr>';
return;
}

tbody.innerHTML = users.map(user => `
<tr>
<td>${user.id}</td>
<td>@${user.username}</td>
<td>${user.email}</td>
<td>${user.first_name}</td>
<td>${user.last_name}</td>
<td>${formatDate(user.created_at)}</td>
</tr>
`).join('');
}

/* ─── DATE FORMATTER ─── */
function formatDate(dateStr) {
if (!dateStr) return '-';
const date = new Date(dateStr);
return date.toLocaleDateString('es-ES', {
year: 'numeric',
month: 'short',
day: 'numeric'
});
}

/* ─── INITIALIZATION ─── */
document.addEventListener('DOMContentLoaded', () => {
loadUsers();
});