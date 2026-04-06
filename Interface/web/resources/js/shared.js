/* ============================================================
   shared.js — Lógica común de la plataforma SeQ
   Expone: SeqSession, SeqToast, SeqUI
   Incluir ANTES del JS específico de cada módulo.
   ============================================================ */
'use strict';

/* ══════════════════════════════════════════════════════════════
   CONFIG  — ajustar según entorno
══════════════════════════════════════════════════════════════ */
const SEQ_CONFIG = Object.freeze({
  API_BASE:  'http://localhost:5000',
  LOGIN_URL: '/pages/login.html',
});

/* ══════════════════════════════════════════════════════════════
   SeqSession — gestión completa de autenticación JWT
   ─────────────────────────────────────────────────────────────
   Uso mínimo en cualquier módulo:

     if (!SeqSession.load()) window.location.href = SeqSession.loginUrl;
     document.getElementById('session-user').textContent = SeqSession.username();
     document.getElementById('btn-logout').addEventListener('click', SeqSession.logout);

   Para llamadas autenticadas usar apiFetch() definido más abajo.
══════════════════════════════════════════════════════════════ */
const SeqSession = (() => {
  const STORAGE_KEY = 'seq_session';
  let _data = null;

  /** Carga la sesión desde sessionStorage. Devuelve true si es válida. */
  function load() {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return false;
    try {
      _data = JSON.parse(raw);
      return !!_data?.accessToken;
    } catch {
      return false;
    }
  }

  function _save() {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(_data));
  }

  /** Devuelve el access token vigente (refresca si está a punto de expirar). */
  async function getToken() {
    if (!_data) return null;
    if (Date.now() > _data.expiresAt - 60_000) {
      const ok = await _refresh();
      if (!ok) return null;
    }
    return _data.accessToken;
  }

  async function _refresh() {
    if (!_data?.refreshToken) return false;
    try {
      const res = await fetch(`${SEQ_CONFIG.API_BASE}/oauth/token`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ grantType: 'refresh_token', refreshToken: _data.refreshToken }),
      });
      if (!res.ok) return false;
      const d = await res.json();
      _data.accessToken = d.access_token;
      _data.expiresAt   = Date.now() + d.expires_in * 1000;
      _save();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Devuelve las cabeceras Authorization + Content-Type listas para fetch.
   * Si el token no se puede obtener, ejecuta logout() y devuelve null.
   */
  async function authHeaders() {
    const t = await getToken();
    if (!t) { logout(); return null; }
    return {
      'Authorization': `Bearer ${t}`,
      'Content-Type':  'application/json',
    };
  }

  /** Cierra la sesión: revoca el token, limpia storage y redirige al login. */
  function logout() {
    const token = _data?.accessToken;
    _data = null;
    sessionStorage.removeItem(STORAGE_KEY);
    if (token) {
      fetch(`${SEQ_CONFIG.API_BASE}/oauth/revoke`, {
        method:  'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      }).catch(() => {});
    }
    window.location.href = SEQ_CONFIG.LOGIN_URL;
  }

  /** Extrae el nombre de usuario del payload JWT (sin verificación). */
  function username() {
    if (!_data?.accessToken) return '';
    try {
      const payload = JSON.parse(atob(_data.accessToken.split('.')[1]));
      return payload.username || payload.sub || '';
    } catch {
      return '';
    }
  }

  return { load, getToken, authHeaders, logout, username, loginUrl: SEQ_CONFIG.LOGIN_URL };
})();

/* ══════════════════════════════════════════════════════════════
   apiFetch — wrapper autenticado sobre fetch
   ─────────────────────────────────────────────────────────────
   Uso:
     const res = await apiFetch('/aegis/topics');
     const res = await apiFetch('/sentinel/nmap', { method: 'POST', body: JSON.stringify({…}) });

   Devuelve null si la sesión no está disponible (ya habrá redirigido al login).
══════════════════════════════════════════════════════════════ */
async function apiFetch(path, options = {}) {
  const authH = await SeqSession.authHeaders();
  if (!authH) return null;

  const headers = { ...authH, ...(options.headers ?? {}) };

  // Si el body es FormData, el navegador añade el Content-Type con boundary solo
  if (options.body instanceof FormData) delete headers['Content-Type'];

  try {
    return await fetch(`${SEQ_CONFIG.API_BASE}${path}`, { ...options, headers });
  } catch (e) {
    console.error('[SeQ] apiFetch error:', e);
    return null;
  }
}

/* ══════════════════════════════════════════════════════════════
   SeqToast — notificaciones temporales no bloqueantes
   ─────────────────────────────────────────────────────────────
   Requiere en el HTML:
     <div id="toast" class="toast" role="alert" aria-live="assertive"></div>

   Uso:
     SeqToast.show('Operación completada', 'success');
     SeqToast.show('Algo falló', 'error');
     SeqToast.show('Ten en cuenta que…', 'warn');
     SeqToast.show('Procesando…', 'info');
══════════════════════════════════════════════════════════════ */
const SeqToast = (() => {
  let _timer;
  let _el;

  function _getEl() {
    if (!_el) _el = document.getElementById('toast');
    return _el;
  }

  /**
   * @param {string} msg   — Texto del mensaje.
   * @param {'success'|'error'|'warn'|'info'|''} [type=''] — Variante visual.
   * @param {number} [duration=3400] — Milisegundos antes de ocultarse.
   */
  function show(msg, type = '', duration = 3400) {
    const el = _getEl();
    if (!el) return;

    clearTimeout(_timer);
    el.textContent = msg;
    el.className   = `toast visible${type ? ` toast--${type}` : ''}`;
    _timer = setTimeout(() => el.classList.remove('visible'), duration);
  }

  return { show };
})();

/* ══════════════════════════════════════════════════════════════
   SeqUI — helpers de interfaz reutilizables
══════════════════════════════════════════════════════════════ */
const SeqUI = (() => {

  /** Escapa caracteres HTML para inserción segura en innerHTML. */
  function escHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Formatea una fecha ISO a cadena localizada.
   * @param {string|null} iso
   * @param {'es-ES'|string} [locale='es-ES']
   */
  function formatDate(iso, locale = 'es-ES') {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString(locale, {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  }

  /**
   * Devuelve el HTML de una pastilla de estado genérica.
   * @param {'running'|'done'|'finished'|'pending'|'error'|'cancelled'} status
   */
  function statusBadge(status) {
    const MAP = {
      running:   ['badge--running',   'Ejecutando'],
      done:      ['badge--done',      'Completado'],
      finished:  ['badge--done',      'Completado'],
      pending:   ['badge--pending',   'Pendiente'],
      error:     ['badge--error',     'Error'],
      cancelled: ['badge--cancelled', 'Cancelado'],
    };
    const [cls, label] = MAP[(status ?? '').toLowerCase()] ?? ['badge--pending', status ?? '—'];
    return `<span class="badge ${cls}">${label}</span>`;
  }

  /**
   * Inicializa la topbar del módulo activo:
   * - Muestra el nombre de usuario en #session-user.
   * - Conecta #btn-logout al método de cierre de sesión.
   *
   * @param {string} [userId='session-user']
   * @param {string} [logoutId='btn-logout']
   */
  function initTopbar(userId = 'session-user', logoutId = 'btn-logout') {
    const userEl   = document.getElementById(userId);
    const logoutEl = document.getElementById(logoutId);
    if (userEl)   userEl.textContent = SeqSession.username();
    if (logoutEl) logoutEl.addEventListener('click', SeqSession.logout);
  }

  /**
   * Guarda de sesión en línea: redirige al login si no hay sesión activa.
   * Llamar al principio del DOMContentLoaded de cada módulo.
   */
  function requireSession() {
    if (!SeqSession.load()) {
      window.location.href = SEQ_CONFIG.LOGIN_URL;
      return false;
    }
    return true;
  }

  return { escHtml, formatDate, statusBadge, initTopbar, requireSession };
})();
