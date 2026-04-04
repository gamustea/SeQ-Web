/* =====================================================
   resources/js/hub.js — SeQ Hub
   Guarda de sesión + generación del starfield
   ===================================================== */

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
  for (let i = 0; i < 120; i++) {
    const star = document.createElement('div');
    star.className = 'star';
    star.style.left   = Math.random() * 100 + '%';
    star.style.top    = Math.random() * 100 + '%';
    const size = Math.random() * 2 + 1;
    star.style.width  = size + 'px';
    star.style.height = size + 'px';
    star.style.animationDelay    = Math.random() * 4 + 's';
    star.style.animationDuration = (Math.random() * 3 + 2) + 's';
    container.appendChild(star);
  }
})();
