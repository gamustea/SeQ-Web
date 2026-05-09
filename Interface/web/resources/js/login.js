/* ============================================================
   login.js — Lógica de la página de inicio de sesión
   ============================================================ */
"use strict";

const API_BASE = "";
const HUB_URL = "/pages/hub.html";

const TokenStore = (() => {
    let _access = null;
    let _refresh = null;
    let _exp = null;
    let _attrs = null;
    let _role = null;

    return {
        save(a, r, expiresIn, attrs, role) {
            _access = a;
            _refresh = r;
            _exp = Date.now() + expiresIn * 1000;
            _attrs = attrs || [];
            _role = role || "role_user";
        },
        clear() {
            _access = null;
            _refresh = null;
            _exp = null;
            _attrs = null;
            _role = null;
        },
        getAccess() {
            return _access;
        },
        getRefresh() {
            return _refresh;
        },
        expiresAt() {
            return _exp;
        },
        hasSession() {
            return !!_access;
        },
        getAttributes() {
            return _attrs;
        },
        getRole() {
            return _role;
        },
        isAdmin() {
            return _role === "role_admin" || _role === "role_root";
        },
        isRoot() {
            return _role === "role_root";
        },
        persist(redirectUrl) {
            sessionStorage.setItem(
                "seq_session",
                JSON.stringify({
                    accessToken: _access,
                    refreshToken: _refresh,
                    expiresAt: _exp,
                    role: _role,
                    attributes: _attrs,
                }),
            );
            this.clear();
            window.location.href = redirectUrl;
        },
    };
})();

const form = document.getElementById("login-form");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const btnSubmit = document.getElementById("btn-submit");
const alertEl = document.getElementById("alert");
const togglePwBtn = document.getElementById("toggle-pw");
const iconEye = document.getElementById("icon-eye");
const iconEyeOff = document.getElementById("icon-eye-off");

togglePwBtn.addEventListener("click", () => {
    const show = passwordInput.type === "password";
    passwordInput.type = show ? "text" : "password";
    iconEye.style.display = show ? "none" : "block";
    iconEyeOff.style.display = show ? "block" : "none";
});

function showAlert(msg, type = "error") {
    const isErr = type === "error";
    alertEl.className = `alert visible ${isErr ? "alert-error" : "alert-success"}`;
    alertEl.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24"
         fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      ${
          isErr
              ? '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
              : '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
      }
    </svg>
    <span>${msg}</span>`;
}
function hideAlert() {
    alertEl.classList.remove("visible");
}

function setLoading(on) {
    btnSubmit.disabled = on;
    btnSubmit.classList.toggle("loading", on);
    usernameInput.disabled = on;
    passwordInput.disabled = on;
}

function markError(input) {
    input.classList.add("input-error");
    input.addEventListener(
        "input",
        () => input.classList.remove("input-error"),
        { once: true },
    );
}

function validate(username, password) {
    if (!username.trim()) {
        showAlert("El nombre de usuario es obligatorio.");
        markError(usernameInput);
        usernameInput.focus();
        return false;
    }
    if (!password) {
        showAlert("La contraseña es obligatoria.");
        markError(passwordInput);
        passwordInput.focus();
        return false;
    }
    return true;
}

async function login(username, password) {
    const res = await fetch(`${API_BASE}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grantType: "password", username, password }),
    });
    const data = await res.json();
    console.log("Login response:", data);
    if (!res.ok) {
        if (res.status === 401)
            throw new Error(
                "Credenciales incorrectas. Verifica tu usuario y contraseña.",
            );
        if (res.status === 400)
            throw new Error(data.error_description || "Solicitud inválida.");
        if (res.status === 429)
            throw new Error(
                "Demasiados intentos. Espera unos minutos e inténtalo de nuevo.",
            );
        throw new Error(
            data.error_description || `Error del servidor (${res.status}).`,
        );
    }
    return data;
}

form.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideAlert();
    const username = usernameInput.value;
    const password = passwordInput.value;
    if (!validate(username, password)) return;
    setLoading(true);
    try {
        const data = await login(username, password);
        TokenStore.save(
            data.access_token,
            data.refresh_token,
            data.expires_in,
            data.attributes,
            data.role,
        );
        showAlert("Sesión iniciada. Redirigiendo…", "success");
        setTimeout(() => TokenStore.persist(HUB_URL), 800);
    } catch (err) {
        showAlert(err.message || "Error desconocido. Inténtalo de nuevo.");
        if (err.message?.includes("Credenciales")) {
            markError(usernameInput);
            markError(passwordInput);
            passwordInput.value = "";
            passwordInput.focus();
        }
    } finally {
        setLoading(false);
    }
});
