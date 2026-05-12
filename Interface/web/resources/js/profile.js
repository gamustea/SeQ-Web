/* =====================================================
resources/js/profile.js — Perfil de Usuario
Carga y edición del perfil del usuario autenticado
Depende de: shared.js (SeqSession, SeqToast, SeqUI, apiFetch)
===================================================== */

if (!SeqSession.load()) window.location.href = SeqSession.loginUrl;
SeqUI.initStarfield();

const API_PROFILE = "/users/me";
const API_PASSWORD = "/users/change-password";

/* ─── LOAD PROFILE ─── */
async function loadProfile() {
    const res = await apiFetch(API_PROFILE);
    if (!res) return;

    if (!res.ok) {
        if (res.status === 401) return;
        SeqToast.show("Error al cargar el perfil", "error");
        return;
    }

    const data = await res.json();

    document.getElementById("profile-name").textContent = `${data.first_name} ${data.last_name}`;
    document.getElementById("profile-username").textContent = `@${data.username}`;
    document.getElementById("first-name").value = data.first_name;
    document.getElementById("last-name").value = data.last_name;
    document.getElementById("email").value = data.email;
    document.getElementById("username").value = data.username;
}

/* ─── UPDATE PROFILE ─── */
async function updateProfile(formData) {
    const res = await apiFetch(API_PROFILE, {
        method: "PUT",
        body: JSON.stringify(formData),
    });
    if (!res) return;

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error_description || "Error al actualizar el perfil");
    }

    const data = await res.json();
    document.getElementById("profile-name").textContent = `${data.first_name} ${data.last_name}`;
    return { success: true, data };
}

/* ─── CHANGE PASSWORD ─── */
async function changePassword(newPassword) {
    const res = await apiFetch(API_PASSWORD, {
        method: "PUT",
        body: JSON.stringify({ newPassword }),
    });
    if (!res) return;

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error_description || "Error al cambiar la contraseña");
    }

    return { success: true };
}

/* ─── INITIALIZATION ─── */
document.addEventListener("DOMContentLoaded", () => {
    loadProfile();

    document.getElementById("btn-cancel")?.addEventListener("click", () => {
        window.location.href = "/pages/hub.html";
    });

    document.getElementById("profile-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = {
            first_name: document.getElementById("first-name").value.trim(),
            last_name: document.getElementById("last-name").value.trim(),
        };

        try {
            await updateProfile(formData);
            SeqToast.show("Perfil actualizado correctamente", "success");
        } catch (error) {
            SeqToast.show("Error al actualizar el perfil", "error");
        }
    });

    document.getElementById("password-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();

        const currentPassword = document.getElementById("current-password").value;
        const newPassword = document.getElementById("new-password").value;
        const confirmPassword = document.getElementById("confirm-password").value;

        if (newPassword.length < 8) {
            SeqToast.show("La contraseña debe tener al menos 8 caracteres", "error");
            return;
        }

        if (newPassword !== confirmPassword) {
            SeqToast.show("Las contraseñas no coinciden", "error");
            return;
        }

        if (currentPassword === newPassword) {
            SeqToast.show("La nueva contraseña debe ser diferente", "error");
            return;
        }

        try {
            await changePassword(newPassword);
            document.getElementById("password-form").reset();
            SeqToast.show("Contraseña cambiada correctamente. Inicie sesión de nuevo.", "success");
            setTimeout(() => SeqSession.logout(), 2000);
        } catch (error) {
            SeqToast.show("Error al cambiar la contraseña", "error");
        }
    });
});