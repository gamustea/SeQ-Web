/* =====================================================
resources/js/config.js — Configuración de SecOps
Carga y guardado de la configuración
Depende de: shared.js (SeqSession, SeqToast, SeqUI, apiFetch)
===================================================== */

if (!SeqSession.load()) window.location.href = SeqSession.loginUrl;
SeqUI.initStarfield();

const API_CONFIG = "/system";

/* ─── GET NESTED VALUE ─── */
function getNestedValue(obj, path) {
    return path.split(".").reduce((current, key) => current && current[key], obj);
}

/* ─── SET NESTED VALUE ─── */
function setNestedValue(obj, path, value) {
    const keys = path.split(".");
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        const key = keys[i];
        if (!(key in current)) current[key] = {};
        current = current[key];
    }
    current[keys[keys.length - 1]] = value;
}

/* ─── LOAD CONFIG ─── */
let originalConfig = null;

async function loadConfig() {
    const res = await apiFetch(API_CONFIG);
    if (!res) return;

    if (!res.ok) {
        if (res.status === 401) return;
        SeqToast.show("Error al cargar la configuración", "error");
        return;
    }

    originalConfig = await res.json();
    fillForm(originalConfig);
}

/* ─── FILL FORM ─── */
function fillForm(config) {
    const form = document.getElementById("config-form");
    if (!form) return;

    form.querySelectorAll("input, textarea").forEach((input) => {
        const name = input.name;
        if (!name) return;

        const value = getNestedValue(config, name);
        if (value === undefined) return;

        if (input.type === "checkbox") {
            input.checked = value === true;
        } else {
            input.value = value;
        }
    });
}

/* ─── SAVE CONFIG ─── */
async function saveConfig(formData) {
    const res = await apiFetch(API_CONFIG, {
        method: "PUT",
        body: JSON.stringify(formData),
    });
    if (!res) return;

    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error_description || "Error al guardar la configuración");
    }

    originalConfig = await res.json();
    return { success: true, data: originalConfig };
}

/* ─── DEEP MERGE ─── */
function deepMerge(target, source) {
    const result = JSON.parse(JSON.stringify(target));
    for (const key in source) {
        if (source[key] !== null && typeof source[key] === "object" && !Array.isArray(source[key])) {
            result[key] = deepMerge(result[key] || {}, source[key]);
        } else if (source[key] !== "") {
            result[key] = source[key];
        }
    }
    return result;
}

/* ─── EXTRACT FORM DATA ─── */
function extractFormData() {
    const form = document.getElementById("config-form");
    if (!form || !originalConfig) {
        SeqToast.show("La configuración no ha cargado aún. Intenta de nuevo.", "error");
        return null;
    }

    const formDelta = {};
    form.querySelectorAll("input, textarea").forEach((input) => {
        const name = input.name;
        if (!name) return;

        let value;
        if (input.type === "checkbox") {
            value = input.checked;
        } else {
            value = input.value;
        }

        if (value !== "") setNestedValue(formDelta, name, value);
    });

    return deepMerge(originalConfig, formDelta);
}

/* ─── INITIALIZATION ─── */
document.addEventListener("DOMContentLoaded", () => {
    loadConfig();

    document.getElementById("btn-reset")?.addEventListener("click", () => {
        if (originalConfig) {
            fillForm(originalConfig);
            SeqToast.show("Configuración restablecida", "info");
        } else {
            loadConfig();
        }
    });

    document.getElementById("config-form")?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = extractFormData();
        if (!formData) return;

        try {
            await saveConfig(formData);
            SeqToast.show("Configuración guardada correctamente", "success");
        } catch (error) {
            SeqToast.show(error.message || "Error al guardar la configuración", "error");
        }
    });
});