/* =====================================================
resources/js/users.js — Gestión de Usuarios
Lista usuarios del sistema en formato card
Depende de: shared.js (SeqSession, SeqToast, SeqUI, apiFetch)
===================================================== */

if (!SeqSession.load()) window.location.href = SeqSession.loginUrl;
SeqUI.initStarfield();

const API_USERS = "/users";
const API_SIGNUP = "/users/sign-up";

var ALL_ATTRIBUTES = [
    { module: "Aegis",    attrs: ["aegis_create", "aegis_read", "aegis_update", "aegis_delete"] },
    { module: "Sentinel", attrs: ["sentinel_create", "sentinel_read", "sentinel_update", "sentinel_delete"] },
    { module: "Acheron", attrs: ["acheron_create", "acheron_read", "acheron_update", "acheron_delete"] },
];

function showToast(message, type) {
    SeqToast.show(message, type || "info");
}

function getInitials(firstName, lastName) {
    return (firstName ? firstName.charAt(0).toUpperCase() : "") + (lastName ? lastName.charAt(0).toUpperCase() : "") || "??";
}

function formatDate(dateStr) {
    if (!dateStr) return "-";
    return new Date(dateStr).toLocaleDateString("es-ES", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function updateCount(count) {
    var el = document.getElementById("users-count");
    if (el) el.textContent = count + " usuario" + (count !== 1 ? "s" : "");
}

function buildAttributeSection(attributes, isAdminOrRoot) {
    var tags = "";
    for (var i = 0; i < attributes.length; i++) {
        var rmBtn = isAdminOrRoot ? '<button class="attr-remove" data-attr="' + attributes[i] + '" title="Eliminar">&times;</button>' : "";
        tags += '<span class="attr-tag">' + attributes[i] + rmBtn + "</span>";
    }
    var addBtn = isAdminOrRoot ? '<button class="btn btn--ghost btn--sm" id="btn-add-attr">+ Añadir atributo</button>' : "";
    return '<div class="user-attributes" id="attr-section"><div class="attr-header"><span class="attr-label">Atributos ABAC</span>' + addBtn + '</div>' + (attributes.length > 0 ? '<div class="attr-tags">' + tags + '</div>' : '<span class="no-attrs">Sin atributos adicionales</span>') + '<div id="attr-form-container"></div></div>';
}

function renderUsers(users) {
    var grid = document.getElementById("users-grid");
    if (!grid) return;

    if (!users || users.length === 0) {
        grid.innerHTML = '<div class="users-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><h3>No hay usuarios registrados</h3><p>Crea el primer usuario</p></div>';
        return;
    }

    var rootHtml = "", adminsHtml = "", basicHtml = "";
    var rootCount = 0, adminCount = 0, basicCount = 0;

    for (var i = 0; i < users.length; i++) {
        var user = users[i];
        var userIsRoot = user.role === "role_root";
        var userIsAdmin = user.role === "role_admin";

        var cardClass = userIsRoot ? "user-card user-card--root" : userIsAdmin ? "user-card user-card--admin" : "user-card user-card--basic";
        var roleLabel = userIsRoot ? "Root" : userIsAdmin ? "Administrador" : "Usuario";

        var cardHtml =
            '<article class="' + cardClass + '">' +
            '<div class="user-card__header">' +
            '<div class="user-card__avatar">' + getInitials(user.first_name, user.last_name) + '</div>' +
            '<div class="user-card__info"><div class="user-card__username">@' + user.username + '</div><div class="user-card__id">ID: ' + user.id + '</div></div>' +
            '</div>' +
            '<div class="user-card__details">' +
            '<div class="user-card__row"><span class="user-card__label">Nombre</span><span class="user-card__value">' + user.first_name + " " + user.last_name + '</span></div>' +
            '<div class="user-card__row"><span class="user-card__label">Correo</span><span class="user-card__value user-card__value--email">' + user.email + '</span></div>' +
            '<div class="user-card__row"><span class="user-card__label">Rol</span><span class="user-card__value">' + roleLabel + '</span></div>' +
            '</div>' +
            '<div class="user-card__footer">' +
            '<span class="user-card__date">' + formatDate(user.created_at) + '</span>' +
            '<button class="btn-details" data-user-id="' + user.id + '">Detalles</button>' +
            '</div></article>';

        if (userIsRoot) { rootCount++; rootHtml += cardHtml; }
        else if (userIsAdmin) { adminCount++; adminsHtml += cardHtml; }
        else { basicCount++; basicHtml += cardHtml; }
    }

    var sectionsHtml = "";
    if (rootHtml) sectionsHtml += '<section class="user-section"><h2 class="user-section__title">Root (' + rootCount + ')</h2><div class="user-section__grid">' + rootHtml + '</div></section>';
    if (adminsHtml) sectionsHtml += '<section class="user-section"><h2 class="user-section__title">Administradores (' + adminCount + ')</h2><div class="user-section__grid">' + adminsHtml + '</div></section>';
    if (basicHtml) sectionsHtml += '<section class="user-section"><h2 class="user-section__title">Usuarios (' + basicCount + ')</h2><div class="user-section__grid">' + basicHtml + '</div></section>';

    grid.innerHTML = sectionsHtml;

    grid.querySelectorAll(".btn-details").forEach(function (btn) {
        btn.addEventListener("click", function () {
            showUserDetails(parseInt(this.getAttribute("data-user-id")));
        });
    });
}

async function loadUsers() {
    var res = await apiFetch(API_USERS);
    if (!res) return;

    if (!res.ok) {
        if (res.status === 401) return;
        showToast("Error al cargar usuarios", "error");
        return;
    }

    var users = await res.json();
    for (var j = 0; j < users.length; j++) {
        users[j].role = users[j].role || "role_user";
    }

    renderUsers(users);
    updateCount(users.length);
}

async function createUser(userData) {
    var res = await apiFetch(API_SIGNUP, { method: "POST", body: JSON.stringify(userData) });
    if (!res) return { success: false };

    if (!res.ok) {
        var err = await res.json().catch(() => ({}));
        if (res.status === 403) showToast(err.error_description || "No tienes permisos para crear usuarios", "error");
        else if (res.status === 409) showToast(err.error_description || "El usuario o correo ya existe", "error");
        else showToast(err.error_description || "Error al crear usuario", "error");
        return { success: false };
    }

    showToast("Usuario creado correctamente", "success");
    loadUsers();
    return { success: true };
}

function showCreateModal() {
    var roleField = "";
    if (SeqSession.isRoot()) {
        roleField = '<div class="form-section"><div class="form-section__title">Configuración</div><div class="form-group"><label for="new-role">Rol</label><select id="new-role" name="role"><option value="role_user">Usuario</option><option value="role_admin">Administrador</option></select></div></div>';
    }

    var modal = document.createElement("div");
    modal.className = "modal-overlay";
    modal.innerHTML =
        '<div class="modal">' +
        '<div class="modal-header"><h2>Crear Nuevo Usuario</h2><button class="modal-close">&times;</button></div>' +
        '<form id="create-user-form">' +
        '<div class="form-section"><div class="form-section__title">Información Personal</div>' +
        '<div class="form-row">' +
        '<div class="form-group"><label for="new-first-name">Nombre</label><div class="input-wrapper"><svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><input type="text" id="new-first-name" name="first_name" required /></div></div>' +
        '<div class="form-group"><label for="new-last-name">Apellidos</label><div class="input-wrapper"><svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><input type="text" id="new-last-name" name="last_name" required /></div></div>' +
        '</div></div>' +
        '<div class="form-section"><div class="form-section__title">Credenciales</div>' +
        '<div class="form-group"><label for="new-username">Nombre de usuario</label><div class="input-wrapper"><svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg><input type="text" id="new-username" name="username" required /></div></div>' +
        '<div class="form-group"><label for="new-email">Correo electrónico</label><div class="input-wrapper"><svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 7l-10 6L2 7"/></svg><input type="email" id="new-email" name="email" required /></div></div>' +
        '<div class="form-group"><label for="new-password">Contraseña</label><div class="input-wrapper"><svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><input type="password" id="new-password" name="password" required minlength="8" /><button type="button" class="toggle-password" aria-label="Mostrar contraseña"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div><div class="password-strength" id="password-strength" style="display:none;"><div class="strength-bar"><div class="strength-fill" id="strength-fill"></div></div><span class="strength-text" id="strength-text"></span></div><span class="form-hint">Mínimo 8 caracteres</span></div>' +
        '</div>' + roleField +
        '<div class="form-section"><div class="form-actions"><button type="button" class="btn btn--ghost" id="btn-cancel">Cancelar</button><button type="submit" class="btn btn--primary">Crear Usuario</button></div></div>' +
        '</form></div>';

    document.body.appendChild(modal);

    var toggleBtn = modal.querySelector(".toggle-password");
    var passwordInput = modal.querySelector("#new-password");
    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", function () {
            var isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            this.innerHTML = isPassword
                ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
                : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        });
    }

    if (passwordInput) {
        passwordInput.addEventListener("input", function () {
            var pwd = this.value;
            var strengthEl = document.getElementById("password-strength");
            var fillEl = document.getElementById("strength-fill");
            var textEl = document.getElementById("strength-text");
            if (!pwd) { strengthEl.style.display = "none"; return; }
            strengthEl.style.display = "block";
            var strength = 0;
            if (pwd.length >= 8) strength++;
            if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
            if (/\d/.test(pwd)) strength++;
            if (/[^a-zA-Z0-9]/.test(pwd)) strength++;
            fillEl.className = "strength-fill";
            if (strength <= 1) { fillEl.classList.add("weak"); textEl.textContent = "Débil"; }
            else if (strength <= 2) { fillEl.classList.add("medium"); textEl.textContent = "Media"; }
            else { fillEl.classList.add("strong"); textEl.textContent = "Fuerte"; }
        });
    }

    modal.querySelector(".modal-close").addEventListener("click", function () { modal.remove(); });
    modal.querySelector("#btn-cancel").addEventListener("click", function () { modal.remove(); });
    modal.addEventListener("click", function (e) { if (e.target === modal) modal.remove(); });

    modal.querySelector("#create-user-form").addEventListener("submit", async function (e) {
        e.preventDefault();
        var formData = {
            username:   document.getElementById("new-username").value.trim(),
            email:      document.getElementById("new-email").value.trim(),
            first_name: document.getElementById("new-first-name").value.trim(),
            last_name:  document.getElementById("new-last-name").value.trim(),
            password:   document.getElementById("new-password").value,
        };
        var roleSelect = document.getElementById("new-role");
        if (roleSelect) formData.role = roleSelect.value;
        await createUser(formData);
        modal.remove();
    });
}

async function showUserDetails(userId) {
    try {
        var [attrsRes, usersRes] = await Promise.all([
            apiFetch(`${API_USERS}/${userId}/attributes`),
            apiFetch(API_USERS),
        ]);

        if (attrsRes?.status === 403) {
            showToast("No tienes permisos para ver atributos", "error");
            return;
        }

        var role       = "role_user";
        var attributes = [];
        if (attrsRes?.ok) {
            var data   = await attrsRes.json();
            role       = data.role       || "role_user";
            attributes = data.attributes || [];
        }

        var user = null;
        if (usersRes?.ok) {
            var allUsers = await usersRes.json();
            for (var i = 0; i < allUsers.length; i++) {
                if (allUsers[i].id === userId) {
                    user = allUsers[i];
                    break;
                }
            }
        }

        if (!user) {
            showToast("Usuario no encontrado", "error");
            return;
        }

        user.role = user.role || role;
        showDetailsModal(user, attributes);
    } catch (error) {
        console.error("Error loading user details:", error);
        showToast("Error al cargar detalles del usuario", "error");
    }
}

function showDetailsModal(user, attributes) {
    var isAdminOrRoot = SeqSession.isAdmin();
    var roleLabel = user.role === "role_root" ? "Root" : user.role === "role_admin" ? "Administrador" : "Usuario";
    var roleBadgeClass = user.role === "role_root" ? "detail-badge detail-badge--root" : user.role === "role_admin" ? "detail-badge detail-badge--admin" : "detail-badge detail-badge--user";

    var attrHtml = buildAttributeSection(attributes, isAdminOrRoot);

    var modal = document.createElement("div");
    modal.className = "modal-overlay";
    modal.innerHTML =
        '<div class="modal modal-details" id="modal-user-details">' +
        '<div class="modal-header"><h2>Detalles del Usuario</h2><button class="modal-close">&times;</button></div>' +
        '<div class="detail-profile">' +
        '<div class="detail-avatar-wrapper"><div class="detail-avatar">' + getInitials(user.first_name, user.last_name) + '</div><div class="status-indicator"></div></div>' +
        '<div class="detail-info">' +
        '<div class="detail-name">' + user.first_name + " " + user.last_name + '</div>' +
        '<div class="detail-username">@' + user.username + '</div>' +
        '<span class="' + roleBadgeClass + '">' + roleLabel + '</span>' +
        '</div></div>' +
        '<div class="detail-grid">' +
        '<div class="detail-item"><span class="detail-label">Nombre</span><span class="detail-value">' + user.first_name + " " + user.last_name + '</span></div>' +
        '<div class="detail-item"><span class="detail-label">Correo</span><span class="detail-value">' + user.email + '</span></div>' +
        '<div class="detail-item"><span class="detail-label">Rol</span><span class="detail-value">' + roleLabel + '</span></div>' +
        '<div class="detail-item"><span class="detail-label">Creado</span><span class="detail-value">' + formatDate(user.created_at) + '</span></div>' +
        '</div>' + attrHtml + '</div>';

    document.body.appendChild(modal);

    modal.querySelector(".modal-close").addEventListener("click", function () { modal.remove(); });
    modal.addEventListener("click", function (e) { if (e.target === modal) modal.remove(); });

    if (isAdminOrRoot) {
        document.getElementById("btn-add-attr")?.addEventListener("click", function () {
            toggleAttributeForm(user.id, attributes, modal);
        });

        modal.querySelectorAll(".attr-remove").forEach(function (btn) {
            btn.addEventListener("click", async function () {
                await removeAttribute(user.id, this.getAttribute("data-attr"), modal);
            });
        });
    }
}

function toggleAttributeForm(userId, currentAttrs, modal) {
    var container = document.getElementById("attr-form-container");
    if (!container) return;
    if (container.innerHTML.trim() !== "") { container.innerHTML = ""; return; }

    var selectHtml = '<div class="attr-form"><label class="attr-form__label">Selecciona atributos:</label><div class="attr-form__groups">';
    for (var g = 0; g < ALL_ATTRIBUTES.length; g++) {
        var grp = ALL_ATTRIBUTES[g];
        selectHtml += '<div class="attr-form__group"><span class="attr-form__module">' + grp.module + '</span>';
        for (var a = 0; a < grp.attrs.length; a++) {
            var attr = grp.attrs[a];
            var checked = currentAttrs.indexOf(attr) !== -1 ? " checked" : "";
            selectHtml += '<label class="attr-form__opt"><input type="checkbox" class="attr-cb" value="' + attr + '"' + checked + ' />' + attr + '</label>';
        }
        selectHtml += "</div>";
    }
    selectHtml += '</div><div class="attr-form__actions"><button class="btn btn--ghost btn--sm" id="btn-cancel-attr">Cancelar</button><button class="btn btn--primary btn--sm" id="btn-save-attr">Guardar</button></div></div>';

    container.innerHTML = selectHtml;

    document.getElementById("btn-cancel-attr").addEventListener("click", function () { container.innerHTML = ""; });
    document.getElementById("btn-save-attr").addEventListener("click", async function () {
        var cbs = container.querySelectorAll(".attr-cb:checked");
        var selected = Array.prototype.map.call(cbs, function (cb) { return cb.value; });
        var toAdd = selected.filter(function (a) { return currentAttrs.indexOf(a) === -1; });
        if (toAdd.length > 0) await addAttributes(userId, toAdd, modal);
        else container.innerHTML = "";
    });
}

async function addAttributes(userId, newAttrs, modal) {
    var res = await apiFetch(`${API_USERS}/${userId}/attributes`, { method: "PUT", body: JSON.stringify({ attributes: newAttrs }) });
    if (!res?.ok) {
        var err = await res.json().catch(() => ({}));
        showToast(err.error_description || "Error al añadir atributos", "error");
        return;
    }
    var data = await res.json();
    refreshAttributeSection(data.attributes || [], modal, userId);
    showToast("Atributos añadidos correctamente", "success");
}

async function removeAttribute(userId, attr, modal) {
    var res = await apiFetch(`${API_USERS}/${userId}/attributes`, { method: "DELETE", body: JSON.stringify({ attributes: [attr] }) });
    if (!res?.ok) {
        var err = await res.json().catch(() => ({}));
        showToast(err.error_description || "Error al eliminar atributo", "error");
        return;
    }
    var data = await res.json();
    refreshAttributeSection(data.attributes || [], modal, userId);
    showToast("Atributo eliminado", "success");
}

function refreshAttributeSection(attributes, modal, userId) {
    var isAdminOrRoot = SeqSession.isAdmin();
    var newHtml = buildAttributeSection(attributes, isAdminOrRoot);
    var attrSection = document.getElementById("attr-section");
    if (attrSection) {
        var tmp = document.createElement("div");
        tmp.innerHTML = newHtml;
        attrSection.innerHTML = tmp.firstElementChild.innerHTML;
    }

    modal.querySelectorAll(".attr-remove").forEach(function (btn) {
        btn.addEventListener("click", async function () {
            await removeAttribute(userId, this.getAttribute("data-attr"), modal);
        });
    });

    document.getElementById("btn-add-attr")?.addEventListener("click", function () {
        toggleAttributeForm(userId, attributes, modal);
    });
}

document.addEventListener("DOMContentLoaded", function () {
    loadUsers();
    document.getElementById("btn-create-user")?.addEventListener("click", showCreateModal);
});