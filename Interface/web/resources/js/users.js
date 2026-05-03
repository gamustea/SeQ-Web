/* =====================================================
resources/js/users.js — Gestión de Usuarios
Lista usuarios del sistema en formato card
===================================================== */

const API_BASE = "";
const API_URL = {
    users: `${API_BASE}/users`,
    signUp: `${API_BASE}/users/sign-up`,
};

/* SESSION GUARD */
(function () {
    const raw = sessionStorage.getItem("seq_session");
    if (!raw) {
        window.location.href = "/pages/login.html";
        return;
    }
    try {
        const s = JSON.parse(raw);
        if (!s.accessToken || Date.now() > s.expiresAt) {
            sessionStorage.removeItem("seq_session");
            window.location.href = "/pages/login.html";
        }
    } catch {
        window.location.href = "/pages/login.html";
    }
})();

function getSessionAttributes() {
    try {
        const s = JSON.parse(sessionStorage.getItem("seq_session"));
        return s.attributes || [];
    } catch {
        return [];
    }
}

function isRoot() {
    return getSessionAttributes().includes("role_root");
}

/* STARFIELD */
(function () {
    const container = document.getElementById("stars");
    if (!container) return;
    for (let i = 0; i < 120; i++) {
        const star = document.createElement("div");
        star.className = "star";
        star.style.left = Math.random() * 100 + "%";
        star.style.top = Math.random() * 100 + "%";
        const size = Math.random() * 2 + 1;
        star.style.width = size + "px";
        star.style.height = size + "px";
        star.style.animationDelay = Math.random() * 4 + "s";
        star.style.animationDuration = Math.random() * 3 + 2 + "s";
        container.appendChild(star);
    }
})();

/* TOAST NOTIFICATIONS */
function showToast(message, type) {
    type = type || "info";
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = "toast toast--" + type + " visible";
    setTimeout(function () {
        toast.classList.remove("visible");
    }, 3000);
}

/* LOAD USERS */
async function loadUsers() {
    const session = JSON.parse(sessionStorage.getItem("seq_session"));
    if (!session) return;

    try {
        const response = await fetch(API_URL.users, {
            headers: {
                Authorization: "Bearer " + session.accessToken,
                "Content-Type": "application/json",
            },
        });

        if (!response.ok) {
            if (response.status === 401) {
                sessionStorage.removeItem("seq_session");
                window.location.href = "/pages/login.html";
                return;
            }
            throw new Error("Error al cargar usuarios");
        }

        const users = await response.json();
        const attrsResponse = await fetch(API_URL.users + "/attributes", {
            headers: {
                Authorization: "Bearer " + session.accessToken,
                "Content-Type": "application/json",
            },
        });

        var userAttrsMap = {};
        if (attrsResponse.ok) {
            var allAttrs = await attrsResponse.json();
            for (var i = 0; i < allAttrs.length; i++) {
                var entry = allAttrs[i];
                userAttrsMap[entry.user_id] = entry.attributes || [];
            }
        }

        for (var j = 0; j < users.length; j++) {
            users[j]._attributes = userAttrsMap[users[j].id] || [];
        }

        renderUsers(users);
        updateCount(users.length);
    } catch (error) {
        console.error("Error loading users:", error);
        showToast("Error al cargar usuarios", "error");
    }
}

/* RENDER USERS */
function renderUsers(users) {
    var grid = document.getElementById("users-grid");
    if (!grid) return;

    if (!users || users.length === 0) {
        grid.innerHTML =
            '<div class="users-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><h3>No hay usuarios registrados</h3><p>Crea el primer usuario</p></div>';
        return;
    }

    var rootHtml = "";
    var adminsHtml = "";
    var basicHtml = "";
    var rootCount = 0;
    var adminCount = 0;
    var basicCount = 0;

    for (var i = 0; i < users.length; i++) {
        var user = users[i];
        var attrs = user._attributes || [];
        var isRoot = attrs.includes("role_root");
        var isAdmin = attrs.includes("role_admin");

        var cardClass = isRoot
            ? "user-card user-card--root"
            : isAdmin
              ? "user-card user-card--admin"
              : "user-card user-card--basic";
        var roleLabel = isRoot ? "Root" : isAdmin ? "Administrador" : "Usuario";

        var cardHtml =
            '<article class="' +
            cardClass +
            '">' +
            '<div class="user-card__header">' +
            '<div class="user-card__avatar">' +
            getInitials(user.first_name, user.last_name) +
            "</div>" +
            '<div class="user-card__info">' +
            '<div class="user-card__username">@' +
            user.username +
            "</div>" +
            '<div class="user-card__id">ID: ' +
            user.id +
            "</div>" +
            "</div>" +
            "</div>" +
            '<div class="user-card__details">' +
            '<div class="user-card__row"><span class="user-card__label">Nombre</span><span class="user-card__value">' +
            user.first_name +
            " " +
            user.last_name +
            "</span></div>" +
            '<div class="user-card__row"><span class="user-card__label">Correo</span><span class="user-card__value user-card__value--email">' +
            user.email +
            "</span></div>" +
            '<div class="user-card__row"><span class="user-card__label">Rol</span><span class="user-card__value">' +
            roleLabel +
            "</span></div>" +
            "</div>" +
            '<div class="user-card__footer">' +
            '<span class="user-card__date">' +
            formatDate(user.created_at) +
            "</span>" +
            '<button class="btn-details" data-user-id="' +
            user.id +
            '">Detalles</button>' +
            "</div>" +
            "</article>";

        if (isRoot) {
            rootCount++;
            rootHtml += cardHtml;
        } else if (isAdmin) {
            adminCount++;
            adminsHtml += cardHtml;
        } else {
            basicHtml += cardHtml;
            basicCount++;
        }
    }

    var sectionsHtml = "";
    if (rootHtml) {
        sectionsHtml +=
            '<section class="user-section"><h2 class="user-section__title">Root (' +
            rootCount +
            ')</h2><div class="user-section__grid">' +
            rootHtml +
            "</div></section>";
    }
    if (adminsHtml) {
        sectionsHtml +=
            '<section class="user-section"><h2 class="user-section__title">Administradores (' +
            adminCount +
            ')</h2><div class="user-section__grid">' +
            adminsHtml +
            "</div></section>";
    }
    if (basicHtml) {
        sectionsHtml +=
            '<section class="user-section"><h2 class="user-section__title">Usuarios (' +
            basicCount +
            ')</h2><div class="user-section__grid">' +
            basicHtml +
            "</div></section>";
    }
    grid.innerHTML = sectionsHtml;

    grid.querySelectorAll(".btn-details").forEach(function (btn) {
        btn.addEventListener("click", function () {
            showUserDetails(parseInt(this.getAttribute("data-user-id")));
        });
    });
}

/* GET INITIALS */
function getInitials(firstName, lastName) {
    var first = firstName ? firstName.charAt(0).toUpperCase() : "";
    var last = lastName ? lastName.charAt(0).toUpperCase() : "";
    return first + last || "??";
}

/* DATE FORMATTER */
function formatDate(dateStr) {
    if (!dateStr) return "-";
    var date = new Date(dateStr);
    return date.toLocaleDateString("es-ES", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

/* UPDATE COUNT */
function updateCount(count) {
    var el = document.getElementById("users-count");
    if (el) {
        el.textContent = count + " usuario" + (count !== 1 ? "s" : "");
    }
}

/* CREATE USER */
async function createUser(userData) {
    var session = JSON.parse(sessionStorage.getItem("seq_session"));
    if (!session) return;

    try {
        var response = await fetch(API_URL.signUp, {
            method: "POST",
            headers: {
                Authorization: "Bearer " + session.accessToken,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(userData),
        });

        if (!response.ok) {
            var error = await response.json();
            if (response.status === 403) {
                showToast("No tienes permisos para crear usuarios", "error");
            } else if (response.status === 409) {
                showToast("El usuario o correo ya existe", "error");
            } else {
                throw new Error(
                    error.error_description || "Error al crear usuario",
                );
            }
            return { success: false };
        }

        showToast("Usuario creado correctamente", "success");
        loadUsers();
        return { success: true };
    } catch (error) {
        console.error("Error creating user:", error);
        showToast("Error al crear usuario", "error");
        return { success: false };
    }
}

/* SHOW CREATE MODAL */
function showCreateModal() {
    var roleField = "";
    if (isRoot()) {
        roleField =
            '<div class="form-group">' +
            '<label for="new-role">Rol</label>' +
            '<select id="new-role" name="role">' +
            '<option value="role_user">Usuario</option>' +
            '<option value="role_admin">Administrador</option>' +
            "</select>" +
            "</div>";
    }

    var modal = document.createElement("div");
    modal.className = "modal-overlay";
    modal.innerHTML =
        '<div class="modal">' +
        '<div class="modal-header">' +
        "<h2>Crear Nuevo Usuario</h2>" +
        '<button class="modal-close">&times;</button>' +
        "</div>" +
        '<form id="create-user-form">' +
        '<div class="form-group"><label for="new-username">Nombre de usuario</label><input type="text" id="new-username" name="username" required /></div>' +
        '<div class="form-group"><label for="new-email">Correo electrónico</label><input type="email" id="new-email" name="email" required /></div>' +
        '<div class="form-group"><label for="new-first-name">Nombre</label><input type="text" id="new-first-name" name="first_name" required /></div>' +
        '<div class="form-group"><label for="new-last-name">Apellidos</label><input type="text" id="new-last-name" name="last_name" required /></div>' +
        '<div class="form-group"><label for="new-password">Contraseña</label><input type="password" id="new-password" name="password" required minlength="8" /></div>' +
        roleField +
        '<div class="form-actions">' +
        '<button type="button" class="btn btn--ghost" id="btn-cancel">Cancelar</button>' +
        '<button type="submit" class="btn btn--primary">Crear Usuario</button>' +
        "</div>" +
        "</form>" +
        "</div>";

    document.body.appendChild(modal);

    modal.querySelector(".modal-close").addEventListener("click", function () {
        modal.remove();
    });

    modal.querySelector("#btn-cancel").addEventListener("click", function () {
        modal.remove();
    });

    modal
        .querySelector("#create-user-form")
        .addEventListener("submit", async function (e) {
            e.preventDefault();
            var formData = {
                username: document.getElementById("new-username").value.trim(),
                email: document.getElementById("new-email").value.trim(),
                first_name: document
                    .getElementById("new-first-name")
                    .value.trim(),
                last_name: document
                    .getElementById("new-last-name")
                    .value.trim(),
                password: document.getElementById("new-password").value,
            };
            var roleSelect = document.getElementById("new-role");
            if (roleSelect) {
                formData.role = roleSelect.value;
            }
            await createUser(formData);
            modal.remove();
        });

    modal.addEventListener("click", function (e) {
        if (e.target === modal) modal.remove();
    });
}

/* SHOW USER DETAILS */
async function showUserDetails(userId) {
    var session = JSON.parse(sessionStorage.getItem("seq_session"));
    if (!session) return;

    try {
        var response = await fetch(
            API_URL.users + "/" + userId + "/attributes",
            {
                headers: {
                    Authorization: "Bearer " + session.accessToken,
                    "Content-Type": "application/json",
                },
            },
        );

        var attributes = [];
        if (response.ok) {
            var data = await response.json();
            attributes = data.attributes || [];
        } else if (response.status === 403) {
            showToast("No tienes permisos para ver atributos", "error");
            return;
        }

        var userResponse = await fetch(API_URL.users, {
            headers: {
                Authorization: "Bearer " + session.accessToken,
                "Content-Type": "application/json",
            },
        });
        var allUsers = await userResponse.json();
        var user = null;
        for (var i = 0; i < allUsers.length; i++) {
            if (allUsers[i].id === userId) {
                user = allUsers[i];
                break;
            }
        }

        if (!user) {
            showToast("Usuario no encontrado", "error");
            return;
        }

        showDetailsModal(user, attributes);
    } catch (error) {
        console.error("Error loading user details:", error);
        showToast("Error al cargar detalles del usuario", "error");
    }
}

/* SHOW DETAILS MODAL */
function showDetailsModal(user, attributes) {
    var attrHtml = "";
    if (attributes.length > 0) {
        attrHtml =
            '<div class="user-attributes"><span class="attr-label">Atributos:</span><div class="attr-tags">';
        for (var i = 0; i < attributes.length; i++) {
            attrHtml += '<span class="attr-tag">' + attributes[i] + "</span>";
        }
        attrHtml += "</div></div>";
    } else {
        attrHtml =
            '<div class="user-attributes"><span class="attr-label">Atributos:</span><span class="no-attrs">Sin atributos</span></div>';
    }

    var modal = document.createElement("div");
    modal.className = "modal-overlay";
    modal.innerHTML =
        '<div class="modal modal-details">' +
        '<div class="modal-header">' +
        "<h2>Detalles del Usuario</h2>" +
        '<button class="modal-close">&times;</button>' +
        "</div>" +
        '<div class="modal-body">' +
        '<div class="detail-section">' +
        '<div class="detail-avatar">' +
        getInitials(user.first_name, user.last_name) +
        "</div>" +
        '<div class="detail-username">@' +
        user.username +
        "</div>" +
        '<div class="detail-id">ID: ' +
        user.id +
        "</div>" +
        "</div>" +
        '<div class="detail-grid">' +
        '<div class="detail-item"><span class="detail-label">Nombre</span><span class="detail-value">' +
        user.first_name +
        " " +
        user.last_name +
        "</span></div>" +
        '<div class="detail-item"><span class="detail-label">Correo</span><span class="detail-value">' +
        user.email +
        "</span></div>" +
        '<div class="detail-item"><span class="detail-label">Creado</span><span class="detail-value">' +
        formatDate(user.created_at) +
        "</span></div>" +
        "</div>" +
        attrHtml +
        "</div>" +
        "</div>";

    document.body.appendChild(modal);

    modal.querySelector(".modal-close").addEventListener("click", function () {
        modal.remove();
    });
    modal.addEventListener("click", function (e) {
        if (e.target === modal) modal.remove();
    });
}

/* INITIALIZATION */
document.addEventListener("DOMContentLoaded", function () {
    loadUsers();

    var btnCreate = document.getElementById("btn-create-user");
    if (btnCreate) {
        btnCreate.addEventListener("click", showCreateModal);
    }
});
