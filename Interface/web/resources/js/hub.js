/* hub.js */
(function () {
    var r = sessionStorage.getItem("seq_session");
    if (!r) {
        window.location.href = "/pages/login.html";
        return;
    }
    try {
        var s = JSON.parse(r);
        if (!s.accessToken || Date.now() > s.expiresAt) {
            sessionStorage.removeItem("seq_session");
            window.location.href = "/pages/login.html";
        }
    } catch (e) {
        window.location.href = "/pages/login.html";
    }
})();

(function () {
    var tb = document.getElementById("sidebar-toggle");
    var sb = document.getElementById("profile-sidebar");
    var lb = document.getElementById("logout-btn");
    var pe = document.getElementById("profile-name");
    var mu = document.getElementById("menu-users");
    var mc = document.getElementById("menu-config");
    if (!tb || !sb) return;

    function getRole() {
        try {
            return JSON.parse(sessionStorage.getItem("seq_session")).role || "role_user";
        } catch (e) {
            return "role_user";
        }
    }

    function applyMenuVisibility() {
        var role = getRole();
        var isPrivileged = role === "role_admin" || role === "role_root";
        if (!isPrivileged) {
            if (mu) mu.style.display = "none";
            if (mc) mc.style.display = "none";
        }
    }
    applyMenuVisibility();

    tb.addEventListener("click", function (e) {
        e.stopPropagation();
        sb.classList.toggle("open");
    });

    document.addEventListener("click", function (e) {
        if (!sb.contains(e.target) && !tb.contains(e.target)) {
            sb.classList.remove("open");
        }
    });

    lb.addEventListener("click", function () {
        var ss = JSON.parse(sessionStorage.getItem("seq_session"));
        if (ss && ss.accessToken) {
            fetch("/oauth/revoke-all", {
                method: "POST",
                headers: { Authorization: "Bearer " + ss.accessToken },
            });
        }
        sessionStorage.removeItem("seq_session");
        window.location.href = "/pages/login.html";
    });

    function loadProfileName() {
        var ss = JSON.parse(sessionStorage.getItem("seq_session"));
        if (!ss || !pe) return;
        fetch("/users/me", {
            headers: { Authorization: "Bearer " + ss.accessToken },
        }).then(function (r) {
            if (r.ok)
                r.json().then(function (d) {
                    pe.textContent = d.first_name + " " + d.last_name;
                    // Actualiza el rol en sesión si el endpoint lo devuelve
                    if (d.role) {
                        try {
                            var s = JSON.parse(sessionStorage.getItem("seq_session"));
                            s.role = d.role;
                            sessionStorage.setItem("seq_session", JSON.stringify(s));
                            applyMenuVisibility();
                        } catch (e) {}
                    }
                });
        });
    }
    loadProfileName();
})();

(function () {
    var c = document.getElementById("stars");
    if (!c) return;
    for (var i = 0; i < 120; i++) {
        var s = document.createElement("div");
        s.className = "star";
        s.style.left = Math.random() * 100 + "%";
        s.style.top = Math.random() * 100 + "%";
        s.style.width = Math.random() * 2 + 1 + "px";
        s.style.height = s.style.width;
        s.style.animationDelay = Math.random() * 4 + "s";
        s.style.animationDuration = Math.random() * 3 + 2 + "s";
        c.appendChild(s);
    }
})();

(function () {
    var b = document.getElementById("terminal-body");
    if (!b) return;
    var tc = document.getElementById("typing-command");
    var to = document.getElementById("terminal-output");
    var tt = document.getElementById("terminal-title");
    var pu = document.getElementById("prompt-user");
    var pp = document.getElementById("prompt-path");

    var tp = {
        nikto: {
            t: "seq@scanner: ~/nikto-scan",
            u: "seq@scanner",
            p: "~/nikto-scan",
            c: "seq nikto scan --target http://example.com --timeout 180",
            r: {
                id: 42,
                target: "http://example.com",
                status: "finished",
                scanType: "nikto",
                startedAt: "2024-01-15T10:30:00Z",
                finishedAt: "2024-01-15T10:45:23Z",
                host: { hostname: "example.com", ip_address: "93.184.216.34" },
                incidents: [
                    { id: 1, osvdb_id: "112264", method: "GET", url: "/server-status", severity: "medium", description: "Server Answers To Server Status" },
                    { id: 2, osvdb_id: "117413", method: "GET", url: "/icons/README", severity: "low", description: "Directory indexing found" },
                    { id: 3, osvdb_id: "3092", method: "GET", url: "/", severity: "info", description: "The anti-clickjacking X-Frame-Options header is not present" },
                    { id: 4, osvdb_id: "895", method: "GET", url: "/", severity: "low", description: "Content-Security-Policy header is not defined" }
                ]
            }
        },
        nmap: {
            t: "seq@scanner: ~/nmap-scan",
            u: "seq@scanner",
            p: "~/nmap-scan",
            c: "seq nmap scan --target 192.168.1.1 --ports 1-1000 --timeout 300",
            r: {
                id: 37,
                target: "192.168.1.1",
                status: "finished",
                scanType: "nmap",
                startedAt: "2024-01-15T09:00:00Z",
                finishedAt: "2024-01-15T09:15:45Z",
                host: { hostname: "gateway.local", ip_address: "192.168.1.1", mac_address: "00:11:22:33:44:55" },
                openPorts: [
                    { port: "22/tcp", product: "OpenSSH", version: "8.2p1", reason: "syn-ack" },
                    { port: "80/tcp", product: "nginx", version: "1.18.0", reason: "syn-ack" },
                    { port: "443/tcp", product: "nginx", version: "1.18.0", reason: "syn-ack" },
                    { port: "3306/tcp", product: "MySQL", version: "8.0.27", reason: "syn-ack" }
                ]
            }
        },
        openvas: {
            t: "seq@scanner: ~/openvas-scan",
            u: "seq@scanner",
            p: "~/openvas-scan",
            c: "seq openvas scan --target 10.0.0.50 --config full_fast",
            r: {
                id: 56,
                target: "10.0.0.50",
                status: "finished",
                scanType: "openvas",
                startedAt: "2024-01-14T14:00:00Z",
                finishedAt: "2024-01-14T16:30:00Z",
                taskId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                reportId: "b2c3d4e5-f6a7-8901-bcde-f23456789012",
                results: [
                    { id: 1, nvt_oid: "1.2.3.4.5.6.7.8.9.0", name: "SSL/TLS: Version 2 and Version 3 Detection", severity: "medium", host: "10.0.0.50", description: "The remote service supports SSLv2 and/or SSLv3." },
                    { id: 2, nvt_oid: "1.2.3.4.5.6.7.8.9.1", name: "HTTP TRACE Method Enabled", severity: "low", host: "10.0.0.50", description: "The TRACE method is enabled on the remote web server." },
                    { id: 3, nvt_oid: "1.2.3.4.5.6.7.8.9.2", name: "PHP Unsupported Version Detected", severity: "high", host: "10.0.0.50", description: "The version of PHP installed on the remote host is no longer supported." },
                    { id: 4, nvt_oid: "1.2.3.4.5.6.7.8.9.3", name: "Default Password: admin", severity: "critical", host: "10.0.0.50", description: "The account 'admin' uses the default password." }
                ]
            }
        }
    };

    var k = Object.keys(tp);
    var sel = tp[k[Math.floor(Math.random() * k.length)]];

    tt.textContent = sel.t;
    pu.textContent = sel.u;
    pp.textContent = sel.p;

    var i = 0;
    function ty() {
        if (i < sel.c.length) {
            tc.textContent += sel.c.charAt(i);
            i++;
            setTimeout(ty, 50);
        } else {
            setTimeout(sh, 500);
        }
    }
    function sh() {
        var jsonStr = JSON.stringify(sel.r, null, 2);
        var highlighted = jsonStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
            var cls = "json-number";
            if (/^"/.test(match)) {
                cls = /:$/.test(match) ? "json-key" : "json-string";
            } else if (/true|false/.test(match)) {
                cls = "json-boolean";
            } else if (/null/.test(match)) {
                cls = "json-null";
            }
            return '<span class="' + cls + '">' + match + "</span>";
        });
        to.innerHTML = highlighted;
        to.style.opacity = "0";
        var o = 0;
        function fd() {
            o += 0.05;
            to.style.opacity = o;
            if (o < 1) requestAnimationFrame(fd);
        }
        fd();
    }
    setTimeout(ty, 1000);
})();