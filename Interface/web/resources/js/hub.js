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

    function ga() {
        try {
            return (
                JSON.parse(sessionStorage.getItem("seq_session")).attributes ||
                []
            );
        } catch (e) {
            return [];
        }
    }

    function cp() {
        var a = ga();
        var isA = a.indexOf("role_admin") > -1;
        var isR = a.indexOf("role_root") > -1;
        if (!isA && !isR) {
            if (mu) mu.style.display = "none";
            if (mc) mc.style.display = "none";
        }
    }
    cp();

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

    function lp() {
        var ss = JSON.parse(sessionStorage.getItem("seq_session"));
        if (!ss || !pe) return;
        fetch("/users/me", {
            headers: { Authorization: "Bearer " + ss.accessToken },
        }).then(function (r) {
            if (r.ok)
                r.json().then(function (d) {
                    pe.textContent = d.first_name + " " + d.last_name;
                });
        });
    }
    lp();
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
        n: {
            t: "seq@scanner: ~/nikto-scan",
            u: "seq@scanner",
            p: "~/nikto-scan",
            c: "seq nikto scan --target http://example.com --timeout 180",
        },
        nm: {
            t: "seq@scanner: ~/nmap-scan",
            u: "seq@scanner",
            p: "~/nmap-scan",
            c: "seq nmap scan --target 192.168.1.1 --ports 1-1000 --timeout 300",
        },
        o: {
            t: "seq@scanner: ~/openvas-scan",
            u: "seq@scanner",
            p: "~/openvas-scan",
            c: "seq openvas scan --target 10.0.0.50 --config full_fast",
        },
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
        to.innerHTML = JSON.stringify({ id: 1, status: "finished" }, null, 2);
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
