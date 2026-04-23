/* =====================================================
   resources/js/hub.js — SeQ Hub
   Guarda de sesión + generación del starfield + terminal demo
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

/* ─── TERMINAL DEMO ─── */
(function () {
  const terminalBody = document.getElementById('terminal-body');
  if (!terminalBody) return;
  
  const typingCommand = document.getElementById('typing-command');
  const terminalOutput = document.getElementById('terminal-output');
  const terminalTitle = document.getElementById('terminal-title');
  const promptUser = document.getElementById('prompt-user');
  const promptPath = document.getElementById('prompt-path');
  
  const templates = {
    nikto: {
      title: 'seq@scanner: ~/nikto-scan',
      user: 'seq@scanner',
      path: '~/nikto-scan',
      command: 'seq nikto scan --target http://example.com --timeout 180',
      response: {
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
      title: 'seq@scanner: ~/nmap-scan',
      user: 'seq@scanner',
      path: '~/nmap-scan',
      command: 'seq nmap scan --target 192.168.1.1 --ports 1-1000 --timeout 300',
      response: {
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
      title: 'seq@scanner: ~/openvas-scan',
      user: 'seq@scanner',
      path: '~/openvas-scan',
      command: 'seq openvas scan --target 10.0.0.50 --config full_fast',
      response: {
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
  
  const templateKeys = Object.keys(templates);
  const randomKey = templateKeys[Math.floor(Math.random() * templateKeys.length)];
  const selectedTemplate = templates[randomKey];
  
  terminalTitle.textContent = selectedTemplate.title;
  promptUser.textContent = selectedTemplate.user;
  promptPath.textContent = selectedTemplate.path;
  
  function syntaxHighlightJson(json) {
    if (typeof json !== 'string') {
      json = JSON.stringify(json, null, 2);
    }
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
      let cls = 'json-number';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          cls = 'json-string';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-boolean';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return '<span class="' + cls + '">' + match + '</span>';
    });
  }
  
  let charIndex = 0;
  const typingSpeed = 50;
  
  function typeCommand() {
    if (charIndex < selectedTemplate.command.length) {
      typingCommand.textContent += selectedTemplate.command.charAt(charIndex);
      charIndex++;
      setTimeout(typeCommand, typingSpeed);
    } else {
      setTimeout(showResponse, 500);
    }
  }
  
  function showResponse() {
    const jsonStr = JSON.stringify(selectedTemplate.response, null, 2);
    const highlightedJson = syntaxHighlightJson(jsonStr);
    terminalOutput.innerHTML = highlightedJson;
    terminalOutput.style.opacity = '0';
    terminalOutput.style.display = 'block';
    
    let opacity = 0;
    const fadeIn = () => {
      opacity += 0.05;
      terminalOutput.style.opacity = opacity;
      if (opacity < 1) {
        requestAnimationFrame(fadeIn);
      }
    };
    fadeIn();
  }
  
  setTimeout(typeCommand, 1000);
})();
