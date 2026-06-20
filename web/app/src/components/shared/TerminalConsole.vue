<template>
  <div class="terminal" ref="terminalEl">
    <div class="terminal-chrome">
      <div class="terminal-dots">
        <span class="dot dot-red"></span>
        <span class="dot dot-yellow"></span>
        <span class="dot dot-green"></span>
      </div>
      <span class="terminal-title">{{ title }}</span>
      <span class="terminal-live">
        <span class="live-dot"></span>
        LIVE
      </span>
    </div>
    <div class="terminal-body" ref="bodyEl">
      <div class="terminal-scanlines"></div>
      <div class="terminal-line">
        <span class="prompt">
          <span class="prompt-user">{{ user }}</span>
          <span class="prompt-sep">:</span>
          <span class="prompt-path">{{ path }}</span>
          <span class="prompt-dollar">$</span>
        </span>
        <span class="command" ref="commandEl"></span>
        <span class="cursor" :class="{ hidden: cursorHidden }">▋</span>
      </div>
      <pre class="output" ref="outputEl"></pre>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const terminalEl = ref(null)
const bodyEl = ref(null)
const commandEl = ref(null)
const outputEl = ref(null)

const title = ref('')
const user = ref('')
const path = ref('')
const cursorHidden = ref(false)

const scenarios = [
  {
    title: 'seq@scanner: ~/nikto-scan',
    user: 'seq@scanner',
    path: '~/nikto-scan',
    command: 'seq nikto scan --target http://example.com --timeout 180',
    output: {
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
  {
    title: 'seq@scanner: ~/nmap-scan',
    user: 'seq@scanner',
    path: '~/nmap-scan',
    command: 'seq nmap scan --target 192.168.1.1 --ports 1-1000 --timeout 300',
    output: {
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
  {
    title: 'seq@scanner: ~/openvas-scan',
    user: 'seq@scanner',
    path: '~/openvas-scan',
    command: 'seq openvas scan --target 10.0.0.50 --config full_fast',
    output: {
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
]

let typingTimer = null
let cursorTimer = null

function highlightJSON(obj) {
  const json = JSON.stringify(obj, null, 2)
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = 'jv'
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? 'jk' : 'js'
      } else if (/true|false/.test(match)) {
        cls = 'jb'
      } else if (/null/.test(match)) {
        cls = 'jn'
      }
      return `<span class="${cls}">${match}</span>`
    }
  )
}

function startAnimation() {
  const sel = scenarios[Math.floor(Math.random() * scenarios.length)]
  title.value = sel.title
  user.value = sel.user
  path.value = sel.path

  const cmd = commandEl.value
  const out = outputEl.value
  if (!cmd || !out) return
  cmd.textContent = ''
  out.innerHTML = ''
  out.style.opacity = '0'

  let i = 0
  function typeChar() {
    if (i < sel.command.length) {
      cmd.textContent += sel.command.charAt(i)
      i++
      typingTimer = setTimeout(typeChar, 40)
    } else {
      setTimeout(showOutput, 500)
    }
  }
  function showOutput() {
    out.innerHTML = highlightJSON(sel.output)
    let opacity = 0
    function fade() {
      opacity += 0.04
      out.style.opacity = Math.min(opacity, 1)
      if (opacity < 1) requestAnimationFrame(fade)
    }
    fade()
  }
  typeChar()
}

onMounted(() => {
  startAnimation()
  cursorTimer = setInterval(() => {
    cursorHidden.value = !cursorHidden.value
  }, 530)
})

onUnmounted(() => {
  if (typingTimer) clearTimeout(typingTimer)
  if (cursorTimer) clearInterval(cursorTimer)
})
</script>

<style scoped>
.terminal {
  background: rgba(10,10,15,0.65);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(212,160,74,0.12);
  border-radius: 12px;
  overflow: hidden;
  width: 100%;
  box-shadow:
    0 0 40px rgba(212,160,74,0.05),
    0 0 80px rgba(212,160,74,0.02),
    0 8px 32px rgba(0,0,0,0.5);
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.1rem;
  line-height: 1.55;
  text-align: left;
}

.terminal-chrome {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.65rem 0.9rem;
  background: rgba(255,255,255,0.015);
  border-bottom: 1px solid rgba(255,255,255,0.05);
}

.terminal-dots {
  display: flex;
  gap: 7px;
}

.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
}
.dot-red    { background: #e06565; }
.dot-yellow { background: #d4a04a; }
.dot-green  { background: #4cb782; }

.terminal-title {
  flex: 1;
  color: rgba(255,255,255,0.22);
  font-size: 0.7rem;
  font-weight: 500;
}

.terminal-live {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.6rem;
  font-weight: 700;
  letter-spacing: 0.15em;
  color: #4cb782;
  text-transform: uppercase;
}

.live-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #4cb782;
  box-shadow: 0 0 8px #4cb782;
  animation: live-pulse 1.4s ease-in-out infinite;
}

@keyframes live-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.35; transform: scale(0.7); }
}

.terminal-body {
  position: relative;
  padding: 0.9rem 1.1rem;
  height: 360px;
  overflow-y: auto;
}

.terminal-scanlines {
  position: absolute;
  inset: 0;
  pointer-events: none;
  opacity: 0.025;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(255,255,255,0.04) 2px,
    rgba(255,255,255,0.04) 3px
  );
  z-index: 1;
}

.terminal-line {
  margin-bottom: 0.5rem;
  word-break: normal;
  overflow-wrap: break-word;
  position: relative;
  z-index: 2;
}

.prompt {
  color: var(--accent, #d4a04a);
  user-select: none;
}
.prompt-user { color: #4cb782; }
.prompt-sep,
.prompt-path { color: var(--accent, #d4a04a); }
.prompt-dollar {
  color: rgba(255,255,255,0.4);
  margin-left: 0.3rem;
}

.command {
  color: #e6e6ec;
}

.cursor {
  color: var(--accent, #d4a04a);
  animation: blink 1s step-end infinite;
  font-weight: 700;
}
.cursor.hidden {
  opacity: 0;
}

@keyframes blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0; }
}

.output {
  position: relative;
  z-index: 2;
  color: #c8c8d0;
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.1rem;
  line-height: 1.5;
  white-space: pre;
  overflow-x: auto;
  transition: opacity 0.3s ease;
}

.output :deep(.jk) { color: #6080e0; }
.output :deep(.js) { color: #4cb782; }
.output :deep(.jv) { color: #d4a04a; }
.output :deep(.jb) { color: #e8bc6a; }
.output :deep(.jn) { color: #d96c6c; }

@media (max-width: 768px) {
  .terminal {
    font-size: 1.1rem;
  }
  .terminal-body {
    padding: 0.7rem 0.85rem;
    height: 260px;
  }
  .output {
    font-size: 1rem;
  }
}
</style>
