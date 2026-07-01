<template>
  <section
    class="signal"
    :style="{ '--sig-active': activeColor }"
    aria-label="Flujo de operaciones de la plataforma en vivo"
  >
    <!-- ── Header: wordmark + live oscilloscope ── -->
    <header class="signal-head">
      <div class="signal-mark">
        <span class="mark-glyph" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
            <path d="M2 12h3l2.5-7 4 15 3-11 2 5h5.5" />
          </svg>
        </span>
        <div class="mark-copy">
          <h2 class="mark-title">Signal</h2>
          <span class="mark-sub">Flujo de operaciones</span>
        </div>
      </div>

      <div class="signal-scope" aria-hidden="true">
        <div class="scope-wave">
          <svg width="240" height="30" viewBox="0 0 240 30" preserveAspectRatio="none">
            <polyline :points="wavePoints" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" stroke-linecap="round" />
          </svg>
        </div>
        <span class="signal-live"><i></i>En vivo</span>
      </div>
    </header>

    <!-- ── Legend: the four instruments ── -->
    <div class="signal-legend" aria-hidden="true">
      <span v-for="(m, key) in modules" :key="key" class="leg" :style="{ '--evt': m.color }">
        <i class="leg-dot"></i>{{ m.label }}
      </span>
    </div>

    <!-- ── Stream: the heartbeat spine ── -->
    <div class="signal-stream">
      <span class="signal-rail" aria-hidden="true"></span>
      <span class="signal-pulse" aria-hidden="true"></span>
      <TransitionGroup name="sig" tag="div" class="signal-events">
        <article
          v-for="e in events"
          :key="e.id"
          class="event"
          :style="{ '--evt': e.color }"
        >
          <span class="event-node" aria-hidden="true"></span>
          <div class="event-main">
            <div class="event-top">
              <span class="event-chip">{{ e.label }}</span>
              <span class="event-op">{{ e.op }}</span>
              <time class="event-time">{{ e.time }}</time>
            </div>
            <div class="event-detail">
              <span class="event-target">{{ e.target }}</span>
              <span class="event-sep">·</span>
              <span class="event-metric">{{ e.metric }}</span>
              <span v-if="e.flag" class="event-flag" :class="`event-flag--${e.flag}`">{{ e.flagLabel }}</span>
            </div>
          </div>
        </article>
      </TransitionGroup>
    </div>

    <!-- ── Footer: the platform's running count ── -->
    <footer class="signal-foot">
      <span class="foot-metric">
        <b>{{ processedLabel }}</b> eventos procesados
      </span>
      <span class="foot-metric foot-metric--right">
        latencia <b>{{ latency }}ms</b>
      </span>
    </footer>
  </section>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'

/* The four instruments of the platform — color IS the identity. */
const modules = {
  sentinel: { label: 'Sentinel', color: '#4cb782' },
  aegis:    { label: 'Aegis',    color: '#6080e0' },
  iris:     { label: 'Iris',     color: '#e07a5f' },
  acheron:  { label: 'Acheron',  color: '#a07ac0' },
}

/* Interleaved so every module keeps reporting into the same signal. */
const pool = [
  { m: 'sentinel', op: 'nmap · escaneo',       target: '192.168.1.1',      metric: '4 puertos abiertos' },
  { m: 'iris',     op: 'cabecera analizada',   target: 'no-reply@banco.co', metric: 'SPF pass · DKIM fail', flag: 'warn', flagLabel: 'Sospechoso' },
  { m: 'acheron',  op: 'bóveda sellada',       target: 'AES-256-GCM',      metric: '128 credenciales' },
  { m: 'aegis',    op: 'briefing generado',    target: 'edición semanal',  metric: '6 amenazas' },
  { m: 'sentinel', op: 'openvas · full_fast',  target: '10.0.0.50',        metric: 'admin: default password', flag: 'crit', flagLabel: 'Crítico' },
  { m: 'iris',     op: 'ruta SMTP trazada',    target: '5 saltos',         metric: 'origen verificado' },
  { m: 'acheron',  op: 'objeto cifrado',       target: 'tarjeta · TOTP',   metric: 'zero-knowledge' },
  { m: 'aegis',    op: 'feeds sincronizados',  target: 'CVE · CISA · NVD', metric: '128 ítems' },
  { m: 'sentinel', op: 'nikto · web scan',     target: 'example.com',      metric: '12 hallazgos' },
  { m: 'iris',     op: 'veredicto phishing',   target: 'score 62 / 100',   metric: 'requiere revisión', flag: 'warn', flagLabel: 'Revisar' },
  { m: 'acheron',  op: 'clave derivada',       target: 'Argon2id',         metric: 'en el navegador' },
  { m: 'aegis',    op: 'export entregado',     target: 'markdown + json',  metric: 'listo' },
]

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

const MAX = 5
let uid = 0
let cursor = 0

function fmtTime(d) {
  return d.toLocaleTimeString('es-ES', { hour12: false })
}

function makeEvent(secondsAgo = 0) {
  const p = pool[cursor % pool.length]
  cursor++
  const mod = modules[p.m]
  return {
    id: uid++,
    label: mod.label,
    color: mod.color,
    op: p.op,
    target: p.target,
    metric: p.metric,
    flag: p.flag || null,
    flagLabel: p.flagLabel || '',
    time: fmtTime(new Date(Date.now() - secondsAgo * 1000)),
  }
}

/* Seed newest-first with staggered past timestamps. */
const seed = []
for (let i = 0; i < MAX; i++) seed.push(makeEvent(3 + i * 8))
const events = ref(seed)

const activeColor = computed(() => events.value[0]?.color || 'var(--accent)')

/* Running platform counters — a nod to real "cómputo". */
const processed = ref(1247)
const latency = ref(42)
const processedLabel = computed(() => processed.value.toLocaleString('es-ES'))

let feedTimer = null

function pushEvent() {
  events.value = [makeEvent(0), ...events.value].slice(0, MAX)
  processed.value += 1 + Math.floor(Math.random() * 4)
  latency.value = 28 + Math.floor(Math.random() * 34)
}

/* Header oscilloscope — two identical tiles so the loop is seamless. */
const TILE = [
  [0, 15], [8, 15], [16, 15], [20, 8], [24, 15], [34, 15], [42, 15],
  [46, 20], [52, 3], [58, 27], [64, 15], [74, 15], [84, 15],
  [90, 12], [96, 15], [110, 15], [120, 15],
]
const wavePoints = [...TILE, ...TILE.map(([x, y]) => [x + 120, y])]
  .map((p) => p.join(','))
  .join(' ')

onMounted(() => {
  if (!reduceMotion) feedTimer = setInterval(pushEvent, 2600)
})
onUnmounted(() => {
  if (feedTimer) clearInterval(feedTimer)
})
</script>

<style scoped>
.signal {
  --evt: var(--accent);
  display: flex;
  flex-direction: column;
  background: rgba(10, 10, 15, 0.62);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(212, 160, 74, 0.12);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 0 40px rgba(212, 160, 74, 0.04), 0 8px 32px rgba(0, 0, 0, 0.5);
  text-align: left;
}

/* ════════ Header ════════ */
.signal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.8rem 1rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}
.signal-mark { display: flex; align-items: center; gap: 0.65rem; min-width: 0; }
.mark-glyph {
  width: 30px; height: 30px; flex-shrink: 0;
  display: grid; place-items: center;
  color: var(--sig-active, var(--accent));
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border-med);
  transition: color 0.6s ease;
}
.mark-glyph svg { width: 18px; height: 18px; }
.mark-copy { display: flex; flex-direction: column; line-height: 1.1; }
.mark-title {
  font-family: var(--font-display);
  font-size: 1.05rem; font-weight: 700; letter-spacing: 0.08em;
  color: var(--text); text-transform: uppercase;
}
.mark-sub {
  font-family: var(--font-mono);
  font-size: 0.6rem; letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--text-muted);
}

.signal-scope { display: flex; align-items: center; gap: 0.7rem; }
.scope-wave {
  width: 118px; height: 30px; overflow: hidden;
  color: var(--sig-active, var(--accent));
  transition: color 0.6s ease;
  -webkit-mask-image: linear-gradient(90deg, transparent, #000 22%, #000 78%, transparent);
  mask-image: linear-gradient(90deg, transparent, #000 22%, #000 78%, transparent);
}
.scope-wave svg { display: block; animation: scope-scroll 2.6s linear infinite; }
@keyframes scope-scroll { to { transform: translateX(-120px); } }
.scope-wave polyline { filter: drop-shadow(0 0 4px currentColor); opacity: 0.85; }

.signal-live {
  display: inline-flex; align-items: center; gap: 0.35rem;
  font-family: var(--font-mono);
  font-size: 0.58rem; font-weight: 500; letter-spacing: 0.14em;
  text-transform: uppercase; color: var(--success); white-space: nowrap;
}
.signal-live i {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--success); box-shadow: 0 0 7px var(--success);
  animation: sig-beat 1.5s ease-in-out infinite;
}

/* ════════ Legend ════════ */
.signal-legend {
  display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid var(--border);
  background: rgba(255, 255, 255, 0.012);
}
.leg {
  display: inline-flex; align-items: center; gap: 0.4rem;
  font-family: var(--font-mono);
  font-size: 0.62rem; letter-spacing: 0.04em; color: var(--text-muted);
}
.leg-dot {
  width: 7px; height: 7px; border-radius: 2px;
  background: var(--evt); box-shadow: 0 0 6px color-mix(in srgb, var(--evt) 55%, transparent);
}

/* ════════ Stream / heartbeat spine ════════ */
.signal-stream {
  position: relative;
  height: 250px;
  overflow: hidden;
  padding: 0.55rem 1rem 0.4rem;
}
.signal-rail {
  position: absolute; top: 0.55rem; bottom: 0.4rem; left: calc(1rem + 4px);
  width: 1px;
  background: linear-gradient(180deg, transparent, var(--border-med) 12%, var(--border-med) 88%, transparent);
}
.signal-pulse {
  position: absolute; left: calc(1rem + 1px); top: 0;
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--sig-active, var(--accent));
  box-shadow: 0 0 10px var(--sig-active, var(--accent));
  opacity: 0.9;
  animation: rail-drop 2.6s cubic-bezier(0.5, 0, 0.5, 1) infinite;
}
@keyframes rail-drop {
  0% { transform: translateY(6px); opacity: 0; }
  12% { opacity: 0.95; }
  85% { opacity: 0.95; }
  100% { transform: translateY(232px); opacity: 0; }
}

.signal-events { position: relative; }
.event {
  position: relative;
  padding: 0.34rem 0 0.34rem 1.6rem;
  min-height: 46px;
}
.event-node {
  position: absolute; left: 0; top: 0.62rem;
  width: 9px; height: 9px; border-radius: 50%;
  background: var(--evt);
  border: 2px solid var(--bg);
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--evt) 50%, transparent);
}
.event:first-child .event-node {
  animation: node-beat 2.6s ease-out infinite;
}
@keyframes node-beat {
  0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--evt) 60%, transparent); }
  60% { box-shadow: 0 0 0 7px transparent; }
  100% { box-shadow: 0 0 0 0 transparent; }
}

.event-top {
  display: flex; align-items: baseline; gap: 0.5rem;
  margin-bottom: 0.15rem;
}
.event-chip {
  font-family: var(--font-display);
  font-size: 0.66rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--evt);
  padding: 0.05rem 0.4rem; border-radius: 4px;
  background: color-mix(in srgb, var(--evt) 12%, transparent);
  flex-shrink: 0;
}
.event-op {
  font-family: var(--font-body);
  font-size: 0.82rem; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.event-time {
  margin-left: auto; flex-shrink: 0;
  font-family: var(--font-mono);
  font-size: 0.66rem; color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}
.event-detail {
  display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap;
  font-family: var(--font-mono);
  font-size: 0.72rem; color: var(--text-dim);
}
.event-target { color: var(--text-dim); }
.event-sep { color: var(--text-muted); }
.event-metric { color: color-mix(in srgb, var(--evt) 78%, var(--text)); }
.event-flag {
  font-family: var(--font-mono);
  font-size: 0.56rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
  padding: 0.05rem 0.35rem; border-radius: 3px;
}
.event-flag--crit { color: var(--danger); background: var(--danger-dim); border: 1px solid rgba(217, 108, 108, 0.25); }
.event-flag--warn { color: var(--warn); background: var(--warn-dim); border: 1px solid rgba(212, 160, 74, 0.22); }

/* Enter/leave choreography for the feed */
.sig-enter-active, .sig-move { transition: transform 0.5s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.5s ease; }
.sig-enter-from { opacity: 0; transform: translateY(-14px); }
.sig-leave-active { position: absolute; left: 0; right: 0; transition: opacity 0.4s ease; }
.sig-leave-to { opacity: 0; }

/* ════════ Footer ════════ */
.signal-foot {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.55rem 1rem;
  border-top: 1px solid rgba(255, 255, 255, 0.05);
  font-family: var(--font-mono);
  font-size: 0.62rem; letter-spacing: 0.04em; color: var(--text-muted);
}
.foot-metric b { color: var(--text-dim); font-weight: 600; font-variant-numeric: tabular-nums; }
.foot-metric--right { opacity: 0.85; }

@keyframes sig-beat {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.7); }
}

@media (max-width: 768px) {
  .signal-stream { height: 220px; }
  .signal-scope { display: none; }
  .event-op { font-size: 0.78rem; }
}

@media (prefers-reduced-motion: reduce) {
  .scope-wave svg, .signal-pulse, .signal-live i,
  .event:first-child .event-node { animation: none !important; }
  .signal-pulse { display: none; }
  .sig-enter-active, .sig-move, .sig-leave-active { transition: none !important; }
}
</style>
