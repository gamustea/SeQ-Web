<template>
  <div class="stats-row">
    <div class="stat-card green">
      <div class="stat-value">{{ total }}</div>
      <div class="stat-label">Escaneos totales</div>
      <div class="stat-sub">todos los tipos</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-value">{{ nmap }}</div>
      <div class="stat-label">Nmap</div>
      <div class="stat-sub">escaneos de red</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-value">{{ nikto }}</div>
      <div class="stat-label">Nikto</div>
      <div class="stat-sub">escaneos web</div>
    </div>
    <div class="stat-card red">
      <div class="stat-value">{{ openvas }}</div>
      <div class="stat-label">OpenVAS</div>
      <div class="stat-sub">análisis de vulns</div>
    </div>
  </div>
</template>

<script setup>
/**
 * StatsRow — Cuatro tarjetas de estadísticas de escaneo.
 *
 * @vue-prop {number} total - Total de escaneos
 * @vue-prop {number} nmap - Escaneos Nmap
 * @vue-prop {number} nikto - Escaneos Nikto
 * @vue-prop {number} openvas - Escaneos OpenVAS
 */
defineProps({
  total:   { type: Number, default: 0 },
  nmap:    { type: Number, default: 0 },
  nikto:   { type: Number, default: 0 },
  openvas: { type: Number, default: 0 },
})
</script>

<style scoped>
.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.5rem; transition: border-color 0.2s, transform 0.2s; }
.stat-card:hover { transform: translateY(-1px); }
.stat-value { font-size: 1.8rem; font-weight: 800; font-family: var(--font-mono); line-height: 1.2; }
.stat-label { font-size: 0.85rem; font-weight: 600; color: var(--text-dim); margin-top: 0.25rem; }
.stat-sub { font-size: 0.7rem; color: var(--text-muted); margin-top: 0.15rem; }
.green { border-color: rgba(52,211,153,0.25); }
.green .stat-value { color: var(--success); }
.blue { border-color: rgba(96,165,250,0.25); }
.blue .stat-value { color: var(--info); }
.amber { border-color: rgba(251,191,36,0.25); }
.amber .stat-value { color: var(--warn); }
.red { border-color: rgba(248,113,113,0.25); }
.red .stat-value { color: var(--danger); }
</style>
