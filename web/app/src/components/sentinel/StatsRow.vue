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
defineProps({
  total:   { type: Number, default: 0 },
  nmap:    { type: Number, default: 0 },
  nikto:   { type: Number, default: 0 },
  openvas: { type: Number, default: 0 },
})
</script>

<style scoped>
.stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.85rem; margin-bottom: 1.25rem; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.25rem; transition: border-color 0.2s, transform 0.2s; }
.stat-card:hover { border-color: var(--border-med); }
.stat-value { font-size: 1.6rem; font-weight: 800; font-family: var(--font-mono); line-height: 1.2; }
.stat-label { font-size: 0.82rem; font-weight: 600; color: var(--text-dim); margin-top: 0.2rem; }
.stat-sub { font-size: 0.68rem; color: var(--text-muted); margin-top: 0.1rem; }
.green .stat-value { color: var(--success); }
.blue .stat-value { color: var(--info); }
.amber .stat-value { color: var(--warn); }
.red .stat-value { color: var(--danger); }
</style>
