<template>
  <div class="config-page">
    <StarBackground />
    <Topbar title="Configuración" />

    <main class="main">
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--lg"></div>
      </div>

      <div v-else class="config-layout">
        <div class="config-nav-column">
          <aside class="config-nav">
            <nav>
              <a v-for="s in navSections" :key="s.id"
                :class="['nav-link', { active: activeSection === s.id }]"
                href="#" @click.prevent="scrollTo(s.id)">
                <span class="nav-icon" v-html="s.icon"></span>
                <span class="nav-label">{{ s.label }}</span>
              </a>
            </nav>
          </aside>
        </div>

        <form class="config-form" @submit.prevent="handleSave">
          <section id="section-general" class="section">
            <div class="section-head"><h2>General</h2><p class="section-desc">Directorios del sistema</p></div>
            <div class="section-body">
              <div class="cfg-grid">
                <div class="form-group"><label>Temp</label><input v-model="store.configFlat['general.directories.tempdir']" type="text" class="inp" /></div>
                <div class="form-group"><label>Logs</label><input v-model="store.configFlat['general.directories.logdir']" type="text" class="inp" /></div>
                <div class="form-group"><label>Resources</label><input v-model="store.configFlat['general.directories.resourcedir']" type="text" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-sequeue" class="section">
            <div class="section-head"><h2>SeQueue</h2><p class="section-desc">Cola de tareas en segundo plano</p></div>
            <div class="section-body">
              <div class="cfg-grid">
                <div class="form-group"><label>Max Workers</label><input v-model.number="store.configFlat['general.sequeue.max_workers']" type="number" min="1" max="32" class="inp" /></div>
                <div class="form-group"><label>Historial TTL (s)</label><input v-model.number="store.configFlat['general.sequeue.history_ttl_seconds']" type="number" min="60" max="86400" class="inp" /></div>
                <div class="form-group"><label>Max items en historial</label><input v-model.number="store.configFlat['general.sequeue.history_max_items']" type="number" min="10" max="1000" class="inp" /></div>
              </div>
            </div>
          </section>

          <section id="section-sentinel" class="section">
            <div class="section-head"><h2>Sentinel</h2><p class="section-desc">Escáner de red, análisis web y vulnerabilidades</p></div>
            <div class="section-body">
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['sentinel.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Directorio de salida (PDFs)</label><input v-model="store.configFlat['sentinel.directories.output']" type="text" class="inp" /></div>
                <div class="form-group"><label>Directorio CSV</label><input v-model="store.configFlat['sentinel.directories.csv']" type="text" class="inp" /></div>
              </div>
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['sentinel.areLocalIpsAllowed']" type="checkbox" class="toggle" /><span>Permitir IPs locales</span></label></div>
              <h3 class="subsection-title">Verificación de accesibilidad del host</h3>
              <div class="cfg-grid">
                <div class="form-group"><label class="toggle-row"><input v-model="store.configFlat['sentinel.hostReachabilityCheck.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
                <div class="form-group"><label>Timeout (s)</label><input v-model.number="store.configFlat['sentinel.hostReachabilityCheck.timeout']" type="number" step="0.5" min="0.5" class="inp" /></div>
                <div class="form-group"><label>Puerto</label><input v-model.number="store.configFlat['sentinel.hostReachabilityCheck.port']" type="number" min="1" max="65535" class="inp" /></div>
              </div>
            </div>
            <div class="scanner-grid">
              <ScannerCard name="Nmap" icon="scan" :flat="store.configFlat" prefix="sentinel.nmap" />
              <ScannerCard name="Nikto" icon="web" :flat="store.configFlat" prefix="sentinel.nikto" />
              <ScannerCard name="OpenVAS" icon="vuln" :flat="store.configFlat" prefix="sentinel.openvas" />
            </div>
            <div class="section-body openvas-tool-configs">
              <h3 class="subsection-title">OpenVAS — Configuraciones de escaneo</h3>
              <div class="cfg-grid">
                <div class="form-group"><label>Full Deep</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_deep']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>Full Fast</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_fast']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>Full Ultimate</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_ultimate']" type="text" class="inp mono" /></div>
              </div>
              <h3 class="subsection-title">OpenVAS — Listas de puertos</h3>
              <div class="cfg-grid">
                <div class="form-group"><label>TCP All</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_all']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>TCP All + UDP Top 100</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_all_udp_top100']" type="text" class="inp mono" /></div>
                <div class="form-group"><label>TCP + UDP All</label><input v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_udp_all']" type="text" class="inp mono" /></div>
              </div>
            </div>
          </section>

          <section id="section-aegis" class="section">
            <div class="section-head"><h2>Aegis</h2><p class="section-desc">Generación de píldoras de concienciación con IA</p></div>
            <div class="section-body">
              <div class="cfg-row"><label class="toggle-row"><input v-model="store.configFlat['aegis.enabled']" type="checkbox" class="toggle" /><span>Habilitado</span></label></div>
              <div class="cfg-grid">
                <div class="form-group"><label>Directorio de salida</label><input v-model="store.configFlat['aegis.directories.output']" type="text" class="inp" /></div>
                <div class="form-group"><label>Stack de documentos</label><input v-model="store.configFlat['aegis.directories.stack']" type="text" class="inp" /></div>
              </div>
              <h3 class="subsection-title">Prompt del sistema</h3>
              <textarea v-model="store.configFlat['aegis.prompts.system']" rows="10" class="txta"></textarea>
              <h3 class="subsection-title">Plantilla de usuario</h3>
              <textarea v-model="store.configFlat['aegis.prompts.userTemplate']" rows="8" class="txta"></textarea>
              <h3 class="subsection-title">Marcas monitoreadas</h3>
              <p class="field-hint">Array JSON. Cada entrada requiere <code>label</code>, <code>circl_vendor</code>, <code>circl_product</code> y <code>aliases</code>.</p>
              <textarea v-model="brandsText" rows="10" class="txta mono" @blur="syncBrands"></textarea>
            </div>
          </section>

          <div class="form-actions">
            <button type="button" class="btn btn--secondary" @click="store.resetForm()">Restablecer</button>
            <button type="submit" class="btn btn--primary" :disabled="store.saving">{{ store.saving ? 'Guardando…' : 'Guardar Configuración' }}</button>
          </div>
        </form>
      </div>
    </main>

    <AppToast />
  </div>
</template>

<script setup>
import { ref, watch, onMounted, onUnmounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useConfigStore } from '@/stores/configStore'
import ScannerCard from '@/components/config/ScannerCard.vue'

const store = useConfigStore()

const navSections = [
  { id: 'general',  label: 'General',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
  { id: 'sequeue',  label: 'SeQueue',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="14" y2="13"/></svg>' },
  { id: 'sentinel', label: 'Sentinel', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' },
  { id: 'aegis',    label: 'Aegis',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' },
]

const activeSection = ref('general')
let observer = null
function scrollTo(sectionId) { const el = document.getElementById(`section-${sectionId}`); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }) }

onMounted(() => {
  store.loadConfig()
  observer = new IntersectionObserver((entries) => { for (const e of entries) { if (e.isIntersecting) activeSection.value = e.target.id.replace('section-', '') } }, { rootMargin: '-80px 0px -60% 0px' })
  requestAnimationFrame(() => { for (const s of navSections) { const el = document.getElementById(`section-${s.id}`); if (el) observer.observe(el) } })
})
onUnmounted(() => { if (observer) observer.disconnect() })

const brandsText = ref('')
watch(() => store.configFlat['aegis.brands'], (val) => { brandsText.value = JSON.stringify(val ?? [], null, 2) }, { immediate: true })
function syncBrands() { try { const p = JSON.parse(brandsText.value); if (Array.isArray(p)) store.configFlat['aegis.brands'] = p } catch {} }
function handleSave() { store.saveConfig() }
</script>

<style scoped>
.config-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1050px; margin: 0 auto; padding: 1.75rem 1.1rem 4rem; position: relative; z-index: 1; }
.config-layout { display: flex; gap: 1.25rem; align-items: flex-start; }
.config-nav-column { width: 160px; flex-shrink: 0; align-self: stretch; }
.config-nav { position: sticky; top: calc(var(--topbar-h) + 1.75rem); }
.config-nav nav { display: flex; flex-direction: column; gap: 0.2rem; }
.nav-link { display: flex; align-items: center; gap: 0.45rem; padding: 0.45rem 0.6rem; border-radius: 7px; color: var(--text-muted); font-size: 0.78rem; font-weight: 500; text-decoration: none; transition: all var(--transition); }
.nav-link:hover { background: var(--surface-2); color: var(--text-dim); }
.nav-link.active { background: var(--accent-dim); color: var(--accent-bright); font-weight: 600; }
.nav-icon { width: 16px; height: 16px; flex-shrink: 0; display: flex; align-items: center; }
.nav-icon svg { width: 100%; height: 100%; }
.nav-label { white-space: nowrap; }
.config-form { flex: 1; min-width: 0; }
.section { margin-bottom: 2rem; }
.section-head { margin-bottom: 0.85rem; padding-bottom: 0.55rem; border-bottom: 1px solid var(--border); }
.section-head h2 { font-size: 1.1rem; font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); }
.section-desc { font-size: 0.78rem; color: var(--text-muted); margin: 0.15rem 0 0; }
.section-body { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.25rem; display: flex; flex-direction: column; gap: 0.85rem; }
.subsection-title { font-size: 0.8rem; font-weight: 600; color: var(--text-dim); margin: 0.2rem 0 0.3rem; }
.cfg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.85rem; }
.cfg-row { display: flex; align-items: center; }
.scanner-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 0.85rem; margin-top: 0.85rem; }
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: 0.72rem; font-weight: 600; color: var(--text-dim); }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: 0.82rem; outline: none; transition: border-color 0.2s; }
.inp:focus { border-color: var(--accent); }
.txta { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.5rem 0.6rem; color: var(--text); font-size: 0.78rem; outline: none; resize: vertical; width: 100%; min-height: 70px; box-sizing: border-box; transition: border-color 0.2s; }
.txta:focus { border-color: var(--accent); }
.mono { font-family: var(--font-mono); }
.toggle-row { display: flex; align-items: center; gap: 0.4rem; cursor: pointer; font-size: 0.85rem; font-weight: 500; color: var(--text); }
.toggle { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.field-hint { font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; }
.field-hint code { font-family: var(--font-mono); font-size: 0.68rem; background: var(--surface-2); padding: 1px 4px; border-radius: 3px; color: var(--text-dim); }
.openvas-tool-configs { margin-top: 0.85rem; }
.form-actions { display: flex; gap: 0.6rem; justify-content: flex-end; position: sticky; bottom: 0.85rem; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 0.85rem 1.1rem; z-index: 10; }
.loading-block { padding: 5rem 0; display: flex; justify-content: center; width: 100%; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 380px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
@media (max-width: 800px) { .config-layout { flex-direction: column; } .config-nav-column { width: 100%; } .config-nav { position: static; } .config-nav nav { flex-direction: row; flex-wrap: wrap; } .nav-link { flex: 1; justify-content: center; min-width: 80px; } }
</style>
