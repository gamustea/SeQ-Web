<template>
  <div class="config-page">
    <Topbar title="Configuración" />

    <main class="main">
      <!-- Loading -->
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--lg"></div>
      </div>

      <div v-else class="config-layout">
        <!-- Sidebar nav -->
        <div class="config-nav-column">
          <aside class="config-nav">
            <nav>
              <a
                v-for="s in navSections"
                :key="s.id"
                :class="['nav-link', { active: activeSection === s.id }]"
                href="#"
                @click.prevent="scrollTo(s.id)"
              >
                <span class="nav-icon" v-html="s.icon"></span>
                <span class="nav-label">{{ s.label }}</span>
              </a>
            </nav>
          </aside>
        </div>

        <form class="config-form" @submit.prevent="handleSave">
          <!-- ══════════ GENERAL ══════════ -->
          <section id="section-general" class="section">
            <div class="section-head">
              <h2>General</h2>
            <p class="section-desc">Directorios del sistema</p>
          </div>

          <div class="section-body">
            <div class="cfg-grid">
              <div class="form-group">
                <label for="general.tempdir">Temp</label>
                <input id="general.tempdir" v-model="store.configFlat['general.directories.tempdir']" type="text" class="input" />
              </div>
              <div class="form-group">
                <label for="general.logdir">Logs</label>
                <input id="general.logdir" v-model="store.configFlat['general.directories.logdir']" type="text" class="input" />
              </div>
              <div class="form-group">
                <label for="general.resourcedir">Resources</label>
                <input id="general.resourcedir" v-model="store.configFlat['general.directories.resourcedir']" type="text" class="input" />
              </div>
            </div>
          </div>
        </section>

        <!-- ══════════ SENTINEL ══════════ -->
        <section id="section-sentinel" class="section">
          <div class="section-head">
            <h2>Sentinel</h2>
            <p class="section-desc">Escáner de red, análisis web y vulnerabilidades</p>
          </div>

          <div class="section-body">
            <!-- Enable -->
            <div class="cfg-row">
              <label class="toggle-row">
                <input v-model="store.configFlat['sentinel.enabled']" type="checkbox" class="toggle" />
                <span>Habilitado</span>
              </label>
            </div>

            <!-- Output / CSV dirs -->
            <div class="cfg-grid">
              <div class="form-group">
                <label for="sentinel.output">Directorio de salida (PDFs)</label>
                <input id="sentinel.output" v-model="store.configFlat['sentinel.directories.output']" type="text" class="input" />
              </div>
              <div class="form-group">
                <label for="sentinel.csv">Directorio CSV</label>
                <input id="sentinel.csv" v-model="store.configFlat['sentinel.directories.csv']" type="text" class="input" />
              </div>
            </div>

            <!-- Local IPs -->
            <div class="cfg-row">
              <label class="toggle-row">
                <input v-model="store.configFlat['sentinel.areLocalIpsAllowed']" type="checkbox" class="toggle" />
                <span>Permitir IPs locales</span>
              </label>
            </div>

            <!-- Host Reachability Check -->
            <h3 class="subsection-title">Verificaci&oacute;n de accesibilidad del host</h3>
            <div class="cfg-grid">
              <div class="form-group">
                <label class="toggle-row">
                  <input v-model="store.configFlat['sentinel.hostReachabilityCheck.enabled']" type="checkbox" class="toggle" />
                  <span>Habilitado</span>
                </label>
              </div>
              <div class="form-group">
                <label for="reach.timeout">Timeout (segundos)</label>
                <input id="reach.timeout" v-model.number="store.configFlat['sentinel.hostReachabilityCheck.timeout']" type="number" step="0.5" min="0.5" class="input" />
              </div>
              <div class="form-group">
                <label for="reach.port">Puerto</label>
                <input id="reach.port" v-model.number="store.configFlat['sentinel.hostReachabilityCheck.port']" type="number" min="1" max="65535" class="input" />
              </div>
            </div>
          </div>

          <!-- Scanners -->
          <div class="scanner-grid">
            <ScannerCard
              name="Nmap"
              icon="scan"
              :flat="store.configFlat"
              prefix="sentinel.nmap"
            />
            <ScannerCard
              name="Nikto"
              icon="web"
              :flat="store.configFlat"
              prefix="sentinel.nikto"
            />
            <ScannerCard
              name="OpenVAS"
              icon="vuln"
              :flat="store.configFlat"
              prefix="sentinel.openvas"
            />
          </div>

          <!-- OpenVAS tool configs -->
          <div class="section-body openvas-tool-configs">
            <h3 class="subsection-title">OpenVAS &mdash; Configuraciones de escaneo</h3>
            <div class="cfg-grid">
              <div class="form-group">
                <label for="ov.full_deep">Full Deep</label>
                <input id="ov.full_deep" v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_deep']" type="text" class="input font-mono" />
              </div>
              <div class="form-group">
                <label for="ov.full_fast">Full Fast</label>
                <input id="ov.full_fast" v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_fast']" type="text" class="input font-mono" />
              </div>
              <div class="form-group">
                <label for="ov.full_ultimate">Full Ultimate</label>
                <input id="ov.full_ultimate" v-model="store.configFlat['sentinel.openvas.toolConfigs.scanConfigs.full_ultimate']" type="text" class="input font-mono" />
              </div>
            </div>

            <h3 class="subsection-title">OpenVAS &mdash; Listas de puertos</h3>
            <div class="cfg-grid">
              <div class="form-group">
                <label for="ov.tcp_all">TCP All</label>
                <input id="ov.tcp_all" v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_all']" type="text" class="input font-mono" />
              </div>
              <div class="form-group">
                <label for="ov.tcp_all_udp">TCP All + UDP Top 100</label>
                <input id="ov.tcp_all_udp" v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_all_udp_top100']" type="text" class="input font-mono" />
              </div>
              <div class="form-group">
                <label for="ov.tcp_udp">TCP + UDP All</label>
                <input id="ov.tcp_udp" v-model="store.configFlat['sentinel.openvas.toolConfigs.portList.tcp_udp_all']" type="text" class="input font-mono" />
              </div>
            </div>
          </div>
        </section>

        <!-- ══════════ AEGIS ══════════ -->
        <section id="section-aegis" class="section">
          <div class="section-head">
            <h2>Aegis</h2>
            <p class="section-desc">Generación de píldoras de concienciación con IA</p>
          </div>

          <div class="section-body">
            <!-- Enable -->
            <div class="cfg-row">
              <label class="toggle-row">
                <input v-model="store.configFlat['aegis.enabled']" type="checkbox" class="toggle" />
                <span>Habilitado</span>
              </label>
            </div>

            <!-- Directories -->
            <div class="cfg-grid">
              <div class="form-group">
                <label for="aegis.output">Directorio de salida</label>
                <input id="aegis.output" v-model="store.configFlat['aegis.directories.output']" type="text" class="input" />
              </div>
              <div class="form-group">
                <label for="aegis.stack">Stack de documentos</label>
                <input id="aegis.stack" v-model="store.configFlat['aegis.directories.stack']" type="text" class="input" />
              </div>
            </div>

            <!-- System prompt -->
            <h3 class="subsection-title">Prompt del sistema</h3>
            <textarea v-model="store.configFlat['aegis.prompts.system']" rows="10" class="textarea"></textarea>

            <!-- User template -->
            <h3 class="subsection-title">Plantilla de usuario</h3>
            <textarea v-model="store.configFlat['aegis.prompts.userTemplate']" rows="8" class="textarea"></textarea>

            <!-- Brands -->
            <h3 class="subsection-title">Marcas monitoreadas</h3>
            <p class="field-hint">Array JSON con las marcas a rastrear. Cada entrada requiere <code>label</code>, <code>circl_vendor</code>, <code>circl_product</code> y <code>aliases</code>.</p>
            <textarea v-model="brandsText" rows="10" class="textarea font-mono" @blur="syncBrands"></textarea>
          </div>
        </section>

        <!-- ══════════ ACTIONS ══════════ -->
        <div class="form-actions">
          <button type="button" class="btn btn--secondary" @click="store.resetForm()">
            Restablecer
          </button>
          <button type="submit" class="btn btn--primary" :disabled="store.saving">
            {{ store.saving ? 'Guardando…' : 'Guardar Configuración' }}
          </button>
        </div>
      </form>
      </div>
    </main>

    <StarBackground />
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

/* ── Sidebar nav ── */
const navSections = [
  { id: 'general',  label: 'General',  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
  { id: 'sentinel', label: 'Sentinel', icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' },
  { id: 'aegis',    label: 'Aegis',    icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' },
]

const activeSection = ref('general')
let observer = null

function scrollTo(sectionId) {
  const el = document.getElementById(`section-${sectionId}`)
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

onMounted(() => {
  store.loadConfig()
  observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        activeSection.value = entry.target.id.replace('section-', '')
      }
    }
  }, { rootMargin: '-80px 0px -60% 0px' })
  // observe after next tick so sections are rendered
  requestAnimationFrame(() => {
    for (const s of navSections) {
      const el = document.getElementById(`section-${s.id}`)
      if (el) observer.observe(el)
    }
  })
})

onUnmounted(() => { if (observer) observer.disconnect() })

/* ── Brands JSON editor ── */
const brandsText = ref('')
watch(() => store.configFlat['aegis.brands'], (val) => {
  brandsText.value = JSON.stringify(val ?? [], null, 2)
}, { immediate: true })

function syncBrands() {
  try {
    const parsed = JSON.parse(brandsText.value)
    if (Array.isArray(parsed)) store.configFlat['aegis.brands'] = parsed
  } catch { /* keep valid value on invalid JSON */ }
}

function handleSave() { store.saveConfig() }
</script>

<style scoped>
.config-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }
.main { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 5rem; }

.config-layout { display: flex; gap: 1.5rem; align-items: flex-start; }

/* ── Sidebar nav ── */
.config-nav-column { width: 170px; flex-shrink: 0; align-self: stretch; }
.config-nav { position: sticky; top: calc(var(--topbar-h) + 2rem); }
.config-nav nav { display: flex; flex-direction: column; gap: 0.25rem; }
.nav-link {
  display: flex; align-items: center; gap: 0.55rem;
  padding: 0.55rem 0.75rem; border-radius: 8px;
  color: var(--text-muted); font-size: 0.82rem; font-weight: 500;
  text-decoration: none; transition: all var(--transition);
}
.nav-link:hover { background: var(--surface-2); color: var(--text-dim); }
.nav-link.active { background: var(--accent-dim); color: var(--accent); font-weight: 600; }
.nav-icon { width: 18px; height: 18px; flex-shrink: 0; display: flex; align-items: center; }
.nav-icon svg { width: 100%; height: 100%; }
.nav-label { white-space: nowrap; }

/* ── Form area ── */
.config-form { flex: 1; min-width: 0; }

/* ═══════ Sections ═══════ */

.section { margin-bottom: 2.5rem; }

.section-head {
  margin-bottom: 1rem;
  padding-bottom: 0.65rem;
  border-bottom: 1px solid var(--border);
}
.section-head h2 {
  font-size: 1.25rem; font-weight: 700; color: var(--text);
  margin: 0;
}
.section-desc {
  font-size: 0.82rem; color: var(--text-muted);
  margin: 0.2rem 0 0;
}

.section-body {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.25rem 1.5rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* ═══════ Sub-section title ═══════ */

.subsection-title {
  font-size: 0.85rem; font-weight: 600; color: var(--text-dim);
  margin: 0.25rem 0 0.35rem;
}

/* ═══════ Grids & rows ═══════ */

.cfg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }

.cfg-row { display: flex; align-items: center; }

/* ═══════ Scanner grid ═══════ */

.scanner-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

/* ═══════ Form controls ═══════ */

.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: 0.78rem; font-weight: 600; color: var(--text-dim); }

.input {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.5rem 0.7rem; color: var(--text); font-size: 0.88rem;
  outline: none; transition: border-color 0.2s;
}
.input:focus { border-color: var(--accent); }

.textarea {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.55rem 0.7rem; color: var(--text); font-size: 0.82rem;
  font-family: var(--font-mono, monospace);
  outline: none; resize: vertical; width: 100%; min-height: 80px;
  box-sizing: border-box; transition: border-color 0.2s;
}
.textarea:focus { border-color: var(--accent); }

.toggle-row { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.9rem; font-weight: 500; color: var(--text); }
.toggle { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }

.field-hint { font-size: 0.78rem; color: var(--text-muted); line-height: 1.5; }
.field-hint code { font-family: var(--font-mono); font-size: 0.72rem; background: var(--surface-2); padding: 1px 5px; border-radius: 3px; color: var(--text-dim); }
.font-mono { font-family: var(--font-mono); font-size: 0.82rem; }

.openvas-tool-configs { margin-top: 1rem; }

/* ═══════ Action bar ═══════ */

.form-actions {
  display: flex; gap: 0.75rem; justify-content: flex-end;
  position: sticky; bottom: 1rem;
  background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
  padding: 1rem 1.5rem; z-index: 10;
}

.btn {
  padding: 0.55rem 1.5rem; border-radius: 8px; font-size: 0.88rem; font-weight: 600;
  border: 1px solid transparent; cursor: pointer; transition: background 0.2s, opacity 0.2s;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn--primary { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn--primary:hover:not(:disabled) { filter: brightness(1.15); }
.btn--secondary { background: transparent; color: var(--text-dim); border-color: var(--border); }
.btn--secondary:hover { background: var(--border); color: var(--text); }

/* ═══════ Loading ═══════ */

.loading-block { padding: 6rem 0; display: flex; justify-content: center; width: 100%; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 420px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }

@media (max-width: 800px) {
  .config-layout { flex-direction: column; }
  .config-nav-column { width: 100%; }
  .config-nav { position: static; }
  .config-nav nav { flex-direction: row; flex-wrap: wrap; }
  .nav-link { flex: 1; justify-content: center; min-width: 100px; }
}
</style>
