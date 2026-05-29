<template>
  <div class="config-page">
    <Topbar title="Configuración" />

    <main class="main">
      <!-- Loading -->
      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--lg"></div>
      </div>

      <form v-else class="config-form" @submit.prevent="handleSave">
        <!-- ══════════ GENERAL ══════════ -->
        <section class="section">
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
        <section class="section">
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

            <!-- Output dir -->
            <div class="cfg-grid">
              <div class="form-group">
                <label for="sentinel.output">Directorio de salida</label>
                <input id="sentinel.output" v-model="store.configFlat['sentinel.directories.output']" type="text" class="input" />
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
        </section>

        <!-- ══════════ AEGIS ══════════ -->
        <section class="section">
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
    </main>

    <StarBackground />
    <AppToast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import { useConfigStore } from '@/stores/configStore'
import ScannerCard from '@/components/config/ScannerCard.vue'

const store = useConfigStore()

onMounted(() => store.loadConfig())

function handleSave() { store.saveConfig() }
</script>

<style scoped>
.config-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); }
.main { max-width: 900px; margin: 0 auto; padding: 2rem 1.25rem 5rem; }

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

.loading-block { padding: 6rem 0; display: flex; justify-content: center; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 420px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
</style>
