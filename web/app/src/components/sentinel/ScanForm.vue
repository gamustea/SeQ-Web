<template>
  <div class="launch-card">
    <div class="launch-header">
      <span class="launch-title">Nuevo escaneo {{ type.toUpperCase() }}</span>
      <Transition name="pop"><span v-if="launched" class="launch-success">Escaneo iniciado</span></Transition>
    </div>
    <div class="launch-fields">
      <template v-if="type === 'nmap'">
        <div class="field"><label>Target (IP / CIDR)</label>
          <input v-model="form.target" placeholder="192.168.1.0/24" /></div>
        <div class="ports-wrapper">
          <div class="field field-lg">
            <label>Puertos</label>
            <select v-model="portMode" @change="applyPortPreset">
              <option value="wellknown">Puertos bien conocidos</option>
              <option value="registered">Puertos registrados</option>
              <option value="private">Puertos privados</option>
              <option value="complete">Completo (0-65535)</option>
              <option value="custom">Personalizado</option>
            </select>
          </div>
          <div class="field" :class="{ hidden: portMode !== 'custom' }"><label>Rango de puertos</label>
            <input v-model="form.ports" placeholder="80,443 o 1-1000" /></div>
        </div>
        <div class="field field-sm"><label>Timeout (s)</label>
          <input v-model.number="form.timeout" type="number" min="30" max="86400" class="no-spin" /></div>
      </template>
      <template v-if="type === 'nikto'">
        <div class="field field-lg"><label>Target URL</label>
          <input v-model="form.target" placeholder="http://example.com" /></div>
        <div class="field field-sm"><label>Timeout (s)</label>
          <input v-model.number="form.timeout" type="number" min="10" max="86400" class="no-spin" /></div>
      </template>
      <template v-if="type === 'openvas'">
        <div class="field field-lg"><label>Target (IP única)</label>
          <input v-model="form.target" placeholder="192.168.1.1" /></div>
        <div class="field field-md">
          <label>Configuración</label>
          <select v-model="form.config">
            <option value="full_fast">Full &amp; Fast</option>
            <option value="full_deep">Full &amp; Deep</option>
            <option value="full_ultimate">Full &amp; Ultimate</option>
          </select>
        </div>
      </template>
      <button class="btn-launch" :class="launching ? 'loading' : ''" :disabled="launching" @click="handleLaunch">
        <span class="btn-label">Lanzar</span>
        <span class="btn-spin"></span>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'

const props = defineProps({ type: { type: String, required: true }, launching: { type: Boolean, default: false } })
const emit = defineEmits(['launch'])
const launched = ref(false)

const DEFAULTS = {
  nmap:    { target: '', ports: '1-1000', timeout: 900,  config: 'full_fast' },
  nikto:   { target: '', ports: '',        timeout: 6000, config: 'full_fast' },
  openvas: { target: '', ports: '',        timeout: 600,  config: 'full_fast' },
}
const form = ref({ ...DEFAULTS.nmap })

// Rangos IANA: bien conocidos (0–1023), registrados (1024–49151), privados/dinámicos (49152–65535), y completo (0–65535).
const PORT_PRESETS = { wellknown: '1-1023', registered: '1024-49151', private: '49152-65535', complete: '1-65535' }
const portMode = ref('custom')
function applyPortPreset() {
  if (portMode.value !== 'custom') form.value.ports = PORT_PRESETS[portMode.value]
}

function resetForm(type) { launched.value = false; form.value = { ...DEFAULTS[type] }; portMode.value = 'custom' }
watch(() => props.type, resetForm, { immediate: true })

function handleLaunch() {
  if (!form.value.target.trim()) return
  const payload = { target: form.value.target.trim() }
  if (props.type === 'nmap') { payload.ports = form.value.ports; payload.timeout = form.value.timeout }
  if (props.type === 'nikto') { payload.timeout = form.value.timeout }
  if (props.type === 'openvas') { payload.scanConfig = form.value.config }
  launched.value = true
  emit('launch', payload)
}
</script>

<style scoped>
.launch-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.1rem 1.25rem; margin-bottom: 1.1rem; }
.launch-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.85rem; }
.launch-title { font-weight: 600; color: var(--text); font-size: 0.9rem; font-family: var(--font-display); }
.launch-success { font-size: 0.72rem; color: var(--success); background: var(--success-dim); padding: 0.15rem 0.5rem; border-radius: 6px; }
.pop-enter-active { transition: opacity 0.2s ease, transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1); }
.pop-enter-from { opacity: 0; transform: scale(0.8); }
.pop-leave-active { transition: opacity 0.15s ease; }
.pop-leave-to { opacity: 0; }
@media (prefers-reduced-motion: reduce) {
  .pop-enter-active, .pop-leave-active { transition: none !important; }
}
.launch-fields { display: flex; align-items: flex-end; gap: 0.6rem; flex-wrap: wrap; }
.ports-wrapper { display: grid; grid-template-columns: 1fr; gap: 0.6rem; flex: 2; min-width: 200px; }
.field { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; min-width: 130px; }
.ports-wrapper .field:nth-child(2) { max-height: 70px; overflow: hidden; transition: max-height 0.2s ease, opacity 0.2s ease; opacity: 1; }
.ports-wrapper .field.hidden { max-height: 0; opacity: 0; pointer-events: none; }
.field label { font-size: 0.72rem; color: var(--text-muted); font-weight: 500; }
.field input, .field select { padding: 0.5rem 0.65rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: 0.82rem; outline: none; transition: border-color 0.2s; }
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-sm { flex: 0 0 100px; min-width: 90px; }
.field-md { flex: 0 0 160px; }
.field-lg { flex: 2; min-width: 190px; }
.no-spin::-webkit-outer-spin-button, .no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }
.btn-launch { height: 34px; padding: 0 1.15rem; margin-bottom: 0; background: var(--accent-dim); border: 1px solid var(--accent); color: var(--accent-bright); font-weight: 600; font-size: 0.8rem; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.35rem; transition: all 0.2s; white-space: nowrap; position: relative; }
.btn-launch:hover:not(:disabled) { background: var(--accent); color: #0b0c10; }
.btn-launch:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-launch.loading .btn-label { opacity: 0; }
.btn-launch.loading .btn-spin { display: block; }
.btn-spin { display: none; position: absolute; width: 13px; height: 13px; border: 2px solid rgba(0,0,0,0.2); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }
</style>
