<template>
  <div class="launch-card">
    <div class="launch-header">
      <span class="launch-title">Nuevo escaneo {{ type.toUpperCase() }}</span>
      <span v-if="launched" class="launch-success">Escaneo iniciado</span>
    </div>

    <div class="launch-fields">
      <!-- Nmap: target + ports + timeout -->
      <template v-if="type === 'nmap'">
        <div class="field"><label>Target (IP / CIDR)</label>
          <input v-model="form.target" placeholder="192.168.1.0/24" /></div>
        <div class="field"><label>Puertos</label>
          <input v-model="form.ports" placeholder="80,443 o 1-1000" /></div>
        <div class="field field-sm"><label>Timeout (s)</label>
          <input v-model.number="form.timeout" type="number" min="30" max="86400" class="no-spin" /></div>
      </template>

      <!-- Nikto: target URL + timeout -->
      <template v-if="type === 'nikto'">
        <div class="field field-lg"><label>Target URL</label>
          <input v-model="form.target" placeholder="http://example.com" /></div>
        <div class="field field-sm"><label>Timeout (s)</label>
          <input v-model.number="form.timeout" type="number" min="10" max="86400" class="no-spin" /></div>
      </template>

      <!-- OpenVAS: target IP + config -->
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
/**
 * ScanForm — Formulario de lanzamiento de escaneo.
 * Adapta los campos según el tipo: nmap (IP+puertos+timeout), nikto (URL+timeout), openvas (IP+config).
 *
 * @vue-prop {'nmap'|'nikto'|'openvas'} type - Tipo de escáner
 * @vue-prop {boolean} launching - True mientras se envía la petición
 *
 * @vue-emit {object} launch - Payload con los campos del formulario
 */
import { ref, watch } from 'vue'

const props = defineProps({
  type: { type: String, required: true },
  launching: { type: Boolean, default: false },
})

const emit = defineEmits(['launch'])

const launched = ref(false)

const DEFAULTS = {
  nmap:    { target: '', ports: '1-1000', timeout: 900,  config: 'full_fast' },
  nikto:   { target: '', ports: '',        timeout: 6000, config: 'full_fast' },
  openvas: { target: '', ports: '',        timeout: 600,  config: 'full_fast' },
}

const form = ref({ ...DEFAULTS.nmap })

function resetForm(type) {
  launched.value = false
  form.value = { ...DEFAULTS[type] }
}

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
.launch-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
.launch-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
.launch-title { font-weight: 600; color: var(--text); font-size: 0.95rem; }
.launch-success { font-size: 0.75rem; color: var(--success); background: var(--success-dim); padding: 0.15rem 0.6rem; border-radius: 10px; }
.launch-fields { display: flex; align-items: flex-end; gap: 0.75rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.3rem; flex: 1; min-width: 140px; }
.field label { font-size: 0.75rem; color: var(--text-muted); font-weight: 500; }
.field input, .field select {
  padding: 0.55rem 0.7rem; background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 8px;
  color: var(--text); font-size: 0.85rem; outline: none; transition: border-color 0.2s;
}
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-sm { flex: 0 0 110px; min-width: 100px; }
.field-md { flex: 0 0 170px; }
.field-lg { flex: 2; min-width: 200px; }
.no-spin::-webkit-outer-spin-button,
.no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }
.btn-launch {
  height: 36px; padding: 0 1.25rem; margin-bottom: 0; background: var(--accent-dim); border: 1px solid var(--accent);
  color: var(--accent); font-weight: 600; font-size: 0.82rem; border-radius: 8px; cursor: pointer;
  display: flex; align-items: center; gap: 0.4rem; transition: all 0.2s; white-space: nowrap;
}
.btn-launch:hover:not(:disabled) { background: var(--accent); color: #000; }
.btn-launch:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-launch.loading .btn-label { opacity: 0; }
.btn-launch.loading .btn-spin { display: block; }
.btn-spin { display: none; position: absolute; width: 14px; height: 14px; border: 2px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }
</style>
