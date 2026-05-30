<template>
  <div class="scanner-card">
    <div class="scanner-header">
      <span class="scanner-icon" v-html="iconSvg"></span>
      <h3>{{ name }}</h3>
    </div>

    <div class="scanner-body">
      <h4>Paleta de colores</h4>
      <div class="color-grid">
        <div v-for="c in colors" :key="prefix + c.key" class="color-pick">
          <input
            :id="prefix + '.colorPalette.' + c.key"
            v-model="flat[prefix + '.colorPalette.' + c.key]"
            type="color"
            class="color-input"
          />
          <span class="color-label">{{ c.label }}</span>
          <span class="color-hex">{{ flat[prefix + '.colorPalette.' + c.key] }}</span>
        </div>
      </div>

      <h4>Prompt del sistema</h4>
      <textarea
        v-model="flat[prefix + '.prompts.system']"
        rows="6"
        class="textarea"
      ></textarea>

      <h4>Plantilla de usuario</h4>
      <textarea
        v-model="flat[prefix + '.prompts.userTemplate']"
        rows="6"
        class="textarea"
      ></textarea>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  name: { type: String, required: true },
  icon: { type: String, default: 'scan' },
  prefix: { type: String, required: true },
  flat: { type: Object, required: true },
})

const colors = [
  { key: 'black', label: 'Negro' },
  { key: 'dark', label: 'Oscuro' },
  { key: 'main', label: 'Principal' },
  { key: 'secondary', label: 'Secundario' },
  { key: 'light', label: 'Claro' },
  { key: 'white', label: 'Blanco' },
]

const icons = {
  scan: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v3l2 2"/></svg>`,
  web: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  vuln: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
}

const iconSvg = computed(() => icons[props.icon] || icons.scan)
</script>

<style scoped>
.scanner-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}

.scanner-header {
  display: flex; align-items: center; gap: 0.6rem;
  padding: 0.85rem 1rem;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
}
.scanner-icon { width: 22px; height: 22px; color: var(--accent); flex-shrink: 0; display: flex; }
.scanner-header h3 { font-size: 1rem; font-weight: 700; color: var(--text); margin: 0; }

.scanner-body { padding: 1rem; display: flex; flex-direction: column; gap: 0.75rem; }
.scanner-body h4 {
  font-size: 0.72rem; font-weight: 700; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.05em; margin: 0;
}

.color-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 0.4rem;
}
.color-pick {
  display: flex; flex-direction: column; align-items: center; gap: 0.15rem;
  padding: 0.45rem 0.25rem;
  background: var(--bg); border-radius: 6px; border: 1px solid var(--border);
}
.color-input {
  width: 32px; height: 24px;
  border: none; border-radius: 3px; cursor: pointer;
  background: transparent; padding: 0;
}
.color-label { font-size: 0.65rem; font-weight: 600; color: var(--text-dim); }
.color-hex { font-size: 0.6rem; color: var(--text-muted); font-family: var(--font-mono); }

.textarea {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.5rem 0.65rem; color: var(--text); font-size: 0.78rem;
  font-family: var(--font-mono, monospace);
  outline: none; resize: vertical; width: 100%; box-sizing: border-box;
  transition: border-color 0.2s;
}
.textarea:focus { border-color: var(--accent); }
</style>
