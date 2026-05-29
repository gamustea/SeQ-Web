<template>
  <div class="tweaks-form">
    <h2>Nueva Píldora</h2>

    <!-- Company -->
    <div class="form-group">
      <label for="tw-company">Empresa</label>
      <input id="tw-company" v-model="store.tweaks.company" type="text" maxlength="60" class="input" placeholder="Nombre de la empresa" />
    </div>

    <!-- Row: Language + Tone -->
    <div class="form-row">
      <div class="form-group">
        <label for="tw-lang">Idioma</label>
        <select id="tw-lang" v-model="store.tweaks.language" class="input select">
          <option value="es">Español</option>
          <option value="en">English</option>
          <option value="fr">Français</option>
          <option value="de">Deutsch</option>
        </select>
      </div>
      <div class="form-group">
        <label for="tw-tone">Tono</label>
        <select id="tw-tone" v-model="store.tweaks.tone" class="input select">
          <option value="profesional">Profesional</option>
          <option value="formal">Formal</option>
          <option value="cercano">Cercano</option>
          <option value="tecnico">Técnico</option>
        </select>
      </div>
    </div>

    <!-- Row: Audience + Sector -->
    <div class="form-row">
      <div class="form-group">
        <label for="tw-audience">Audiencia</label>
        <select id="tw-audience" v-model="store.tweaks.audienceLevel" class="input select">
          <option value="mixed">Mixta</option>
          <option value="technical">Técnica</option>
          <option value="non-technical">No técnica</option>
        </select>
      </div>
      <div class="form-group">
        <label for="tw-sector">Sector</label>
        <input id="tw-sector" v-model="store.tweaks.sector" type="text" maxlength="40" class="input" placeholder="Ej: banca" />
      </div>
    </div>

    <!-- Contact -->
    <div class="form-group">
      <label for="tw-contact">Email de contacto</label>
      <input id="tw-contact" v-model="store.tweaks.mentionContact" type="email" maxlength="100" class="input" placeholder="contacto@empresa.com" />
    </div>

    <!-- Brands -->
    <div class="form-group">
      <label>Marcas asociadas</label>
      <div class="selected-brands" v-if="store.selectedBrands.length">
        <span v-for="b in store.selectedBrands" :key="b" class="brand-tag">
          {{ b }}
          <button type="button" class="brand-remove" @click="removeBrand(b)">&times;</button>
        </span>
      </div>
      <select class="input select" :value="''" @change="addBrand($event.target.value); $event.target.value = ''">
        <option value="">+ Añadir marca</option>
        <option v-for="b in availableBrands" :key="b" :value="b">{{ b }}</option>
      </select>
    </div>

    <!-- Focus -->
    <div class="form-group">
      <label for="tw-focus">Foco del tema</label>
      <input id="tw-focus" v-model="store.tweaks.topicFocus" type="text" maxlength="120" class="input" placeholder="Ej: phishing por QR" />
    </div>

    <!-- Topics -->
    <TopicGrid :topics="store.topics" :selected-topic-id="store.selectedTopicId" @select="store.selectedTopicId = $event" />

    <!-- Generate -->
    <button
      type="button"
      class="btn btn--generate"
      :disabled="!store.selectedTopicId || store.generating"
      @click="store.generate()"
    >
      <span v-if="store.generating" class="spinner"></span>
      {{ store.generating ? 'Generando…' : 'Generar Píldora' }}
    </button>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useAegisStore } from '@/stores/aegisStore'
import TopicGrid from './TopicGrid.vue'

const store = useAegisStore()

const availableBrands = computed(() => {
  const all = store.brands || []
  return all.filter(b => !store.selectedBrands.includes(b))
})

function addBrand(brand) {
  if (!brand) return
  store.selectedBrands.push(brand)
}

function removeBrand(brand) {
  store.selectedBrands = store.selectedBrands.filter(b => b !== brand)
}
</script>

<style scoped>
.tweaks-form { display: flex; flex-direction: column; gap: 0.75rem; padding: 1.25rem; }
.tweaks-form h2 { font-size: 1.1rem; font-weight: 700; color: var(--text); margin: 0 0 0.25rem; flex-shrink: 0; }

.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; }
.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: 0.75rem; font-weight: 600; color: var(--text-dim); }

.input {
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  padding: 0.45rem 0.6rem; color: var(--text); font-size: 0.82rem; outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s;
}
.input:focus { border-color: var(--accent); }
.select { cursor: pointer; appearance: auto; }

.selected-brands { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-bottom: 0.35rem; }
.brand-tag {
  display: inline-flex; align-items: center; gap: 0.3rem;
  padding: 0.2rem 0.5rem; font-size: 0.72rem; font-weight: 600;
  background: var(--accent); color: var(--bg); border-radius: 5px;
}
.brand-remove { background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; padding: 0; line-height: 1; opacity: 0.7; }
.brand-remove:hover { opacity: 1; }

.btn--generate {
  margin-top: 0.5rem; padding: 0.7rem; font-size: 0.9rem; font-weight: 700;
  border-radius: 8px; border: none; cursor: pointer; background: var(--accent); color: var(--bg);
  transition: filter 0.2s, opacity 0.2s; display: flex; align-items: center; justify-content: center; gap: 0.5rem;
}
.btn--generate:hover:not(:disabled) { filter: brightness(1.15); }
.btn--generate:disabled { opacity: 0.5; cursor: not-allowed; }

.spinner { width: 16px; height: 16px; border: 2px solid rgba(255,255,255,.3); border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
