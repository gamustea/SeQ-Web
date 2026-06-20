/**
 * main.js — Punto de entrada de la aplicación.
 *
 * Inicializa la instancia de Vue con los plugins necesarios:
 * - Pinia: estado global reactivo (auth, toast, etc.)
 * - Vue Router: navegación SPA
 *
 * También importa el archivo CSS compartido del proyecto legacy
 * (shared.css) para reutilizar los tokens de diseño (colores, fuentes,
 * espaciados) definidos como custom properties en :root.
 */
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'

import '../../resources/css/shared.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
