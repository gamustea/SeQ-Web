<template>
  <StarBackground v-if="!isGuestRoute" />
  <router-view />
  <AppToast />
</template>

<script setup>
/**
 * App.vue — Componente raíz de la aplicación.
 *
 * Renderiza la vista activa del router y el componente global de
 * notificaciones (AppToast). Al montarse, intenta restaurar la sesión
 * desde sessionStorage para que, si el usuario ya estaba autenticado,
 * no tenga que volver a loguearse al recargar la página.
 */
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'

const route = useRoute()
const auth = useAuthStore()

const isGuestRoute = computed(() => route.meta.guest)

onMounted(() => {
  auth.loadFromStorage()
})
</script>
