<template>
  <router-view />
  <AppToast />
</template>

<script setup>
import { onMounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import AppToast from '@/components/shared/AppToast.vue'

const auth = useAuthStore()

onMounted(() => {
  auth.loadFromStorage()
})
</script>
