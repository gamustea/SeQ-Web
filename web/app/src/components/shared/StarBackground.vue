<template>
  <div class="stars" ref="starsRef" aria-hidden="true"></div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const starsRef = ref(null)

onMounted(() => {
  const container = starsRef.value
  if (!container) return
  const count = window.innerWidth < 768 ? 60 : 120
  for (let i = 0; i < count; i++) {
    const star = document.createElement('div')
    star.className = 'star'
    star.style.cssText = `
      left: ${Math.random() * 100}%;
      top: ${Math.random() * 100}%;
      width: ${Math.random() * 2.5 + 0.5}px;
      height: ${Math.random() * 2.5 + 0.5}px;
      animation-delay: ${Math.random() * 5}s;
      animation-duration: ${Math.random() * 4 + 2}s;
      opacity: ${Math.random() * 0.6 + 0.2};
    `
    container.appendChild(star)
  }
})
</script>

<style scoped>
.stars {
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
}

:deep(.star) {
  position: absolute;
  background: #fff;
  border-radius: 50%;
  animation: star-twinkle linear infinite;
  box-shadow: 0 0 4px rgba(255, 255, 255, 0.3);
}

@keyframes star-twinkle {
  0%, 100% { opacity: 0.2; transform: scale(1); }
  50%      { opacity: 1; transform: scale(1.3); }
}
</style>
