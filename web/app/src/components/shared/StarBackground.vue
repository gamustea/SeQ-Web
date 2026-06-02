<template>
  <div class="bg" aria-hidden="true">
    <div class="bg-orb bg-orb--1"></div>
    <div class="bg-orb bg-orb--2"></div>
    <div class="bg-orb bg-orb--3"></div>
    <div class="bg-grain"></div>
  </div>
</template>

<style scoped>
.bg {
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
  background: var(--bg, #0b0c10);
}

.bg-orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.3;
  animation: orb-drift 20s ease-in-out infinite;
}
.bg-orb--1 {
  width: 600px;
  height: 600px;
  background: radial-gradient(circle, rgba(212,160,74,0.12) 0%, transparent 70%);
  top: -20%;
  left: -10%;
  animation-delay: 0s;
}
.bg-orb--2 {
  width: 400px;
  height: 400px;
  background: radial-gradient(circle, rgba(76,183,130,0.08) 0%, transparent 70%);
  bottom: -10%;
  right: -5%;
  animation-delay: -7s;
}
.bg-orb--3 {
  width: 350px;
  height: 350px;
  background: radial-gradient(circle, rgba(96,128,224,0.06) 0%, transparent 70%);
  top: 40%;
  left: 60%;
  animation-delay: -14s;
}

@keyframes orb-drift {
  0%, 100% { transform: translate(0, 0) scale(1); }
  25%      { transform: translate(30px, -20px) scale(1.05); }
  50%      { transform: translate(-20px, 30px) scale(0.95); }
  75%      { transform: translate(20px, 10px) scale(1.02); }
}

.bg-grain {
  position: absolute;
  inset: 0;
  opacity: 0.03;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
  background-repeat: repeat;
  background-size: 256px 256px;
}
</style>
