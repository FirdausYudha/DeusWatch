import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// API DeusWatch jalan di :8080 (docker compose). Proxy ini membuat dev server
// meneruskan /healthz & /readyz ke sana, sehingga UI menyentuh backend asli
// tanpa masalah CORS.
const API_TARGET = process.env.DEUSWATCH_API ?? 'http://localhost:8080'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/healthz': API_TARGET,
      '/readyz': API_TARGET,
      '/api': API_TARGET,
    },
  },
})
