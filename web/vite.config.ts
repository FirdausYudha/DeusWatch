import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The DeusWatch API runs on :8080 (docker compose). This proxy makes the dev server
// forward /healthz, /readyz, /api there, so the UI hits the real backend without
// CORS issues.
const API_TARGET = 'http://localhost:8080'

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
