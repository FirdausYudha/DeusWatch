import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Minimal local declaration so the config can read env vars without pulling in @types/node
// (the web app deliberately keeps its dependency surface small).
declare const process: { env: Record<string, string | undefined> }

// DeusWatch publishes its services on non-default host ports so they don't collide with
// whatever else the host runs: web 9173, API 9080, gateway 9443 (see deploy/docker-compose.yml —
// the API listens on 8080 *inside* its container, but 9080 is what's exposed to the host).
// The dev server must therefore proxy to 9080, not 8080.
//
// Override when you remapped the port (DEUSWATCH_API_PORT in deploy/.env) or run the API
// directly on another port:  DEUSWATCH_API_PORT=8080 npm run dev
const API_PORT = process.env.DEUSWATCH_API_PORT || '9080'
const API_TARGET = process.env.DEUSWATCH_API_URL || `http://localhost:${API_PORT}`

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
