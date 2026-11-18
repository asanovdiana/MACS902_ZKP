import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const GATEWAY = process.env.VITE_GATEWAY_URL ?? 'http://127.0.0.1:4000';
const SSO = process.env.VITE_SSO_URL ?? 'http://127.0.0.1:4200';
const PROVER = process.env.VITE_PROVER_URL ?? 'http://127.0.0.1:4700';

// The browser only ever talks to this origin. The dev server forwards:
//   /api, /svc  → ZK gateway   /sso → SSO baseline   /p2 → user-side prover (team wallet prover; v3 stand-in for dev:v3)
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: GATEWAY, ws: true },
      '/svc': { target: GATEWAY },
      '/sso': { target: SSO, ws: true },
      '/p2': { target: PROVER, rewrite: (p) => p.replace(/^\/p2/, '') },
    },
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 900 },
  test: {
    environment: 'jsdom',
    include: ['tests/unit/**/*.test.{ts,tsx}'],
    setupFiles: ['tests/unit/setup.ts'],
  },
});
