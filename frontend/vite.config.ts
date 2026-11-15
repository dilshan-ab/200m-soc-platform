/// <reference types="vitest" />
/// <reference types="node" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: {
    '/api': { target: process.env.SOC_API ?? 'http://localhost:8000', changeOrigin: false },
    '/taxii2': { target: process.env.SOC_API ?? 'http://localhost:8000', changeOrigin: false },
  } },
  build: { sourcemap: false, chunkSizeWarningLimit: 1200 },
  test: { environment: 'jsdom', globals: true },
});
