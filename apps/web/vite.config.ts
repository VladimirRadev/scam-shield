import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ command }) => ({
  plugins: [react()],
  envDir: repoRoot,
  // Build-time guarantee: the hosted build exposes only Firebase and reCAPTCHA variables,
  // so VITE_APPCHECK_DEBUG_TOKEN can never be inlined into apps/web/dist.
  // `vite dev` (localhost) exposes all VITE_* variables, including the debug token.
  envPrefix: command === 'build' ? ['VITE_FIREBASE_', 'VITE_RECAPTCHA_'] : 'VITE_',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    chunkSizeWarningLimit: 1200,
  },
  server: { port: 5173, strictPort: false },
}));
