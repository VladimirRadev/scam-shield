import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const repoRoot = here('../..');

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
    rollupOptions: {
      // eval.html: the in-browser model evaluation page (not linked from the app).
      input: { main: here('index.html'), eval: here('eval.html') },
      output: {
        // Long-lived vendor chunks (React, Firebase) apart from the app code. Firestore is
        // excluded on purpose: it stays a lazy chunk, loaded only for the community counters.
        codeSplitting: {
          groups: [
            { name: 'react', test: /[\\/]node_modules[\\/](?:react|react-dom|scheduler)[\\/]/ },
            { name: 'firebase', test: /[\\/]node_modules[\\/](?:@firebase[\\/](?!firestore|webchannel-wrapper)|firebase[\\/](?!firestore))/ },
            { name: 'scamshield', test: /[\\/]packages[\\/](?:core|ai|ui)[\\/]src[\\/]/ },
          ],
        },
      },
    },
  },
  server: { port: 5173, strictPort: false },
}));
