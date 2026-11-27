import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { stripRemoteScripts } from './build/strip-remote-scripts';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  plugins: [react(), stripRemoteScripts()],
  envDir: here('../..'),
  // The extension is allowed to carry the App Check debug token (no reCAPTCHA in MV3 pages).
  envPrefix: 'VITE_',
  base: './',
  resolve: {
    // Firebase Auth build for extensions: no remote scripts (MV3 forbids them).
    alias: [{ find: /^firebase\/auth$/, replacement: 'firebase/auth/web-extension' }],
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    modulePreload: { polyfill: false },
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      input: {
        sidepanel: here('sidepanel.html'),
        background: here('src/background.ts'),
      },
      output: {
        entryFileNames: (chunk) => (chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js'),
      },
    },
  },
});
