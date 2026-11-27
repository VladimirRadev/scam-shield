import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { createScamShieldAI } from '@scamshield/ai';
import { ErrorBoundary, ScamShieldApp } from '@scamshield/ui';
import '@scamshield/ui/styles.css';

const ai = createScamShieldAI(import.meta.env, {
  isExtension: false,
  // The debug token is only ever used by `vite dev` on localhost (see vite.config.ts envPrefix).
  allowDebugToken: import.meta.env.DEV,
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <ScamShieldApp ai={ai} variant="web" />
    </ErrorBoundary>
  </StrictMode>,
);
