import { describe, expect, it } from 'vitest';
import { readEnv } from '../src/env';

const full = {
  VITE_FIREBASE_API_KEY: 'k',
  VITE_FIREBASE_AUTH_DOMAIN: 'scamshield-hybrid.firebaseapp.com',
  VITE_FIREBASE_PROJECT_ID: 'scamshield-hybrid',
  VITE_FIREBASE_STORAGE_BUCKET: 'b',
  VITE_FIREBASE_MESSAGING_SENDER_ID: '1',
  VITE_FIREBASE_APP_ID: 'a',
  VITE_RECAPTCHA_SITE_KEY: 'site',
  VITE_RECAPTCHA_PROVIDER: 'enterprise',
  VITE_APPCHECK_DEBUG_TOKEN: 'debug-token',
};

describe('readEnv()', () => {
  it('reports every missing variable instead of crashing', () => {
    const r = readEnv({}, { isExtension: false, allowDebugToken: false });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.missing).toContain('VITE_FIREBASE_API_KEY');
      expect(r.missing).toContain('VITE_FIREBASE_APP_ID');
      expect(r.missing).toContain('VITE_RECAPTCHA_SITE_KEY');
    }
  });

  it('drops the App Check debug token when it is not allowed (hosted web build)', () => {
    const r = readEnv(full, { isExtension: false, allowDebugToken: false });
    expect(r.ok && r.env.appCheckDebugToken).toBe(null);
  });

  it('keeps the debug token for the extension and local dev', () => {
    const r = readEnv(full, { isExtension: true, allowDebugToken: true });
    expect(r.ok && r.env.appCheckDebugToken).toBe('debug-token');
  });

  it('defaults to reCAPTCHA Enterprise', () => {
    const r = readEnv({ ...full, VITE_RECAPTCHA_PROVIDER: undefined }, { isExtension: false, allowDebugToken: false });
    expect(r.ok && r.env.recaptchaProvider).toBe('enterprise');
  });

  it('lets the extension run without a reCAPTCHA key when a debug token is present', () => {
    const r = readEnv({ ...full, VITE_RECAPTCHA_SITE_KEY: '' }, { isExtension: true, allowDebugToken: true });
    expect(r.ok).toBe(true);
  });
});
