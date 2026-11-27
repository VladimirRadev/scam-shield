/**
 * Firebase web configuration, read from Vite `VITE_*` variables (written to `.env.local`,
 * which is git-ignored). The apps pass `import.meta.env` in, so this module stays testable.
 */

export interface FirebaseWebConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
}

export type RecaptchaProvider = 'enterprise' | 'v3';

export interface ScamShieldEnv {
  firebase: FirebaseWebConfig;
  recaptchaSiteKey: string | null;
  recaptchaProvider: RecaptchaProvider;
  /** App Check debug token. Only ever set for local dev and the extension build. */
  appCheckDebugToken: string | null;
  /** Chrome extension page (no remote scripts allowed, so App Check runs on the debug token). */
  isExtension: boolean;
}

export type EnvResult = { ok: true; env: ScamShieldEnv } | { ok: false; missing: string[] };

const REQUIRED = {
  apiKey: 'VITE_FIREBASE_API_KEY',
  authDomain: 'VITE_FIREBASE_AUTH_DOMAIN',
  projectId: 'VITE_FIREBASE_PROJECT_ID',
  storageBucket: 'VITE_FIREBASE_STORAGE_BUCKET',
  messagingSenderId: 'VITE_FIREBASE_MESSAGING_SENDER_ID',
  appId: 'VITE_FIREBASE_APP_ID',
} as const satisfies Record<keyof FirebaseWebConfig, string>;

type RawEnv = Record<string, string | boolean | undefined>;

const str = (raw: RawEnv, key: string): string => {
  const v = raw[key];
  return typeof v === 'string' ? v.trim() : '';
};

export interface ReadEnvOptions {
  isExtension: boolean;
  /** Whether the App Check debug token may be used (local dev or extension only). */
  allowDebugToken: boolean;
}

export function readEnv(raw: RawEnv, opts: ReadEnvOptions): EnvResult {
  const missing: string[] = [];
  const firebase = {} as FirebaseWebConfig;
  for (const [field, key] of Object.entries(REQUIRED) as Array<[keyof FirebaseWebConfig, string]>) {
    const v = str(raw, key);
    if (!v) missing.push(key);
    firebase[field] = v;
  }
  const debugToken = opts.allowDebugToken ? str(raw, 'VITE_APPCHECK_DEBUG_TOKEN') || null : null;
  const siteKey = str(raw, 'VITE_RECAPTCHA_SITE_KEY') || null;
  // A web page needs a reCAPTCHA key; the extension and local dev can run on the debug token.
  if (!siteKey && !debugToken) missing.push('VITE_RECAPTCHA_SITE_KEY');
  if (missing.length) return { ok: false, missing };
  return {
    ok: true,
    env: {
      firebase,
      recaptchaSiteKey: siteKey,
      recaptchaProvider: str(raw, 'VITE_RECAPTCHA_PROVIDER').toLowerCase() === 'v3' ? 'v3' : 'enterprise',
      appCheckDebugToken: debugToken,
      isExtension: opts.isExtension,
    },
  };
}
