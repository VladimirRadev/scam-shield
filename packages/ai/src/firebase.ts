/**
 * Firebase initialisation: app, App Check, anonymous Auth, Remote Config, Firestore and
 * Firebase AI Logic with the Gemini Developer API backend.
 */
import { initializeApp, type FirebaseApp } from 'firebase/app';
import {
  CustomProvider,
  initializeAppCheck,
  ReCaptchaEnterpriseProvider,
  ReCaptchaV3Provider,
  type AppCheck,
} from 'firebase/app-check';
// The extension build aliases 'firebase/auth' to 'firebase/auth/web-extension' (no remote scripts).
import { getAuth, onAuthStateChanged, signInAnonymously, type Auth, type User } from 'firebase/auth';
import { getAI, GoogleAIBackend, type AI } from 'firebase/ai';
import type { Firestore } from 'firebase/firestore';
import { getRemoteConfig, type RemoteConfig } from 'firebase/remote-config';
import type { ScamShieldEnv } from './env';
import { REMOTE_CONFIG_DEFAULTS } from './remote-config';

export interface FirebaseServices {
  app: FirebaseApp;
  appCheck: AppCheck;
  auth: Auth;
  ai: AI;
  remoteConfig: RemoteConfig;
  /** Firestore is loaded on first use (anonymous stats arrive in run 2). */
  firestore: () => Promise<Firestore>;
  /** Resolves with the anonymous user, or null if sign-in failed (the app keeps working). */
  user: Promise<User | null>;
}

declare global {
  // Read by the App Check SDK to enable debug mode.
  var FIREBASE_APPCHECK_DEBUG_TOKEN: string | boolean | undefined;
}

let services: FirebaseServices | null = null;

function appCheckProvider(env: ScamShieldEnv) {
  if (env.isExtension || !env.recaptchaSiteKey) {
    // Extension pages may not load the remote reCAPTCHA script (MV3 CSP). In debug mode the
    // SDK exchanges the debug token and never asks this provider for a token.
    return new CustomProvider({
      getToken: () => Promise.reject(new Error('App Check in the extension runs on the registered debug token.')),
    });
  }
  return env.recaptchaProvider === 'v3'
    ? new ReCaptchaV3Provider(env.recaptchaSiteKey)
    : new ReCaptchaEnterpriseProvider(env.recaptchaSiteKey);
}

export function initFirebase(env: ScamShieldEnv): FirebaseServices {
  if (services) return services;
  const app = initializeApp(env.firebase);

  if (env.appCheckDebugToken) {
    // Must be set before initializeAppCheck(). Only present in local dev and the extension.
    globalThis.FIREBASE_APPCHECK_DEBUG_TOKEN = env.appCheckDebugToken;
  }
  const appCheck = initializeAppCheck(app, { provider: appCheckProvider(env), isTokenAutoRefreshEnabled: true });

  const auth = getAuth(app);
  const user = new Promise<User | null>((resolve) => {
    const stop = onAuthStateChanged(auth, (u) => {
      if (u) {
        stop();
        resolve(u);
      }
    });
    signInAnonymously(auth).catch((e: unknown) => {
      console.warn('[scam-shield] anonymous sign-in failed', e);
      stop();
      resolve(null);
    });
  });

  const remoteConfig = getRemoteConfig(app);
  remoteConfig.defaultConfig = { ...REMOTE_CONFIG_DEFAULTS };
  remoteConfig.settings.minimumFetchIntervalMillis = 60 * 60 * 1000;
  remoteConfig.settings.fetchTimeoutMillis = 5000;

  const ai = getAI(app, { backend: new GoogleAIBackend() });
  let db: Promise<Firestore> | null = null;
  const firestore = () => (db ??= import('firebase/firestore').then((m) => m.getFirestore(app)));

  services = { app, appCheck, auth, ai, remoteConfig, firestore, user };
  return services;
}
