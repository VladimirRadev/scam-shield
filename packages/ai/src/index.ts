/**
 * Browser-only AI layer of Scam Shield. One facade for the UI:
 * status of the on-device model, model download, quick check and deep check.
 */
import {
  DEFAULT_THRESHOLDS,
  prepareDeepCheck,
  runDeepCheck,
  runQuickCheck,
  type CheckResult,
  type CommunityStats,
  type PreparedDeepCheck,
} from '@scamshield/core';
import { readEnv, type EnvResult, type ReadEnvOptions, type ScamShieldEnv } from './env';
import { runEvalCheck, type EvalRoute } from './eval-check';
import { initFirebase, type FirebaseServices } from './firebase';
import { createModels, sdkGenerate, type ScamShieldModels } from './models';
import { downloadOnDeviceModel, markOnDeviceFailed, onDeviceStatus, type OnDeviceStatus } from './on-device';
import { DEFAULT_APP_CONFIG, loadAppConfig, type AppConfig } from './remote-config';
import { createStatsClient, type StatsClient } from './stats';

export * from './env';
export * from './on-device';
export * from './remote-config';
export { hybridParams, OnDeviceUnavailableError } from './models';
export { runEvalCheck, type EvalRoute, type EvalCheckDeps } from './eval-check';
export { createStatsClient, readCommunityStats, writeCheckStats, statsPayload, type StatsCheck, type StatsClient } from './stats';

export interface ScamShieldAI {
  /** False when the Firebase config is missing: checks run on heuristics only. */
  readonly configured: boolean;
  readonly missingConfig: string[];
  config(): AppConfig;
  /** Resolves once Remote Config was fetched (or fell back to defaults). */
  ready: Promise<AppConfig>;
  status(): Promise<OnDeviceStatus>;
  /** Download Gemini Nano. Call from a click handler. */
  download(onProgress: (fraction: number) => void): Promise<void>;
  quickCheck(text: string): Promise<CheckResult>;
  prepareDeep(text: string): PreparedDeepCheck;
  deepCheck(text: string, prepared: PreparedDeepCheck): Promise<CheckResult>;
  /** Anonymous community totals from Firestore (zeros before the first check), null if unreachable. */
  communityStats(): Promise<CommunityStats | null>;
  /** One check on a fixed route, for the evaluation page. Not counted in the community stats. */
  evalCheck(text: string, route: EvalRoute): Promise<CheckResult>;
  services: FirebaseServices | null;
}

export function createScamShieldAI(rawEnv: Record<string, string | boolean | undefined>, opts: ReadEnvOptions): ScamShieldAI {
  const envResult: EnvResult = readEnv(rawEnv, opts);
  let appConfig: AppConfig = DEFAULT_APP_CONFIG;
  let services: FirebaseServices | null = null;
  let models: ScamShieldModels | null = null;
  let initError: string | null = null;

  if (envResult.ok) {
    try {
      services = initFirebase(envResult.env as ScamShieldEnv);
    } catch (e) {
      initError = e instanceof Error ? e.message : String(e);
      console.error('[scam-shield] Firebase init failed', e);
    }
  }

  const ready: Promise<AppConfig> = services
    ? loadAppConfig(services.remoteConfig).then((c) => {
        appConfig = c;
        models = createModels(services!.ai, c.cloudModel);
        return c;
      })
    : Promise.resolve(DEFAULT_APP_CONFIG);

  const getModels = async (): Promise<ScamShieldModels | null> => {
    if (!services) return null;
    await ready;
    return models;
  };

  // Counters only (see stats.ts). Never blocks a check, never throws.
  const stats: StatsClient | null = services ? createStatsClient({ user: services.user, firestore: services.firestore }) : null;
  const counted = (r: CheckResult): CheckResult => {
    stats?.record(r);
    return r;
  };

  const heuristicsOnly = (note: string) => () => Promise.reject(new Error(note));
  const missingNote = envResult.ok
    ? `Firebase failed to start (${initError ?? 'unknown error'})`
    : `Firebase is not configured (missing ${envResult.missing.join(', ')})`;

  return {
    configured: Boolean(services),
    missingConfig: envResult.ok ? [] : envResult.missing,
    config: () => appConfig,
    ready,
    status: onDeviceStatus,
    async download(onProgress) {
      await downloadOnDeviceModel(onProgress);
      // Also let the SDK's hybrid model register the ready device model.
      const m = await getModels();
      await m?.quick.initializeDeviceModel().catch(() => undefined);
    },
    async quickCheck(text) {
      const m = await getModels();
      const status = await onDeviceStatus();
      const result = await runQuickCheck(text, {
        onDeviceAvailable: Boolean(m) && status === 'available',
        // "available" but no session could be created (e.g. no usable GPU): cloud, redacted only.
        onDeviceFailed: status === 'failed',
        onDeviceFailure: markOnDeviceFailed,
        generate: m ? sdkGenerate(m) : heuristicsOnly(missingNote),
        thresholds: appConfig.thresholds ?? DEFAULT_THRESHOLDS,
      });
      return counted(result);
    },
    prepareDeep(text) {
      return prepareDeepCheck(text, appConfig.thresholds);
    },
    async deepCheck(text, prepared) {
      const m = await getModels();
      if (!appConfig.deepCheckEnabled) {
        return runDeepCheck(text, { generate: heuristicsOnly('Deep check is switched off in Remote Config'), thresholds: appConfig.thresholds }, prepared);
      }
      return counted(await runDeepCheck(text, { generate: m ? sdkGenerate(m) : heuristicsOnly(missingNote), thresholds: appConfig.thresholds }, prepared));
    },
    communityStats: () => stats?.read() ?? Promise.resolve(null),
    async evalCheck(text, route) {
      const m = await getModels();
      // The real status: the device route runs only when Gemini Nano is really usable here.
      const status = m ? await onDeviceStatus() : 'unsupported';
      const generate = m ? sdkGenerate(m) : heuristicsOnly(missingNote);
      return runEvalCheck(text, route, { status, generate, thresholds: appConfig.thresholds ?? DEFAULT_THRESHOLDS });
    },
    get services() {
      return services;
    },
  };
}
