/**
 * Remote Config keys with in-code defaults (identical to the published template).
 */
import type { Thresholds } from '@scamshield/core';
import { fetchAndActivate, getBoolean, getNumber, getString, type RemoteConfig } from 'firebase/remote-config';

export const REMOTE_CONFIG_DEFAULTS = {
  risk_threshold_scam: 70,
  risk_threshold_suspicious: 40,
  /** Corroboration rule: model risk needed to flag a message with no local red flag. */
  model_only_min_risk: 85,
  prompt_version: 'v1',
  cloud_model: 'gemini-3.5-flash-lite',
  deep_check_enabled: true,
} as const;

export interface AppConfig {
  thresholds: Thresholds;
  promptVersion: string;
  cloudModel: string;
  deepCheckEnabled: boolean;
  /** 'remote' when values came from the server, 'defaults' otherwise. */
  source: 'remote' | 'defaults';
}

export const DEFAULT_APP_CONFIG: AppConfig = {
  thresholds: {
    scam: REMOTE_CONFIG_DEFAULTS.risk_threshold_scam,
    suspicious: REMOTE_CONFIG_DEFAULTS.risk_threshold_suspicious,
    modelOnlyMinRisk: REMOTE_CONFIG_DEFAULTS.model_only_min_risk,
  },
  promptVersion: REMOTE_CONFIG_DEFAULTS.prompt_version,
  cloudModel: REMOTE_CONFIG_DEFAULTS.cloud_model,
  deepCheckEnabled: REMOTE_CONFIG_DEFAULTS.deep_check_enabled,
  source: 'defaults',
};

/** Sanity-check values so a bad template can never break scoring. */
export function toAppConfig(
  v: { scam: number; suspicious: number; modelOnlyMinRisk: number; promptVersion: string; cloudModel: string; deepCheckEnabled: boolean },
  source: AppConfig['source'],
): AppConfig {
  const ok = (n: number) => Number.isFinite(n) && n > 0 && n <= 100;
  const scam = ok(v.scam) ? v.scam : DEFAULT_APP_CONFIG.thresholds.scam;
  let suspicious = ok(v.suspicious) ? v.suspicious : DEFAULT_APP_CONFIG.thresholds.suspicious;
  if (suspicious >= scam) suspicious = Math.max(1, scam - 1);
  const modelOnlyMinRisk = ok(v.modelOnlyMinRisk) ? v.modelOnlyMinRisk : REMOTE_CONFIG_DEFAULTS.model_only_min_risk;
  return {
    thresholds: { scam, suspicious, modelOnlyMinRisk },
    promptVersion: v.promptVersion || DEFAULT_APP_CONFIG.promptVersion,
    cloudModel: /^[\w.-]+$/.test(v.cloudModel) ? v.cloudModel : DEFAULT_APP_CONFIG.cloudModel,
    deepCheckEnabled: v.deepCheckEnabled,
    source,
  };
}

/** Fetch and activate, with a short timeout. Falls back to defaults on any error. */
export async function loadAppConfig(rc: RemoteConfig, timeoutMs = 4000): Promise<AppConfig> {
  try {
    await Promise.race([
      fetchAndActivate(rc),
      new Promise((_, reject) => setTimeout(() => reject(new Error('remote config timeout')), timeoutMs)),
    ]);
    return toAppConfig(
      {
        scam: getNumber(rc, 'risk_threshold_scam'),
        suspicious: getNumber(rc, 'risk_threshold_suspicious'),
        modelOnlyMinRisk: getNumber(rc, 'model_only_min_risk'),
        promptVersion: getString(rc, 'prompt_version'),
        cloudModel: getString(rc, 'cloud_model'),
        deepCheckEnabled: getBoolean(rc, 'deep_check_enabled'),
      },
      'remote',
    );
  } catch {
    return DEFAULT_APP_CONFIG;
  }
}
