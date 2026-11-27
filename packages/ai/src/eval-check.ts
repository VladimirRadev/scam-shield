/**
 * One check on a fixed route for the evaluation page (apps/web/eval.html). Pure on its inputs,
 * so the routing rule is unit-tested without a browser:
 * - `device`: RAW text, on the device only. Unless the on-device status is "available" there is no
 *   model call at all (a heuristics-only row); a failing device call never falls back to the cloud.
 * - `cloud`: REDACTED text, cloud only (the quick-check fallback route).
 * - `heuristics`: no model, local signals only.
 */
import { analyzeLocal, combine, DEFAULT_THRESHOLDS, runQuickCheck, type CheckResult, type Generate, type Thresholds } from '@scamshield/core';
import type { OnDeviceStatus } from './on-device';

export type EvalRoute = 'device' | 'cloud' | 'heuristics';

export interface EvalCheckDeps {
  /** Real, fresh on-device status (`onDeviceStatus()`). */
  status: OnDeviceStatus;
  generate: Generate;
  thresholds?: Thresholds;
  now?: () => number;
}

export async function runEvalCheck(text: string, route: EvalRoute, deps: EvalCheckDeps): Promise<CheckResult> {
  const thresholds = deps.thresholds ?? DEFAULT_THRESHOLDS;
  const now = deps.now ?? (() => performance.now());
  if (route === 'device' && deps.status !== 'available') {
    const t0 = now();
    const local = analyzeLocal(text);
    return combine({ text, local, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, thresholds, note: `On-device model is ${deps.status}; raw text was not sent anywhere.` });
  }
  if (route === 'heuristics') {
    const t0 = now();
    const local = analyzeLocal(text);
    return combine({ text, local, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, thresholds });
  }
  if (route === 'device') {
    return runQuickCheck(text, { onDeviceAvailable: true, allowCloudFallback: false, onDeviceFailure: () => undefined, generate: deps.generate, thresholds, now });
  }
  return runQuickCheck(text, { onDeviceAvailable: false, onDeviceFailed: true, generate: deps.generate, thresholds, now });
}
