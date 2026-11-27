import { describe, expect, it } from 'vitest';
import { DEFAULT_THRESHOLDS } from '@scamshield/core';
import { DEFAULT_APP_CONFIG, REMOTE_CONFIG_DEFAULTS, toAppConfig } from '../src/remote-config';

const good = { scam: 70, suspicious: 40, modelOnlyMinRisk: 85, promptVersion: 'v2', cloudModel: 'gemini-3.5-flash-lite', deepCheckEnabled: true };

describe('Remote Config defaults', () => {
  it('match the published template', () => {
    expect(REMOTE_CONFIG_DEFAULTS).toEqual({
      risk_threshold_scam: 70,
      risk_threshold_suspicious: 40,
      model_only_min_risk: 85,
      prompt_version: 'v1',
      cloud_model: 'gemini-3.5-flash-lite',
      deep_check_enabled: true,
    });
    expect(DEFAULT_APP_CONFIG.thresholds).toEqual({ scam: 70, suspicious: 40, modelOnlyMinRisk: 85 });
    expect(DEFAULT_APP_CONFIG.thresholds).toEqual(DEFAULT_THRESHOLDS);
  });

  it('rejects broken values from the server', () => {
    const c = toAppConfig({ scam: 0, suspicious: 500, modelOnlyMinRisk: 0, promptVersion: '', cloudModel: 'bad model; drop', deepCheckEnabled: false }, 'remote');
    expect(c.thresholds.scam).toBe(70);
    expect(c.thresholds.suspicious).toBeLessThan(c.thresholds.scam);
    expect(c.thresholds.modelOnlyMinRisk).toBe(85);
    expect(c.cloudModel).toBe('gemini-3.5-flash-lite');
    expect(c.promptVersion).toBe('v1');
    expect(c.deepCheckEnabled).toBe(false);
  });

  it('takes a valid model_only_min_risk from the server and rejects out-of-range ones', () => {
    expect(toAppConfig({ ...good, modelOnlyMinRisk: 90 }, 'remote').thresholds.modelOnlyMinRisk).toBe(90);
    expect(toAppConfig({ ...good, modelOnlyMinRisk: 100 }, 'remote').thresholds.modelOnlyMinRisk).toBe(100);
    for (const bad of [-5, 101, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(toAppConfig({ ...good, modelOnlyMinRisk: bad }, 'remote').thresholds.modelOnlyMinRisk, String(bad)).toBe(85);
    }
  });
});
