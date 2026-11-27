import { describe, expect, it } from 'vitest';
import { DEFAULT_APP_CONFIG, REMOTE_CONFIG_DEFAULTS, toAppConfig } from '../src/remote-config';

describe('Remote Config defaults', () => {
  it('match the published template', () => {
    expect(REMOTE_CONFIG_DEFAULTS).toEqual({
      risk_threshold_scam: 70,
      risk_threshold_suspicious: 40,
      prompt_version: 'v1',
      cloud_model: 'gemini-3.5-flash-lite',
      deep_check_enabled: true,
    });
    expect(DEFAULT_APP_CONFIG.thresholds).toEqual({ scam: 70, suspicious: 40 });
  });

  it('rejects broken values from the server', () => {
    const c = toAppConfig({ scam: 0, suspicious: 500, promptVersion: '', cloudModel: 'bad model; drop', deepCheckEnabled: false }, 'remote');
    expect(c.thresholds.scam).toBe(70);
    expect(c.thresholds.suspicious).toBeLessThan(c.thresholds.scam);
    expect(c.cloudModel).toBe('gemini-3.5-flash-lite');
    expect(c.promptVersion).toBe('v1');
    expect(c.deepCheckEnabled).toBe(false);
  });
});
