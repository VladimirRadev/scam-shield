import { describe, expect, it, vi } from 'vitest';
import { runEvalCheck } from '../src/eval-check';

const SCAM = JSON.stringify({ risk: 90, verdict: 'scam', category: 'phishing', reasons: [], advice: 'x' });
const TEXT = 'Verify your password at https://secure-paypa1.com/login now, anna.k@gmail.com';

describe('runEvalCheck()', () => {
  it.each(['unsupported', 'downloadable', 'failed', 'unavailable'] as const)(
    'device route with status "%s": no model call, a heuristics-only row',
    async (status) => {
      const generate = vi.fn(async () => ({ text: SCAM, source: 'cloud' as const }));
      const r = await runEvalCheck(TEXT, 'device', { status, generate });
      expect(generate).not.toHaveBeenCalled();
      expect(r.backend).toBe('heuristics-only');
      expect(r.bytesSent).toBe(0);
      expect(r.note).toContain(status);
    },
  );

  it('device route with status "available": raw text on the device route only', async () => {
    const generate = vi.fn(async () => ({ text: SCAM, source: 'on-device' as const }));
    const r = await runEvalCheck(TEXT, 'device', { status: 'available', generate });
    expect(generate).toHaveBeenCalledTimes(1);
    expect((generate.mock.calls[0] as unknown as [string, string])[1]).toBe('device');
    expect(r.backend).toBe('on-device');
  });

  it('device route never falls back to the cloud when the device call fails', async () => {
    const generate = vi.fn().mockRejectedValue(new Error('session lost'));
    const r = await runEvalCheck(TEXT, 'device', { status: 'available', generate });
    expect(generate).toHaveBeenCalledTimes(1);
    expect(r.backend).toBe('heuristics-only');
  });

  it('cloud route sends redacted text only', async () => {
    const generate = vi.fn(async () => ({ text: SCAM, source: 'cloud' as const }));
    const r = await runEvalCheck(TEXT, 'cloud', { status: 'available', generate });
    const [prompt, route] = generate.mock.calls[0] as unknown as [string, string];
    expect(route).toBe('cloud');
    expect(prompt).not.toContain('anna.k@gmail.com');
    expect(r.backend).toBe('cloud-redacted');
  });
});
