import { describe, expect, it, vi } from 'vitest';
import { analyzeLocal, combine, runQuickCheck, runDeepCheck, locateQuote, DEFAULT_THRESHOLDS, toSegments } from '../src/engine';
import type { ModelVerdict } from '../src/types';

const PHISH =
  'URGENT: Your account will be suspended within 24 hours. Verify your password at https://secure-paypa1.com/login now. Questions? anna.k@gmail.com or +1 415 555 0132.';

const SAFE_VERDICT = JSON.stringify({
  risk: 5,
  verdict: 'safe',
  category: 'none',
  reasons: [],
  advice: 'Looks fine.',
});

const SCAM_VERDICT = JSON.stringify({
  risk: 92,
  verdict: 'scam',
  category: 'phishing',
  reasons: [{ quote: 'Verify your password', why: 'Banks never ask for your password by message.' }],
  advice: 'Do not click the link.',
});

let clock = 1000;
const now = () => (clock += 250);

describe('default thresholds', () => {
  it('match the Remote Config defaults', () => {
    expect(DEFAULT_THRESHOLDS).toEqual({ scam: 70, suspicious: 40 });
  });
});

describe('combine()', () => {
  const local = analyzeLocal(PHISH);

  it('without a model, uses the heuristic score', () => {
    const r = combine({ text: PHISH, local, model: null, backend: 'heuristics-only', latencyMs: 3, sentText: null });
    expect(r.risk).toBe(local.score.total);
    expect(r.modelRisk).toBeNull();
    expect(r.backend).toBe('heuristics-only');
    expect(r.bytesSent).toBe(0);
  });

  it('never lets a "safe" model answer erase hard red flags (prompt-injection guard)', () => {
    const model: ModelVerdict = { risk: 0, verdict: 'safe', category: 'none', reasons: [], advice: '' };
    const r = combine({ text: PHISH, local, model, backend: 'on-device', latencyMs: 10, sentText: null });
    expect(r.risk).toBeGreaterThanOrEqual(local.score.hard);
    expect(r.risk).toBeGreaterThan(0);
  });

  it('lets a confident model raise the score above weak heuristics', () => {
    const t = 'Hi, how are you? Long time no see.';
    const model: ModelVerdict = { risk: 88, verdict: 'scam', category: 'investment-romance', reasons: [], advice: '' };
    const r = combine({ text: t, local: analyzeLocal(t), model, backend: 'on-device', latencyMs: 10, sentText: null });
    expect(r.risk).toBe(88);
    expect(r.verdict).toBe('scam');
    expect(r.category).toBe('investment-romance');
  });

  it('turns model quotes into highlights on the original text', () => {
    const model: ModelVerdict = {
      risk: 90,
      verdict: 'scam',
      category: 'phishing',
      reasons: [{ quote: 'verify your password', why: 'Credential theft.' }],
      advice: '',
    };
    const r = combine({ text: PHISH, local, model, backend: 'on-device', latencyMs: 10, sentText: null });
    const h = r.highlights.find((x) => x.source === 'model');
    expect(h).toBeDefined();
    expect(PHISH.slice(h!.start, h!.end)).toBe('Verify your password');
  });

  it('records bytes sent as the UTF-8 length of the text that left the device', () => {
    const r = combine({ text: PHISH, local, model: null, backend: 'cloud-redacted', latencyMs: 1, sentText: 'héllo' });
    expect(r.bytesSent).toBe(6);
  });

  it('category is "none" when the verdict is safe', () => {
    const t = 'See you at lunch at 12.';
    const r = combine({ text: t, local: analyzeLocal(t), model: null, backend: 'heuristics-only', latencyMs: 1, sentText: null });
    expect(r.verdict).toBe('safe');
    expect(r.category).toBe('none');
  });
});

describe('locateQuote()', () => {
  it('finds exact, case-insensitive and whitespace-normalised quotes', () => {
    const t = 'Please   send the\nfee today';
    expect(locateQuote(t, 'send the fee')).toEqual({ start: 9, end: 21 });
    expect(locateQuote(t, 'FEE TODAY')).toEqual({ start: 18, end: 27 });
    expect(locateQuote(t, 'not there')).toBeNull();
    expect(locateQuote(t, '')).toBeNull();
  });

  it('maps a quote of the redacted text back to the original', () => {
    const original = 'Write to bob@evil.io to claim the prize';
    const local = analyzeLocal(original);
    const span = locateQuote(original, 'Write to [EMAIL@evil.io] to claim', local.redaction);
    expect(span).not.toBeNull();
    expect(original.slice(span!.start, span!.end)).toBe('Write to bob@evil.io to claim');
  });
});

describe('runQuickCheck() privacy routing', () => {
  it('sends the RAW text to the on-device model and reports 0 bytes sent', async () => {
    const generate = vi.fn(async () => ({ text: SCAM_VERDICT, source: 'on-device' as const }));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: true, generate, now });
    expect(generate).toHaveBeenCalledTimes(1);
    const [prompt, route] = generate.mock.calls[0] as unknown as [string, string];
    expect(route).toBe('device');
    expect(prompt).toContain('anna.k@gmail.com');
    expect(r.backend).toBe('on-device');
    expect(r.bytesSent).toBe(0);
    expect(r.sentText).toBeNull();
    expect(r.verdict).toBe('scam');
    expect(r.latencyMs).toBeGreaterThan(0);
  });

  it('sends ONLY redacted text when the on-device model is unavailable', async () => {
    const generate = vi.fn(async () => ({ text: SCAM_VERDICT, source: 'cloud' as const }));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: false, generate, now });
    const [prompt, route] = generate.mock.calls[0] as unknown as [string, string];
    expect(route).toBe('hybrid');
    expect(prompt).not.toContain('anna.k@gmail.com');
    expect(prompt).not.toContain('555 0132');
    expect(prompt).not.toContain('/login');
    expect(r.backend).toBe('cloud-redacted');
    expect(r.sentText).toBe(prompt);
    expect(r.bytesSent).toBe(new TextEncoder().encode(prompt).length);
  });

  it('reports on-device when the hybrid model answered on the device with redacted text', async () => {
    const generate = vi.fn(async () => ({ text: SAFE_VERDICT, source: 'on-device' as const }));
    const r = await runQuickCheck('hello', { onDeviceAvailable: false, generate, now });
    expect(r.backend).toBe('on-device');
    expect(r.bytesSent).toBe(0);
  });

  it('when "available" Nano cannot open a session: reports the failure and sends only redacted text to the cloud', async () => {
    const sessionError = Object.assign(new Error('The device is unable to create a session to run the model'), {
      name: 'InvalidStateError',
    });
    const generate = vi
      .fn()
      .mockRejectedValueOnce(sessionError)
      .mockResolvedValueOnce({ text: SCAM_VERDICT, source: 'cloud' });
    const onDeviceFailure = vi.fn();
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: true, generate, now, onDeviceFailure });
    expect(generate).toHaveBeenCalledTimes(2);
    const first = generate.mock.calls[0] as unknown as [string, string];
    const second = generate.mock.calls[1] as unknown as [string, string];
    expect(first[1]).toBe('device');
    // Not 'hybrid': the PREFER_ON_DEVICE model would pick the broken device again.
    expect(second[1]).toBe('cloud');
    expect(second[0]).not.toContain('anna.k@gmail.com');
    expect(second[0]).not.toContain('555 0132');
    expect(second[0]).toContain('[EMAIL@gmail.com]');
    expect(onDeviceFailure).toHaveBeenCalledWith(sessionError);
    expect(r.backend).toBe('cloud-redacted');
    expect(r.sentText).toBe(second[0]);
    expect(r.note).toMatch(/unable to create a session/);
  });

  it('skips the device and the hybrid model once on-device is known to fail this session', async () => {
    const generate = vi.fn(async () => ({ text: SCAM_VERDICT, source: 'cloud' as const }));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: false, onDeviceFailed: true, generate, now });
    expect(generate).toHaveBeenCalledTimes(1);
    const [prompt, route] = generate.mock.calls[0] as unknown as [string, string];
    expect(route).toBe('cloud');
    expect(prompt).not.toContain('anna.k@gmail.com');
    expect(r.backend).toBe('cloud-redacted');
  });

  it('never sends raw text on the fallback, whatever the device error', async () => {
    const generate = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('responseConstraint not supported'))
      .mockResolvedValueOnce({ text: SAFE_VERDICT, source: 'cloud' });
    await runQuickCheck(PHISH, { onDeviceAvailable: true, generate, now });
    const calls = generate.mock.calls as unknown as Array<[string, string]>;
    const raw = calls.filter(([p]) => p.includes('anna.k@gmail.com'));
    expect(raw).toHaveLength(1);
    expect(raw[0]![1]).toBe('device');
  });

  it('does not fall back to the cloud when cloud fallback is disabled', async () => {
    const generate = vi.fn().mockRejectedValueOnce(new Error('device busy'));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: true, generate, now, allowCloudFallback: false });
    expect(generate).toHaveBeenCalledTimes(1);
    expect(r.backend).toBe('heuristics-only');
    expect(r.bytesSent).toBe(0);
  });

  it('falls back to heuristics-only when every model call fails', async () => {
    const generate = vi.fn().mockRejectedValue(new Error('offline'));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: false, generate, now });
    expect(r.backend).toBe('heuristics-only');
    expect(r.note).toMatch(/offline/);
    expect(r.risk).toBe(analyzeLocal(PHISH).score.total);
  });

  it('falls back to heuristics-only when the model answer cannot be parsed', async () => {
    const generate = vi.fn(async () => ({ text: 'no json here', source: 'on-device' as const }));
    const r = await runQuickCheck(PHISH, { onDeviceAvailable: true, generate, now });
    expect(r.backend).toBe('heuristics-only');
    expect(r.note).toMatch(/parse/i);
  });

  it('returns a safe empty result for blank input without calling the model', async () => {
    const generate = vi.fn();
    const r = await runQuickCheck('   ', { onDeviceAvailable: true, generate, now });
    expect(generate).not.toHaveBeenCalled();
    expect(r.verdict).toBe('safe');
  });
});

describe('runDeepCheck()', () => {
  it('sends exactly the consented redacted text to the cloud', async () => {
    const local = analyzeLocal(PHISH);
    const generate = vi.fn(async () => ({ text: SCAM_VERDICT, source: 'cloud' as const }));
    const r = await runDeepCheck(PHISH, { generate, now });
    const [prompt, route] = generate.mock.calls[0] as unknown as [string, string];
    expect(route).toBe('deep');
    expect(prompt).toContain(local.redaction.text);
    expect(prompt).not.toContain('anna.k@gmail.com');
    expect(r.kind).toBe('deep');
    expect(r.backend).toBe('cloud-redacted');
  });
});

describe('toSegments()', () => {
  it('splits text into plain and highlighted pieces without losing characters', () => {
    const t = 'abc def ghi';
    const segs = toSegments(t, [
      { start: 4, end: 7, source: 'signal', label: 'x', why: 'y', severity: 'high' },
      { start: 5, end: 11, source: 'model', label: 'm', why: 'n', severity: 'medium' },
    ]);
    expect(segs.map((s) => s.text).join('')).toBe(t);
    expect(segs.filter((s) => s.highlights.length > 0).map((s) => s.text).join('')).toBe('def ghi');
  });
});
