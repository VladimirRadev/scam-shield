import { describe, expect, it } from 'vitest';
import { median, percentile, prf, routeMarkdown, summarizeRoute, type EvalRow } from '../src/metrics';

const row = (id: string, label: 'scam' | 'legit', risk: number, over: Partial<EvalRow> = {}): EvalRow => ({
  id,
  label,
  risk,
  verdict: risk >= 70 ? 'scam' : risk >= 40 ? 'suspicious' : 'safe',
  backend: 'on-device',
  latencyMs: 100,
  bytesSent: 0,
  note: null,
  ...over,
});

describe('prf()', () => {
  it('computes precision, recall and F1 from predictions', () => {
    const m = prf([
      { actual: true, predicted: true },
      { actual: true, predicted: true },
      { actual: true, predicted: false },
      { actual: false, predicted: true },
      { actual: false, predicted: false },
    ]);
    expect(m).toMatchObject({ tp: 2, fp: 1, fn: 1, tn: 1 });
    expect(m.precision).toBeCloseTo(2 / 3);
    expect(m.recall).toBeCloseTo(2 / 3);
    expect(m.f1).toBeCloseTo(2 / 3);
  });

  it('returns null instead of NaN when a ratio is undefined', () => {
    const m = prf([{ actual: false, predicted: false }]);
    expect(m.precision).toBeNull();
    expect(m.recall).toBeNull();
    expect(m.f1).toBeNull();
  });
});

describe('median() and percentile()', () => {
  it('uses the middle value, or the mean of the two middle values', () => {
    expect(median([5, 1, 3])).toBe(3);
    expect(median([4, 1, 3, 2])).toBe(2.5);
    expect(median([])).toBeNull();
  });

  it('uses nearest-rank percentiles', () => {
    const ten = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    expect(percentile(ten, 90)).toBe(90);
    expect(percentile(ten, 100)).toBe(100);
    expect(percentile([7], 90)).toBe(7);
    expect(percentile([], 90)).toBeNull();
  });
});

describe('summarizeRoute()', () => {
  const rows: EvalRow[] = [
    row('s1', 'scam', 90, { latencyMs: 100 }),
    row('s2', 'scam', 50, { latencyMs: 300 }),
    row('s3', 'scam', 10, { latencyMs: 200 }),
    row('l1', 'legit', 5, { latencyMs: 400 }),
    row('l2', 'legit', 45, { latencyMs: 500, backend: 'heuristics-only', note: 'On-device model failed' }),
  ];
  const s = summarizeRoute('device', rows, { scam: 70, suspicious: 40 });

  it('scores "flagged" (suspicious or worse) and "scam" separately', () => {
    expect(s.flagged).toMatchObject({ tp: 2, fp: 1, fn: 1, tn: 1 });
    expect(s.scam).toMatchObject({ tp: 1, fp: 0, fn: 2, tn: 2 });
    expect(s.scam.precision).toBe(1);
  });

  it('reports latency, bytes, backends and misclassified ids', () => {
    expect(s.n).toBe(5);
    expect(s.latencyMs).toEqual({ median: 300, p90: 500 });
    expect(s.avgBytesSent).toBe(0);
    expect(s.backends).toEqual({ 'on-device': 4, 'heuristics-only': 1 });
    expect(s.offRoute).toBe(1);
    expect(s.misclassified).toEqual(['s3', 'l2']);
  });

  it('averages the bytes that left the device', () => {
    const cloud = summarizeRoute('cloud', [row('a', 'scam', 80, { backend: 'cloud-redacted', bytesSent: 2000 }), row('b', 'legit', 0, { backend: 'cloud-redacted', bytesSent: 1000 })], {
      scam: 70,
      suspicious: 40,
    });
    expect(cloud.avgBytesSent).toBe(1500);
    expect(cloud.offRoute).toBe(0);
  });
});

describe('routeMarkdown()', () => {
  it('renders a README-ready block in the format of the heuristic table', () => {
    const md = routeMarkdown(summarizeRoute('cloud', [row('a', 'scam', 80, { backend: 'cloud-redacted', bytesSent: 2100, latencyMs: 1234 }), row('b', 'legit', 0, { backend: 'cloud-redacted', bytesSent: 1900, latencyMs: 900 })], { scam: 70, suspicious: 40 }), {
      browser: 'Chrome 142',
      model: 'gemini-3.5-flash-lite',
    });
    expect(md).toContain('| Positive when | TP | FP | FN | TN | Precision | Recall | F1 |');
    expect(md).toContain('| flagged (risk >= 40) | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 100.0% |');
    expect(md).toContain('Cloud, redacted text (ONLY_IN_CLOUD, gemini-3.5-flash-lite)');
    expect(md).toContain('median 1,067 ms');
    expect(md).toContain('2.0 kB');
    expect(md).toContain('No misclassified examples.');
  });
});
