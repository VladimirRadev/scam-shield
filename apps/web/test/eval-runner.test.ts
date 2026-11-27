import { describe, expect, it, vi } from 'vitest';
import type { CheckResult } from '@scamshield/core';
import { isRateLimited, runRoute } from '../src/eval-runner';

const examples = [
  { id: 'a', label: 'scam' as const, text: 'A' },
  { id: 'b', label: 'legit' as const, text: 'B' },
  { id: 'c', label: 'scam' as const, text: 'C' },
];

const result = (over: Partial<CheckResult> = {}) =>
  ({ risk: 80, verdict: 'scam', backend: 'cloud-redacted', latencyMs: 900, bytesSent: 2000, note: null, ...over }) as CheckResult;

describe('runRoute()', () => {
  it('runs the examples one after another and reports progress', async () => {
    let running = 0;
    let maxRunning = 0;
    const check = vi.fn(async (_text: string, _route: string) => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((r) => setTimeout(r, 2));
      running--;
      return result();
    });
    const progress: number[] = [];
    const rows = await runRoute({ route: 'cloud', examples, check, onProgress: (done) => progress.push(done), sleep: async () => undefined });
    expect(maxRunning).toBe(1);
    expect(check.mock.calls.map((c) => c[0])).toEqual(['A', 'B', 'C']);
    expect(check.mock.calls.every((c) => c[1] === 'cloud')).toBe(true);
    expect(progress).toEqual([1, 2, 3]);
    expect(rows.map((r) => [r.id, r.label, r.risk, r.backend, r.bytesSent])).toEqual([
      ['a', 'scam', 80, 'cloud-redacted', 2000],
      ['b', 'legit', 80, 'cloud-redacted', 2000],
      ['c', 'scam', 80, 'cloud-redacted', 2000],
    ]);
  });

  it('pauses between calls (cloud rate limits) but not after the last one', async () => {
    const sleep = vi.fn(async () => undefined);
    await runRoute({ route: 'cloud', examples, check: async () => result(), pauseMs: 4000, sleep });
    expect(sleep.mock.calls).toEqual([[4000], [4000]]);
  });

  it('retries a rate-limited cloud call and keeps the good answer', async () => {
    const sleep = vi.fn(async () => undefined);
    const check = vi
      .fn()
      .mockResolvedValueOnce(result({ backend: 'heuristics-only', bytesSent: 0, note: 'Model unavailable (AI: 429 Too Many Requests); showing the local heuristic check only.' }))
      .mockResolvedValue(result());
    const rows = await runRoute({ route: 'cloud', examples: examples.slice(0, 1), check, sleep, retryWaitMs: 20_000 });
    expect(check).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(20_000);
    expect(rows[0]!.backend).toBe('cloud-redacted');
  });

  it('stops when aborted and returns the finished rows', async () => {
    const ctrl = new AbortController();
    const rows = await runRoute({
      route: 'device',
      examples,
      check: async () => {
        ctrl.abort();
        return result({ backend: 'on-device', bytesSent: 0 });
      },
      signal: ctrl.signal,
      sleep: async () => undefined,
    });
    expect(rows).toHaveLength(1);
  });
});

describe('isRateLimited()', () => {
  it('recognises quota errors in a fallback note', () => {
    expect(isRateLimited(result({ backend: 'heuristics-only', note: 'Model unavailable (RESOURCE_EXHAUSTED: quota exceeded)' }))).toBe(true);
    expect(isRateLimited(result({ backend: 'heuristics-only', note: 'On-device model failed (InvalidStateError)' }))).toBe(false);
    expect(isRateLimited(result())).toBe(false);
  });
});
