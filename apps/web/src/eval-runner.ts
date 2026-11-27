/**
 * Sequential evaluation of the labelled examples on one fixed route (see eval.tsx).
 * Pure orchestration: the check function is injected, so this runs in tests without a browser.
 */
import type { CheckResult, EvalRouteName, EvalRow, Example } from '@scamshield/core';

const RATE_LIMIT_RE = /\b429\b|quota|rate.?limit|resource.?exhausted|too many requests/i;

/** True when the engine fell back to heuristics because the cloud model was rate limited. */
export function isRateLimited(r: Pick<CheckResult, 'backend' | 'note'>): boolean {
  return r.backend === 'heuristics-only' && RATE_LIMIT_RE.test(r.note ?? '');
}

export interface RunRouteOptions {
  route: EvalRouteName;
  examples: ReadonlyArray<Pick<Example, 'id' | 'label' | 'text'>>;
  check: (text: string, route: EvalRouteName) => Promise<CheckResult>;
  onProgress?: (done: number, total: number, row: EvalRow) => void;
  /** Wait between two calls (the free cloud tier allows a limited number of requests per minute). */
  pauseMs?: number;
  /** Wait before retrying a rate-limited call. */
  retryWaitMs?: number;
  maxRetries?: number;
  signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function runRoute(opts: RunRouteOptions): Promise<EvalRow[]> {
  const { route, examples, check, onProgress, pauseMs = 0, retryWaitMs = 20_000, maxRetries = 2, signal } = opts;
  const sleep = opts.sleep ?? defaultSleep;
  const rows: EvalRow[] = [];
  for (let i = 0; i < examples.length; i++) {
    if (signal?.aborted) break;
    const ex = examples[i]!;
    let r = await check(ex.text, route);
    for (let attempt = 0; attempt < maxRetries && isRateLimited(r) && !signal?.aborted; attempt++) {
      await sleep(retryWaitMs);
      r = await check(ex.text, route);
    }
    const row: EvalRow = {
      id: ex.id,
      label: ex.label,
      risk: r.risk,
      verdict: r.verdict,
      backend: r.backend,
      latencyMs: r.latencyMs,
      bytesSent: r.bytesSent,
      note: r.note,
    };
    rows.push(row);
    onProgress?.(rows.length, examples.length, row);
    if (pauseMs > 0 && i < examples.length - 1 && !signal?.aborted) await sleep(pauseMs);
  }
  return rows;
}
