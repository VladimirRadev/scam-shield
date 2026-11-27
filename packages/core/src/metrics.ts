/**
 * Evaluation metrics for the labelled examples: precision / recall / F1, latency percentiles,
 * bytes sent off the device, and a Markdown block for the README.
 * Used by `npm run eval` (heuristics, Node) and by apps/web/eval.html (real models, browser).
 */
import type { Backend, Thresholds, Verdict } from './types';

export interface Prf {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  /** null when undefined (no positive prediction / no positive example). */
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export function prf(pairs: Iterable<{ actual: boolean; predicted: boolean }>): Prf {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const { actual, predicted } of pairs) {
    if (predicted && actual) tp++;
    else if (predicted) fp++;
    else if (actual) fn++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : null;
  const recall = tp + fn ? tp / (tp + fn) : null;
  const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  return { tp, fp, fn, tn, precision, recall, f1 };
}

export function median(values: readonly number[]): number | null {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/** Nearest-rank percentile (p in 0..100). */
export function percentile(values: readonly number[], p: number): number | null {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const rank = Math.min(s.length, Math.max(1, Math.ceil((p / 100) * s.length)));
  return s[rank - 1]!;
}

/** One example's outcome on one route. */
export interface EvalRow {
  id: string;
  label: 'scam' | 'legit';
  risk: number;
  verdict: Verdict;
  backend: Backend;
  latencyMs: number;
  bytesSent: number;
  note: string | null;
}

export type EvalRouteName = 'device' | 'cloud' | 'heuristics';

/** The backend each evaluation route is meant to use. */
export const EXPECTED_BACKEND: Record<EvalRouteName, Backend> = {
  device: 'on-device',
  cloud: 'cloud-redacted',
  heuristics: 'heuristics-only',
};

export interface RouteSummary {
  route: EvalRouteName;
  n: number;
  thresholds: Thresholds;
  /** Positive = risk >= suspicious threshold. */
  flagged: Prf;
  /** Positive = risk >= scam threshold. */
  scam: Prf;
  latencyMs: { median: number | null; p90: number | null };
  /** Average UTF-8 bytes that left the device per example. */
  avgBytesSent: number;
  /** How many examples each backend actually answered. */
  backends: Partial<Record<Backend, number>>;
  /** Examples answered by another backend than the route's (e.g. on-device model failed). */
  offRoute: number;
  /** Ids wrong under the "flagged" rule: missed scams and false alarms, in input order. */
  misclassified: string[];
}

export function summarizeRoute(route: EvalRouteName, rows: readonly EvalRow[], thresholds: Thresholds): RouteSummary {
  const isScam = (r: EvalRow) => r.label === 'scam';
  const backends: Partial<Record<Backend, number>> = {};
  for (const r of rows) backends[r.backend] = (backends[r.backend] ?? 0) + 1;
  const latencies = rows.map((r) => r.latencyMs);
  const med = median(latencies);
  const p90 = percentile(latencies, 90);
  return {
    route,
    n: rows.length,
    thresholds,
    flagged: prf(rows.map((r) => ({ actual: isScam(r), predicted: r.risk >= thresholds.suspicious }))),
    scam: prf(rows.map((r) => ({ actual: isScam(r), predicted: r.risk >= thresholds.scam }))),
    latencyMs: { median: med === null ? null : Math.round(med), p90: p90 === null ? null : Math.round(p90) },
    avgBytesSent: rows.length ? Math.round(rows.reduce((a, r) => a + r.bytesSent, 0) / rows.length) : 0,
    backends,
    offRoute: rows.filter((r) => r.backend !== EXPECTED_BACKEND[route]).length,
    misclassified: rows.filter((r) => isScam(r) !== r.risk >= thresholds.suspicious).map((r) => r.id),
  };
}

// ------------------------------------------------------------------ Markdown

export const pct = (x: number | null): string => (x === null ? 'n/a' : `${(x * 100).toFixed(1)}%`);
const ms = (x: number | null): string => (x === null ? 'n/a' : `${x.toLocaleString('en-US')} ms`);
const bytes = (n: number): string => (n === 0 ? '0 bytes' : n < 1000 ? `${n} bytes` : `${(n / 1000).toFixed(1)} kB`);

export const ROUTE_TITLES: Record<EvalRouteName, (model?: string) => string> = {
  device: () => 'Gemini Nano on device, raw text (ONLY_ON_DEVICE)',
  cloud: (model) => `Cloud, redacted text (ONLY_IN_CLOUD${model ? `, ${model}` : ''})`,
  heuristics: () => 'Heuristic layer only (no model)',
};

/** The P/R/F1 table, same columns as `npm run eval`. */
export function prfTable(s: Pick<RouteSummary, 'flagged' | 'scam' | 'thresholds'>): string[] {
  const line = (name: string, m: Prf) => `| ${name} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} |`;
  return [
    '| Positive when | TP | FP | FN | TN | Precision | Recall | F1 |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
    line(`flagged (risk >= ${s.thresholds.suspicious})`, s.flagged),
    line(`scam (risk >= ${s.thresholds.scam})`, s.scam),
  ];
}

/** README block for one route. */
export function routeMarkdown(s: RouteSummary, meta: { browser?: string; model?: string; date?: string } = {}): string {
  const where = [meta.browser, meta.date].filter(Boolean).join(', ');
  const backendList = Object.entries(s.backends)
    .map(([b, n]) => `${n} ${b}`)
    .join(', ');
  const lines = [
    `**${ROUTE_TITLES[s.route](meta.model)}**, ${s.n} examples${where ? ` (${where})` : ''}`,
    '',
    ...prfTable(s),
    '',
    `Latency per check: median ${ms(s.latencyMs.median)}, p90 ${ms(s.latencyMs.p90)} · average sent off the device: ${bytes(s.avgBytesSent)} · answered by: ${backendList || 'none'}`,
    '',
    s.misclassified.length ? `Misclassified (flagged rule): ${s.misclassified.map((id) => `\`${id}\``).join(', ')}` : 'No misclassified examples.',
  ];
  return lines.join('\n');
}
