import { CATEGORY_LABELS, stayedOnDeviceShare, type Backend, type CheckResult, type CommunityStats, type Verdict } from '@scamshield/core';

export function formatMs(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}

export function formatBytes(n: number): string {
  if (n === 0) return '0 bytes';
  if (n < 1000) return `${n} bytes`;
  return `${(n / 1000).toFixed(1)} kB`;
}

export const VERDICT_TITLE: Record<Verdict, string> = {
  scam: 'Scam',
  suspicious: 'Suspicious',
  safe: 'Looks safe',
};

export const BACKEND_TITLE: Record<Backend, string> = {
  'on-device': 'On-device Gemini Nano',
  'cloud-redacted': 'Cloud · redacted',
  'heuristics-only': 'Local checks only',
};

/** One-line provenance, e.g. "On-device Gemini Nano · 840 ms · 0 bytes sent". */
export function provenance(r: Pick<CheckResult, 'backend' | 'latencyMs' | 'bytesSent' | 'kind'>): string {
  const parts = [r.kind === 'deep' && r.backend === 'cloud-redacted' ? 'Deep check · cloud · redacted' : BACKEND_TITLE[r.backend], formatMs(r.latencyMs)];
  parts.push(`${formatBytes(r.bytesSent)} sent`);
  return parts.join(' · ');
}

export function categoryLabel(r: Pick<CheckResult, 'category' | 'verdict'>): string {
  return r.verdict === 'safe' ? 'No scam pattern found' : CATEGORY_LABELS[r.category];
}

/** Text for the screen-reader live region. */
export function announce(r: CheckResult): string {
  return `${VERDICT_TITLE[r.verdict]}. Risk ${r.risk} out of 100. ${categoryLabel(r)}. ${provenance(r)}.`;
}

/** "1,284 checks so far · 71% never left the device", or null before the first check. */
export function communityLine(s: CommunityStats | null): string | null {
  if (!s || s.checks <= 0) return null;
  const share = stayedOnDeviceShare(s) ?? 0;
  let pct = Math.round(share * 100);
  if (pct === 100 && share < 1) pct = 99;
  if (pct === 0 && share > 0) pct = 1;
  return `${s.checks.toLocaleString('en-US')} check${s.checks === 1 ? '' : 's'} so far · ${pct}% never left the device`;
}
