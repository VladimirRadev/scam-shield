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

/** The redacted text went to the cloud, but no usable answer came back (error, blocked or unparseable). */
const cloudWithoutAnswer = (r: Pick<CheckResult, 'backend' | 'bytesSent'>) => r.backend === 'heuristics-only' && r.bytesSent > 0;

/** One-line provenance, e.g. "On-device Gemini Nano · 840 ms · 0 bytes sent". */
export function provenance(r: Pick<CheckResult, 'backend' | 'latencyMs' | 'bytesSent' | 'kind'>): string {
  const title =
    r.kind === 'deep' && r.backend === 'cloud-redacted'
      ? 'Deep check · cloud · redacted'
      : cloudWithoutAnswer(r)
        ? 'Local checks · no usable cloud answer'
        : BACKEND_TITLE[r.backend];
  return [title, formatMs(r.latencyMs), `${formatBytes(r.bytesSent)} sent`].join(' · ');
}

export interface DataPathStep {
  key: 'local' | 'device' | 'cloud';
  on: boolean;
  title: string;
  detail: string;
}

/**
 * The privacy story of one check: which of the three stages ran. The cloud stage is decided by
 * `bytesSent`, never by the backend alone, so a failed cloud call never reads "nothing sent".
 */
export function dataPathSteps(r: Pick<CheckResult, 'backend' | 'latencyMs' | 'bytesSent' | 'signals' | 'redaction'>): DataPathStep[] {
  const masked = r.redaction.redactions.length;
  const signs = r.signals.length;
  const device = r.backend === 'on-device';
  const sent = r.bytesSent > 0;
  return [
    {
      key: 'local',
      on: true,
      title: 'Local checks',
      detail: `${signs} sign${signs === 1 ? '' : 's'} · ${masked} personal detail${masked === 1 ? '' : 's'} masked`,
    },
    { key: 'device', on: device, title: 'Gemini Nano on device', detail: device ? `${formatMs(r.latencyMs)} · raw text stayed here` : 'not used' },
    {
      key: 'cloud',
      on: sent,
      title: 'Cloud model',
      detail: !sent ? 'nothing sent' : `redacted only · ${formatBytes(r.bytesSent)}${cloudWithoutAnswer(r) ? ' · no usable answer' : ''}`,
    },
  ];
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
