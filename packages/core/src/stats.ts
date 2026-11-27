/**
 * Anonymous community statistics: which counters one finished check increments.
 *
 * Only these counter names ever reach Firestore (document `stats/global`), each incremented
 * by exactly 1. No message text, quote, URL or user id is ever written. `firestore.rules`
 * repeats the same list, and a test keeps the two in sync.
 */
import { CATEGORIES, type Backend, type Category, type CheckResult } from './types';

export type StatsRoute = 'onDevice' | 'cloudRedacted' | 'heuristicsOnly';

export const STAT_ROUTE_FIELDS: readonly StatsRoute[] = ['onDevice', 'cloudRedacted', 'heuristicsOnly'];
export const STAT_VERDICT_FIELDS = ['verdict_scam', 'verdict_suspicious', 'verdict_safe'] as const;

/** Firestore field name of a category counter, e.g. `fake-recruiter` -> `cat_fake_recruiter`. */
export const categoryStatField = (c: Category): string => `cat_${c.replace(/-/g, '_')}`;

/** Every counter field of `stats/global`, in the order `firestore.rules` lists them. */
export const STAT_FIELDS: readonly string[] = ['checks', ...STAT_ROUTE_FIELDS, ...STAT_VERDICT_FIELDS, ...CATEGORIES.map(categoryStatField)];

type StatsInput = Pick<CheckResult, 'verdict' | 'category' | 'bytesSent'> & { backend: Backend };

/** Where the text of this check went: any uploaded byte counts as the (redacted) cloud route. */
export function statsRouteFor(r: Pick<StatsInput, 'backend' | 'bytesSent'>): StatsRoute {
  if (r.bytesSent > 0 || r.backend === 'cloud-redacted') return 'cloudRedacted';
  return r.backend === 'on-device' ? 'onDevice' : 'heuristicsOnly';
}

/** The four counters one finished check increments by 1. */
export function statsFieldsFor(r: StatsInput): string[] {
  return ['checks', statsRouteFor(r), `verdict_${r.verdict}`, categoryStatField(r.category)];
}

/** The part of `stats/global` the UI shows. */
export interface CommunityStats {
  checks: number;
  onDevice: number;
  cloudRedacted: number;
  heuristicsOnly: number;
}

const count = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);

/** Read the stats document defensively; null when it is missing or empty. */
export function parseCommunityStats(data: unknown): CommunityStats | null {
  if (!data || typeof data !== 'object') return null;
  const d = data as Record<string, unknown>;
  const checks = count(d.checks);
  if (checks === 0) return null;
  return { checks, onDevice: count(d.onDevice), cloudRedacted: count(d.cloudRedacted), heuristicsOnly: count(d.heuristicsOnly) };
}

/** Share (0..1) of checks whose text never left the device, or null without checks. */
export function stayedOnDeviceShare(s: CommunityStats): number | null {
  if (s.checks <= 0) return null;
  return Math.min(1, (s.onDevice + s.heuristicsOnly) / s.checks);
}

/** The numbers on screen after one more finished check (no need to read Firestore again). */
export function addCheckToStats(s: CommunityStats | null, r: StatsInput): CommunityStats {
  const next: CommunityStats = s ? { ...s } : { checks: 0, onDevice: 0, cloudRedacted: 0, heuristicsOnly: 0 };
  next.checks += 1;
  next[statsRouteFor(r)] += 1;
  return next;
}
