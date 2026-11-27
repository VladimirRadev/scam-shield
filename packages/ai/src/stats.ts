/**
 * Anonymous community statistics in Firestore: one document, `stats/global`, with counters.
 *
 * A finished check increments four counters by 1 (`checks`, where the text went, the verdict
 * and the category). Only counter names and `increment(1)` are written: no message text, quote,
 * URL or user id. `firestore.rules` enforces the same shape on the server.
 *
 * Firestore Lite (plain REST calls, no offline cache or listeners) is loaded lazily, after
 * anonymous sign-in, and every error is swallowed: statistics never block or slow down a check.
 */
import type { Firestore } from 'firebase/firestore/lite';
import { parseCommunityStats, statsFieldsFor, type CheckResult, type CommunityStats } from '@scamshield/core';

export type StatsCheck = Pick<CheckResult, 'backend' | 'bytesSent' | 'verdict' | 'category'>;

export const STATS_COLLECTION = 'stats';
export const STATS_DOC_ID = 'global';

/** The write for one check: `{ checks: inc(1), onDevice: inc(1), verdict_scam: inc(1), cat_phishing: inc(1) }`. */
export function statsPayload<T>(r: StatsCheck, inc: (n: number) => T): Record<string, T> {
  return Object.fromEntries(statsFieldsFor(r).map((f) => [f, inc(1)]));
}

/** Increment the counters of one finished check (creates `stats/global` on the first check). */
export async function writeCheckStats(db: Firestore, r: StatsCheck): Promise<void> {
  const { doc, increment, setDoc } = await import('firebase/firestore/lite');
  await setDoc(doc(db, STATS_COLLECTION, STATS_DOC_ID), statsPayload(r, increment), { merge: true });
}

export const NO_CHECKS_YET: CommunityStats = { checks: 0, onDevice: 0, cloudRedacted: 0, heuristicsOnly: 0 };

/** Read the community totals; all zero when the document does not exist yet. */
export async function readCommunityStats(db: Firestore): Promise<CommunityStats> {
  const { doc, getDoc } = await import('firebase/firestore/lite');
  const snap = await getDoc(doc(db, STATS_COLLECTION, STATS_DOC_ID));
  return (snap.exists() ? parseCommunityStats(snap.data()) : null) ?? { ...NO_CHECKS_YET };
}

export interface StatsClient {
  /** Fire and forget. Never throws, never blocks. */
  record(r: StatsCheck): void;
  /** Community totals (zeros before the first check), or null when signed out, offline or denied. */
  read(): Promise<CommunityStats | null>;
}

export interface StatsClientDeps {
  /** Resolves with the anonymous user, or null when sign-in failed. */
  user: Promise<unknown>;
  firestore: () => Promise<Firestore>;
  write?: (db: Firestore, r: StatsCheck) => Promise<void>;
  read?: (db: Firestore) => Promise<CommunityStats>;
}

export function createStatsClient(deps: StatsClientDeps): StatsClient {
  const write = deps.write ?? writeCheckStats;
  const read = deps.read ?? readCommunityStats;
  return {
    record(r) {
      void deps.user
        .then(async (u) => {
          if (u) await write(await deps.firestore(), r);
        })
        .catch((e: unknown) => console.debug('[scam-shield] community stats not recorded', e));
    },
    async read() {
      try {
        if (!(await deps.user)) return null;
        return await read(await deps.firestore());
      } catch (e) {
        console.debug('[scam-shield] community stats not available', e);
        return null;
      }
    },
  };
}
