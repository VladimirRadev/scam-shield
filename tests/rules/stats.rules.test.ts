/**
 * Firestore security rules for stats/global, run against the Firestore emulator:
 *
 *   npm run test:rules        (needs Java 21+; starts and stops the emulator)
 */
import { readFileSync } from 'node:fs';
import { assertFails, assertSucceeds, initializeTestEnvironment, type RulesTestEnvironment } from '@firebase/rules-unit-testing';
import { collection, deleteDoc, doc, getDoc, getDocs, increment, setDoc, updateDoc, type Firestore } from 'firebase/firestore';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { readCommunityStats, writeCheckStats, type StatsCheck } from '../../packages/ai/src/stats';

let env: RulesTestEnvironment;

const onDeviceScam: StatsCheck = { backend: 'on-device', bytesSent: 0, verdict: 'scam', category: 'malware-task' };
const cloudSafe: StatsCheck = { backend: 'cloud-redacted', bytesSent: 900, verdict: 'safe', category: 'none' };

const anon = () => env.authenticatedContext('anon-user', { firebase: { sign_in_provider: 'anonymous' } }).firestore() as unknown as Firestore;
const nobody = () => env.unauthenticatedContext().firestore() as unknown as Firestore;
const statsRef = (db: Firestore) => doc(db, 'stats', 'global');

async function seed(data: Record<string, number>) {
  await env.withSecurityRulesDisabled(async (ctx) => {
    await setDoc(doc(ctx.firestore() as unknown as Firestore, 'stats', 'global'), data);
  });
}

beforeAll(async () => {
  const [host, port] = (process.env.FIRESTORE_EMULATOR_HOST ?? '127.0.0.1:8180').split(':');
  env = await initializeTestEnvironment({
    projectId: 'demo-scamshield',
    firestore: { host, port: Number(port), rules: readFileSync(new URL('../../firestore.rules', import.meta.url), 'utf8') },
  });
});

afterAll(async () => {
  await env?.cleanup();
});

beforeEach(async () => {
  await env.clearFirestore();
});

describe('stats/global reads', () => {
  it('lets a signed-in (anonymous) user read the totals, also before the document exists', async () => {
    await assertSucceeds(getDoc(statsRef(anon())));
    expect(await readCommunityStats(anon())).toEqual({ checks: 0, onDevice: 0, cloudRedacted: 0, heuristicsOnly: 0 });
  });

  it('denies reads without sign-in, and listing the collection', async () => {
    await assertFails(getDoc(statsRef(nobody())));
    await assertFails(getDocs(collection(anon(), 'stats')));
  });
});

describe('stats/global create', () => {
  it('lets the first check create the document with its four counters at 1', async () => {
    await assertSucceeds(writeCheckStats(anon(), onDeviceScam));
    expect(await readCommunityStats(anon())).toEqual({ checks: 1, onDevice: 1, cloudRedacted: 0, heuristicsOnly: 0 });
  });

  it('denies a create without sign-in, with text, or with counters above 1', async () => {
    await assertFails(writeCheckStats(nobody(), onDeviceScam));
    await assertFails(setDoc(statsRef(anon()), { checks: 1, text: 'Hi Elena, clone our repo' }));
    await assertFails(setDoc(statsRef(anon()), { checks: 1, uid: 'anon-user' }));
    await assertFails(setDoc(statsRef(anon()), { checks: 5 }));
    await assertFails(setDoc(statsRef(anon()), { checks: 1, onDevice: 2 }));
    await assertFails(setDoc(statsRef(anon()), { checks: 1, onDevice: '1' }));
    await assertFails(setDoc(statsRef(anon()), { onDevice: 1 }));
  });
});

describe('stats/global update', () => {
  beforeEach(() => seed({ checks: 10, onDevice: 7, cloudRedacted: 3, verdict_scam: 4, verdict_safe: 6, cat_malware_task: 4, cat_none: 6 }));

  it('lets a check add exactly 1 to checks, one route, one verdict and one category', async () => {
    await assertSucceeds(writeCheckStats(anon(), onDeviceScam));
    await assertSucceeds(writeCheckStats(anon(), cloudSafe));
    // A first-time counter (heuristicsOnly, verdict_suspicious, cat_phishing) starts at 1.
    await assertSucceeds(writeCheckStats(anon(), { backend: 'heuristics-only', bytesSent: 0, verdict: 'suspicious', category: 'phishing' }));
    expect(await readCommunityStats(anon())).toEqual({ checks: 13, onDevice: 8, cloudRedacted: 4, heuristicsOnly: 1 });
  });

  it('denies jumps, decrements, resets and partial updates', async () => {
    const db = anon();
    await assertFails(updateDoc(statsRef(db), { checks: increment(2), onDevice: increment(1), verdict_scam: increment(1), cat_malware_task: increment(1) }));
    await assertFails(updateDoc(statsRef(db), { checks: increment(-1), onDevice: increment(-1), verdict_scam: increment(-1), cat_malware_task: increment(-1) }));
    await assertFails(updateDoc(statsRef(db), { checks: 0, onDevice: 0, verdict_scam: 0, cat_malware_task: 0 }));
    await assertFails(updateDoc(statsRef(db), { checks: 1000, onDevice: 8, verdict_scam: 5, cat_malware_task: 5 }));
    await assertFails(updateDoc(statsRef(db), { checks: increment(1) }));
    await assertFails(updateDoc(statsRef(db), { onDevice: increment(1), verdict_scam: increment(1), cat_malware_task: increment(1), cat_none: increment(1) }));
  });

  it('denies two routes or two verdicts in one check', async () => {
    const db = anon();
    await assertFails(updateDoc(statsRef(db), { checks: increment(1), onDevice: increment(1), cloudRedacted: increment(1), verdict_scam: increment(1) }));
    await assertFails(updateDoc(statsRef(db), { checks: increment(1), onDevice: increment(1), verdict_scam: increment(1), verdict_safe: increment(1) }));
  });

  it('denies any non-counter field, so no text, URL or user id can be stored', async () => {
    const db = anon();
    await assertFails(
      updateDoc(statsRef(db), { checks: increment(1), onDevice: increment(1), verdict_scam: increment(1), lastText: 'Verify your password at https://secure-paypa1.com' }),
    );
    await assertFails(setDoc(statsRef(db), { checks: increment(1), onDevice: increment(1), verdict_scam: increment(1), cat_x: increment(1) }, { merge: true }));
  });

  it('denies updates without sign-in and any delete', async () => {
    await assertFails(writeCheckStats(nobody(), onDeviceScam));
    await assertFails(deleteDoc(statsRef(anon())));
  });
});

describe('everything else', () => {
  it('denies reads and writes outside stats/global', async () => {
    const db = anon();
    await assertFails(getDoc(doc(db, 'stats', 'other')));
    await assertFails(setDoc(doc(db, 'stats', 'other'), { checks: 1 }));
    await assertFails(setDoc(doc(db, 'checks', 'abc'), { text: 'raw message' }));
    await assertFails(getDoc(doc(db, 'users', 'anon-user')));
  });
});
