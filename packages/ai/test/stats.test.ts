import { describe, expect, it, vi } from 'vitest';
import { STAT_FIELDS } from '@scamshield/core';
import { createStatsClient, statsPayload } from '../src/stats';

const check = { backend: 'on-device' as const, bytesSent: 0, verdict: 'scam' as const, category: 'wallet-drainer' as const };
const db = {} as never;
const flush = () => new Promise((r) => setTimeout(r, 0));

describe('statsPayload()', () => {
  it('maps the four counters of a check to one increment each, and nothing else', () => {
    const inc = (n: number) => ({ inc: n });
    const p = statsPayload(check, inc);
    expect(p).toEqual({ checks: { inc: 1 }, onDevice: { inc: 1 }, verdict_scam: { inc: 1 }, cat_wallet_drainer: { inc: 1 } });
    for (const k of Object.keys(p)) expect(STAT_FIELDS).toContain(k);
  });
});

describe('createStatsClient()', () => {
  it('writes after anonymous sign-in', async () => {
    const write = vi.fn(async () => undefined);
    const client = createStatsClient({ user: Promise.resolve({ uid: 'u' }), firestore: async () => db, write, read: vi.fn() });
    client.record(check);
    await flush();
    expect(write).toHaveBeenCalledWith(db, check);
  });

  it('does not write when sign-in failed, and never throws', async () => {
    const write = vi.fn(async () => undefined);
    const client = createStatsClient({ user: Promise.resolve(null), firestore: async () => db, write, read: vi.fn() });
    client.record(check);
    await flush();
    expect(write).not.toHaveBeenCalled();
    expect(await client.read()).toBeNull();
  });

  it('swallows write and read errors (statistics never block a check)', async () => {
    const warn = vi.spyOn(console, 'debug').mockImplementation(() => undefined);
    const client = createStatsClient({
      user: Promise.resolve({ uid: 'u' }),
      firestore: async () => db,
      write: async () => {
        throw new Error('permission-denied');
      },
      read: async () => {
        throw new Error('offline');
      },
    });
    expect(() => client.record(check)).not.toThrow();
    await flush();
    expect(await client.read()).toBeNull();
    warn.mockRestore();
  });

  it('reads the community totals', async () => {
    const stats = { checks: 3, onDevice: 2, cloudRedacted: 1, heuristicsOnly: 0 };
    const client = createStatsClient({ user: Promise.resolve({ uid: 'u' }), firestore: async () => db, write: vi.fn(), read: async () => stats });
    expect(await client.read()).toEqual(stats);
  });
});
