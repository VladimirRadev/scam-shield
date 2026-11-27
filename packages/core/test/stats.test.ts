import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  addCheckToStats,
  categoryStatField,
  parseCommunityStats,
  STAT_FIELDS,
  statsFieldsFor,
  statsRouteFor,
  stayedOnDeviceShare,
} from '../src/stats';
import { CATEGORIES } from '../src/types';

const result = (over: Partial<Parameters<typeof statsFieldsFor>[0]> = {}) => ({
  backend: 'on-device' as const,
  bytesSent: 0,
  verdict: 'scam' as const,
  category: 'malware-task' as const,
  ...over,
});

describe('statsFieldsFor()', () => {
  it('names exactly four counters: the check, where the text went, the verdict and the category', () => {
    expect(statsFieldsFor(result())).toEqual(['checks', 'onDevice', 'verdict_scam', 'cat_malware_task']);
    expect(statsFieldsFor(result({ backend: 'cloud-redacted', bytesSent: 812, verdict: 'safe', category: 'none' }))).toEqual([
      'checks',
      'cloudRedacted',
      'verdict_safe',
      'cat_none',
    ]);
  });

  it('only ever returns known counter names (never text)', () => {
    for (const c of CATEGORIES) {
      for (const f of statsFieldsFor(result({ category: c }))) expect(STAT_FIELDS).toContain(f);
    }
  });

  it('counts a check by where the text went, not by the backend label', () => {
    expect(statsRouteFor({ backend: 'heuristics-only', bytesSent: 0 })).toBe('heuristicsOnly');
    // The cloud answered but could not be parsed: the redacted text still left the device.
    expect(statsRouteFor({ backend: 'heuristics-only', bytesSent: 900 })).toBe('cloudRedacted');
    expect(statsRouteFor({ backend: 'cloud-redacted', bytesSent: 900 })).toBe('cloudRedacted');
    expect(statsRouteFor({ backend: 'on-device', bytesSent: 0 })).toBe('onDevice');
  });
});

describe('STAT_FIELDS', () => {
  it('has one counter per category with Firestore-friendly names', () => {
    expect(STAT_FIELDS).toHaveLength(7 + CATEGORIES.length);
    expect(new Set(STAT_FIELDS).size).toBe(STAT_FIELDS.length);
    for (const f of STAT_FIELDS) expect(f).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/);
    expect(categoryStatField('fake-recruiter')).toBe('cat_fake_recruiter');
  });

  it('matches the counter list and per-field checks in firestore.rules', () => {
    const rules = readFileSync(new URL('../../../firestore.rules', import.meta.url), 'utf8');
    const list = /function counters\(\)\s*\{\s*return\s*\[([^\]]*)\]/.exec(rules)?.[1] ?? '';
    const inRules = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
    expect(inRules).toEqual([...STAT_FIELDS]);
    for (const f of STAT_FIELDS) {
      expect(rules).toContain(`bumped(changed, '${f}')`);
      expect(rules).toContain(`zeroOrOne('${f}')`);
    }
  });
});

describe('community stats', () => {
  it('parses the stats document defensively', () => {
    expect(parseCommunityStats(null)).toBeNull();
    expect(parseCommunityStats({})).toBeNull();
    expect(parseCommunityStats({ checks: 'lots' })).toBeNull();
    expect(parseCommunityStats({ checks: 10, onDevice: 6, heuristicsOnly: 1 })).toEqual({
      checks: 10,
      onDevice: 6,
      cloudRedacted: 0,
      heuristicsOnly: 1,
    });
  });

  it('computes the share of checks whose text never left the device', () => {
    expect(stayedOnDeviceShare({ checks: 1284, onDevice: 800, cloudRedacted: 372, heuristicsOnly: 112 })).toBeCloseTo(912 / 1284);
    expect(stayedOnDeviceShare({ checks: 0, onDevice: 0, cloudRedacted: 0, heuristicsOnly: 0 })).toBeNull();
  });

  it('adds one finished check to the numbers on screen', () => {
    expect(addCheckToStats(null, result())).toEqual({ checks: 1, onDevice: 1, cloudRedacted: 0, heuristicsOnly: 0 });
    expect(addCheckToStats({ checks: 4, onDevice: 1, cloudRedacted: 2, heuristicsOnly: 1 }, result({ backend: 'cloud-redacted', bytesSent: 10 }))).toEqual({
      checks: 5,
      onDevice: 1,
      cloudRedacted: 3,
      heuristicsOnly: 1,
    });
  });
});
