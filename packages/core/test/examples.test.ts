import { describe, expect, it } from 'vitest';
import { EXAMPLES } from '../src/examples';
import { CATEGORIES } from '../src/types';
import { analyzeLocal, verdictFor } from '../src/engine';

describe('examples.json', () => {
  it('has enough labelled scams and legitimate look-alikes', () => {
    expect(EXAMPLES.length).toBeGreaterThanOrEqual(44);
    expect(EXAMPLES.filter((e) => e.label === 'scam').length).toBeGreaterThanOrEqual(26);
    expect(EXAMPLES.filter((e) => e.label === 'legit').length).toBeGreaterThanOrEqual(18);
  });

  it('has unique ids, known categories and non-empty text', () => {
    const ids = new Set(EXAMPLES.map((e) => e.id));
    expect(ids.size).toBe(EXAMPLES.length);
    for (const e of EXAMPLES) {
      expect(CATEGORIES).toContain(e.category);
      expect(e.text.length).toBeGreaterThan(40);
      expect(e.title.length).toBeLessThanOrEqual(32);
      expect(e.label === 'legit' ? e.category === 'none' : e.category !== 'none').toBe(true);
    }
  });

  it('covers every scam family', () => {
    const covered = new Set(EXAMPLES.filter((e) => e.label === 'scam').map((e) => e.category));
    for (const c of CATEGORIES.filter((c) => c !== 'none')) expect(covered).toContain(c);
  });

  it('the heuristic layer never calls a legitimate example a scam', () => {
    for (const e of EXAMPLES.filter((x) => x.label === 'legit')) {
      expect(verdictFor(analyzeLocal(e.text).score.total), e.id).not.toBe('scam');
    }
  });
});
