import { describe, expect, it } from 'vitest';
import { badgeFor, badgeTabFor } from '../src/badge';

describe('badgeFor()', () => {
  it('shows the risk in the verdict colour', () => {
    expect(badgeFor('scam', 92)).toEqual({ text: '92', color: '#cf1f2c', title: 'Scam Shield: Scam (risk 92/100)' });
    expect(badgeFor('suspicious', 55).color).toBe('#b86a00');
    expect(badgeFor('safe', 8).text).toBe('OK');
  });
});

describe('badgeTabFor()', () => {
  it('puts the badge on the tab the checked text came from', () => {
    expect(badgeTabFor([{ tabId: 7, text: 'page text' }], 'page text')).toBe(7);
  });

  it('puts no badge anywhere for typed text or an example (no source tab)', () => {
    expect(badgeTabFor([], 'typed by the user')).toBeUndefined();
  });

  it('puts no badge on the scanned tab for a different text (edited, or an older queued check)', () => {
    expect(badgeTabFor([{ tabId: 7, text: 'page text' }], 'page text, edited')).toBeUndefined();
  });

  it('a queued check of tab A still badges tab A after tab B was scanned', () => {
    const sources = [
      { tabId: 1, text: 'page A' },
      { tabId: 2, text: 'page B' },
    ];
    expect(badgeTabFor(sources, 'page A')).toBe(1);
    expect(badgeTabFor(sources, 'page B')).toBe(2);
  });
});
