import { describe, expect, it } from 'vitest';
import { badgeFor } from '../src/badge';

describe('badgeFor()', () => {
  it('shows the risk in the verdict colour', () => {
    expect(badgeFor('scam', 92)).toEqual({ text: '92', color: '#cf1f2c', title: 'Scam Shield: Scam (risk 92/100)' });
    expect(badgeFor('suspicious', 55).color).toBe('#b86a00');
    expect(badgeFor('safe', 8).text).toBe('OK');
  });
});
