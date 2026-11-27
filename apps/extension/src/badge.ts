import type { Verdict } from '@scamshield/core';

export const BADGE_COLORS: Record<Verdict, string> = {
  scam: '#cf1f2c',
  suspicious: '#b86a00',
  safe: '#0d8457',
};

/** Toolbar badge for a verdict: the risk number in the verdict colour ("OK" when safe). */
export function badgeFor(verdict: Verdict, risk: number): { text: string; color: string; title: string } {
  const label = verdict === 'scam' ? 'Scam' : verdict === 'suspicious' ? 'Suspicious' : 'Looks safe';
  return {
    text: verdict === 'safe' ? 'OK' : String(Math.round(risk)),
    color: BADGE_COLORS[verdict],
    title: `Scam Shield: ${label} (risk ${Math.round(risk)}/100)`,
  };
}
