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

/** The tab a text came from (context menu or "Scan this page"), together with that text. */
export interface BadgeSource {
  tabId: number;
  text: string;
}

/**
 * The tab whose toolbar badge shows this result, or undefined for none. Only a text that really
 * came from a tab may set that tab's badge: typed text, an example or an edited page text never
 * paints a badge. `sources` lists the recent page texts, newest last (a queued check of tab A
 * that finishes after tab B was scanned still finds tab A).
 */
export function badgeTabFor(sources: readonly BadgeSource[], checkedText: string): number | undefined {
  for (let i = sources.length - 1; i >= 0; i--) if (sources[i]!.text === checkedText) return sources[i]!.tabId;
  return undefined;
}
