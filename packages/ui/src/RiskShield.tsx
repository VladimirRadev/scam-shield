import { useEffect, useId, useState } from 'react';
import type { Verdict } from '@scamshield/core';
import { SHIELD_PATH } from './icons';

interface Props {
  risk: number | null;
  verdict: Verdict | null;
  size?: number;
  busy?: boolean;
}

/** The risk gauge: a shield that fills from the bottom with the verdict colour. */
export function RiskShield({ risk, verdict, size = 168, busy = false }: Props) {
  const id = useId().replace(/:/g, '');
  const pct = risk === null ? 0 : Math.max(0, Math.min(100, risk));
  // Shield interior spans y = 4..112 in the viewBox.
  const target = 112 - (108 * pct) / 100;
  // Start empty and animate up to the target on the next frame.
  const [fillTop, setFillTop] = useState(116);
  useEffect(() => {
    const raf = requestAnimationFrame(() => setFillTop(target));
    return () => cancelAnimationFrame(raf);
  }, [target]);
  const tone = verdict ?? 'idle';
  return (
    <figure className={`ss-shield ss-tone-${tone}${busy ? ' is-busy' : ''}`} style={{ width: size }} aria-hidden={risk === null}>
      <svg viewBox="0 0 100 116" width={size} height={(size * 116) / 100} role="img" aria-label={risk === null ? 'No result yet' : `Risk ${pct} out of 100`}>
        <defs>
          <clipPath id={`clip-${id}`}>
            <path d={SHIELD_PATH} />
          </clipPath>
          <linearGradient id={`g-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="var(--tone)" stopOpacity="0.95" />
            <stop offset="1" stopColor="var(--tone)" stopOpacity="0.7" />
          </linearGradient>
        </defs>
        <path d={SHIELD_PATH} className="ss-shield-bg" />
        <g clipPath={`url(#clip-${id})`}>
          <rect className="ss-shield-fill" x="0" y="0" width="100" height="116" fill={`url(#g-${id})`} style={{ transform: `translateY(${fillTop}px)` }} />
          {busy && <rect className="ss-shield-scan" x="0" y="0" width="100" height="10" />}
        </g>
        <path d={SHIELD_PATH} className="ss-shield-outline" />
      </svg>
      <figcaption className="ss-shield-label">
        <span className="ss-shield-num">{risk === null ? (busy ? '…' : '—') : pct}</span>
        <span className="ss-shield-cap">risk</span>
      </figcaption>
    </figure>
  );
}
