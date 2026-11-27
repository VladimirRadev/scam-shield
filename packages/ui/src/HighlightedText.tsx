import { useMemo } from 'react';
import { toSegments, type Highlight } from '@scamshield/core';

interface Props {
  text: string;
  highlights: Highlight[];
  maxChars?: number;
}

const rank = { high: 3, medium: 2, low: 1 } as const;

/** The user's ORIGINAL text with every flagged span marked; hover or focus a mark to see why. */
export function HighlightedText({ text, highlights, maxChars = 6000 }: Props) {
  const shown = text.length > maxChars ? text.slice(0, maxChars) : text;
  const segments = useMemo(() => toSegments(shown, highlights.filter((h) => h.start < shown.length)), [shown, highlights]);
  return (
    <div className="ss-original" aria-label="Your text with warning signs highlighted">
      {segments.map((seg) => {
        if (!seg.highlights.length) return <span key={seg.start}>{seg.text}</span>;
        const top = seg.highlights.reduce((a, b) => (rank[b.severity] > rank[a.severity] ? b : a));
        const fromModel = seg.highlights.some((h) => h.source === 'model');
        const fromSignal = seg.highlights.some((h) => h.source === 'signal');
        const why = [...new Set(seg.highlights.map((h) => (h.source === 'model' ? `AI: ${h.why}` : `${h.label}: ${h.why}`)))].join('\n');
        return (
          <mark
            key={seg.start}
            className={`ss-mark ss-sev-${top.severity}${fromModel ? ' ss-by-model' : ''}${fromSignal ? ' ss-by-signal' : ''}`}
            title={why}
            tabIndex={0}
            aria-label={`${seg.text}. ${why}`}
          >
            {seg.text}
          </mark>
        );
      })}
      {text.length > maxChars && <span className="ss-muted"> … (long text cut for display)</span>}
    </div>
  );
}
