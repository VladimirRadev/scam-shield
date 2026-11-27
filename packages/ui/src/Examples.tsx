import { useId, useRef, useState, type KeyboardEvent } from 'react';
import { EXAMPLES, type Example } from '@scamshield/core';

const FEATURED = [
  'scam-recruiter-repo',
  'scam-seed-support',
  'scam-dhl-sms',
  'scam-bank-details',
  'scam-wrong-number',
  'scam-clickfix-captcha',
  'legit-recruiter',
  'legit-colleague-repo',
];

const byId = new Map(EXAMPLES.map((e) => [e.id, e]));
const featured = FEATURED.map((id) => byId.get(id)).filter((e): e is Example => Boolean(e));
const scams = EXAMPLES.filter((e) => e.label === 'scam');
const legit = EXAMPLES.filter((e) => e.label === 'legit');

type TabId = 'featured' | 'scam' | 'legit';

/** Tab bar: label, optional count, the chips it shows and the name of that chip group. */
const TABS: Array<{ id: TabId; label: string; count?: number; list: Example[]; group: string }> = [
  { id: 'featured', label: 'Featured', list: featured, group: 'Try an example' },
  { id: 'scam', label: 'Scams', count: scams.length, list: scams, group: 'Scam examples' },
  { id: 'legit', label: 'Look-alikes', count: legit.length, list: legit, group: 'Legitimate look-alikes' },
];

function Chip({ ex, onPick, active }: { ex: Example; onPick: (e: Example) => void; active: boolean }) {
  return (
    <button type="button" className={`ss-chip${active ? ' is-active' : ''}`} onClick={() => onPick(ex)} aria-pressed={active}>
      <span className={`ss-chip-channel ss-ch-${ex.channel}`} aria-hidden />
      {ex.title}
    </button>
  );
}

/**
 * Example chips under a segmented tab bar: a featured set, then every example grouped by label.
 * Labels stay hidden in the chip itself.
 */
export function ExampleChips({ onPick, activeId }: { onPick: (e: Example) => void; activeId: string | null }) {
  const [tab, setTab] = useState<TabId>('featured');
  const uid = useId();
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const current = TABS.find((t) => t.id === tab) ?? TABS[0]!;

  // Arrow keys move between tabs (WAI-ARIA tabs pattern, automatic activation).
  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    const to = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : step ? (i + step + TABS.length) % TABS.length : null;
    if (to === null) return;
    e.preventDefault();
    setTab(TABS[to]!.id);
    tabRefs.current[to]?.focus();
  };

  return (
    <div className="ss-examples">
      <div className="ss-examples-head">
        <div className="ss-tabs" role="tablist" aria-label="Example messages">
          {TABS.map((t, i) => (
            <button
              key={t.id}
              ref={(el) => {
                tabRefs.current[i] = el;
              }}
              type="button"
              role="tab"
              id={`${uid}-tab-${t.id}`}
              className="ss-tab"
              aria-selected={tab === t.id}
              aria-controls={`${uid}-panel`}
              tabIndex={tab === t.id ? 0 : -1}
              onClick={() => setTab(t.id)}
              onKeyDown={(e) => onKeyDown(e, i)}
            >
              {t.label}
              {t.count !== undefined && <span className="ss-tab-count">{t.count}</span>}
            </button>
          ))}
        </div>
        <span className="ss-examples-hint">Pick one to try it</span>
      </div>
      <div key={tab} id={`${uid}-panel`} className="ss-tabpanel" role="tabpanel" aria-labelledby={`${uid}-tab-${tab}`}>
        <div className="ss-examples-row" role="group" aria-label={current.group}>
          {current.list.map((ex) => (
            <Chip key={ex.id} ex={ex} onPick={onPick} active={activeId === ex.id} />
          ))}
        </div>
      </div>
    </div>
  );
}
