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

function Chip({ ex, onPick, active }: { ex: Example; onPick: (e: Example) => void; active: boolean }) {
  return (
    <button type="button" className={`ss-chip${active ? ' is-active' : ''}`} onClick={() => onPick(ex)} aria-pressed={active}>
      <span className={`ss-chip-channel ss-ch-${ex.channel}`} aria-hidden />
      {ex.title}
    </button>
  );
}

/** Example chips: a featured row plus every example grouped by label. Labels stay hidden in the chip itself. */
export function ExampleChips({ onPick, activeId }: { onPick: (e: Example) => void; activeId: string | null }) {
  const scams = EXAMPLES.filter((e) => e.label === 'scam');
  const legit = EXAMPLES.filter((e) => e.label === 'legit');
  return (
    <div className="ss-examples">
      <div className="ss-examples-row" role="group" aria-label="Try an example">
        {featured.map((ex) => (
          <Chip key={ex.id} ex={ex} onPick={onPick} active={activeId === ex.id} />
        ))}
      </div>
      <details className="ss-examples-more">
        <summary>All {EXAMPLES.length} examples</summary>
        <div className="ss-examples-group">
          <h3>Scams ({scams.length})</h3>
          <div className="ss-examples-row">
            {scams.map((ex) => (
              <Chip key={ex.id} ex={ex} onPick={onPick} active={activeId === ex.id} />
            ))}
          </div>
          <h3>Legitimate look-alikes ({legit.length})</h3>
          <div className="ss-examples-row">
            {legit.map((ex) => (
              <Chip key={ex.id} ex={ex} onPick={onPick} active={activeId === ex.id} />
            ))}
          </div>
        </div>
      </details>
    </div>
  );
}
