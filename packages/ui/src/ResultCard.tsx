import type { CheckResult } from '@scamshield/core';
import { HighlightedText } from './HighlightedText';
import { RiskShield } from './RiskShield';
import { categoryLabel, dataPathSteps, provenance, VERDICT_TITLE } from './format';
import { IconAlert, IconCheck, IconChip, IconCloud, IconList, IconSpark } from './icons';

function ProvenanceChip({ result }: { result: CheckResult }) {
  // Any uploaded byte shows the cloud icon, also when the cloud call failed.
  const Icon = result.backend === 'on-device' ? IconChip : result.bytesSent > 0 ? IconCloud : IconList;
  return (
    <span className={`ss-prov ss-prov-${result.backend}`} title="Where this check ran and what left your device">
      <Icon size={15} />
      {provenance(result)}
    </span>
  );
}

const PATH_ICONS = { local: IconList, device: IconChip, cloud: IconCloud } as const;

/** The privacy story of this exact check: which of the three stages ran. */
function DataPath({ result }: { result: CheckResult }) {
  return (
    <ol className="ss-path" aria-label="Where your text went">
      {dataPathSteps(result).map((s) => {
        const Icon = PATH_ICONS[s.key];
        return (
          <li key={s.key} className={`ss-path-step${s.on ? ' is-on' : ''} ss-path-${s.key}`}>
            <span className="ss-path-icon"><Icon size={16} /></span>
            <span className="ss-path-title">{s.title}</span>
            <span className="ss-path-detail">{s.detail}</span>
          </li>
        );
      })}
    </ol>
  );
}

interface Props {
  result: CheckResult;
  text: string;
  canDeepCheck: boolean;
  deepBusy: boolean;
  onDeepCheck: () => void;
  compact?: boolean;
}

export function ResultCard({ result, text, canDeepCheck, deepBusy, onDeepCheck, compact = false }: Props) {
  const engineReasons = result.reasons.filter((r) => r.source === 'engine');
  const modelReasons = result.reasons.filter((r) => r.source === 'model');
  const VerdictIcon = result.verdict === 'safe' ? IconCheck : IconAlert;
  return (
    <article className={`ss-result ss-tone-${result.verdict}${compact ? ' is-compact' : ''}`} aria-label="Check result">
      <header className="ss-result-head">
        <RiskShield risk={result.risk} verdict={result.verdict} size={compact ? 92 : 132} />
        <div className="ss-result-verdict">
          <span className="ss-kicker">{result.kind === 'deep' ? 'Deep check' : 'Quick check'}</span>
          <h2 className="ss-verdict">
            <VerdictIcon size={compact ? 22 : 28} /> {VERDICT_TITLE[result.verdict]}
          </h2>
          <p className="ss-category">{categoryLabel(result)}</p>
          <ProvenanceChip result={result} />
        </div>
      </header>

      <p className="ss-advice">{result.advice}</p>

      <DataPath result={result} />

      {(engineReasons.length > 0 || modelReasons.length > 0 || result.signals.length > 0) && (
        <section className="ss-reasons" aria-label="Why">
          <h3>Why</h3>
          <ul>
            {engineReasons.map((r, i) => (
              <li key={`e${i}`} className="ss-reason ss-reason-engine">
                <span className="ss-reason-tag"><IconAlert size={13} /> Rule</span>
                <span className="ss-reason-body">
                  <strong>{r.why}</strong>
                </span>
              </li>
            ))}
            {modelReasons.map((r, i) => (
              <li key={`m${i}`} className="ss-reason ss-reason-model">
                <span className="ss-reason-tag"><IconSpark size={13} /> AI</span>
                <span className="ss-reason-body">
                  {r.quote && <q>{r.quote}</q>} {r.why}
                </span>
              </li>
            ))}
            {result.signals.map((s) => (
              <li key={s.id} className={`ss-reason ss-reason-signal ss-sev-${s.severity}`}>
                <span className="ss-reason-tag">+{s.weight}</span>
                <span className="ss-reason-body">
                  <strong>{s.label}.</strong> {s.explanation}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {result.highlights.length > 0 && (
        <section className="ss-evidence" aria-label="Highlighted text">
          <h3>In your text</h3>
          <HighlightedText text={text} highlights={result.highlights} maxChars={compact ? 2500 : 6000} />
          <p className="ss-legend">
            <span className="ss-mark ss-sev-high">strong sign</span>
            <span className="ss-mark ss-sev-medium">warning</span>
            <span className="ss-mark ss-sev-low">weak</span>
            <span className="ss-mark ss-by-model ss-sev-none">quoted by AI</span>
          </p>
        </section>
      )}

      <footer className="ss-result-foot">
        <span className="ss-muted">
          Heuristics {result.heuristicRisk}
          {result.modelRisk !== null ? ` · model ${result.modelRisk}` : ''} · prompt {result.promptVersion}
          {result.truncated ? ' · long text cut' : ''}
        </span>
        {canDeepCheck && result.kind === 'quick' && (
          <button type="button" className="ss-btn ss-btn-ghost" onClick={onDeepCheck} disabled={deepBusy}>
            <IconCloud size={16} /> {deepBusy ? 'Deep check running…' : 'Deep check (redacted, cloud)'}
          </button>
        )}
      </footer>
      {result.note && <p className="ss-note" role="status">{result.note}</p>}
    </article>
  );
}
