import { Component, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { addCheckToStats, analyzeLocal, EXAMPLES, SIGNAL_DEFINITIONS, type CheckResult, type CommunityStats, type Example, type PreparedDeepCheck } from '@scamshield/core';
import type { ScamShieldAI } from '@scamshield/ai';
import { createCheckQueue, type CheckQueue } from './check-queue';
import { ConsentDialog } from './ConsentDialog';
import { ExampleChips } from './Examples';
import { announce, communityLine } from './format';
import { IconArrow, IconChip, IconCloud, IconList, IconLock, ShieldMark } from './icons';
import { ModelStatusPanel, useModelState } from './ModelStatus';
import { ResultCard } from './ResultCard';
import { RiskShield } from './RiskShield';

const REPO_URL = 'https://github.com/VladimirRadev/scam-shield';
const EXTENSION_URL = `${REPO_URL}/releases/latest`;

export interface IncomingText {
  text: string;
  /** e.g. "Selected text" or "Page: example.com" */
  source: string;
  nonce: number;
}

export interface ScamShieldAppProps {
  ai: ScamShieldAI;
  variant?: 'web' | 'panel';
  incoming?: IncomingText | null;
  /** Run the quick check right away when text arrives from outside. */
  autoCheckIncoming?: boolean;
  /** Extra buttons next to the input (extension: "Scan this page"). */
  actions?: ReactNode;
  /** A message shown above the input, e.g. why a page could not be read. */
  notice?: ReactNode;
  /** A finished check, with the exact text that was checked. */
  onResult?: (r: CheckResult, checkedText: string) => void;
  /** The user typed, picked an example or cleared the text box. */
  onEdit?: () => void;
}

function SetupNotice({ missing }: { missing: string[] }) {
  return (
    <div className="ss-setup" role="alert">
      <strong>Setup needed: Firebase is not configured.</strong> Local checks still work, AI checks are off. Copy
      <code>.env.example</code> to <code>.env.local</code> and fill in{' '}
      {missing.map((m, i) => (
        <span key={m}>
          <code>{m}</code>
          {i < missing.length - 1 ? ', ' : ''}
        </span>
      ))}
      , then restart the build.
    </div>
  );
}

/** Three real numbers from the code, in Jumper-style tiles under the hero. */
function StatTiles() {
  const stats = [
    { num: String(SIGNAL_DEFINITIONS.length), label: 'local scam signals' },
    { num: '0', label: 'bytes sent on device' },
    { num: String(EXAMPLES.length), label: 'test messages' },
  ];
  return (
    <ul className="ss-stats" aria-label="Scam Shield in numbers">
      {stats.map((s) => (
        <li key={s.label}>
          <span className="ss-stat-num">{s.num}</span>
          <span className="ss-stat-label">{s.label}</span>
        </li>
      ))}
    </ul>
  );
}

function PrivacySteps() {
  return (
    <section className="ss-how" aria-labelledby="ss-how-title">
      <h2 id="ss-how-title">
        Private <span className="ss-grad">by design</span>
      </h2>
      <p className="ss-how-lede">The raw text stays on your PC. The cloud only ever sees a redacted copy.</p>
      <ol className="ss-steps" aria-label="How Scam Shield keeps your text private">
        <li>
          <span className="ss-step-num" aria-hidden>01</span>
          <span className="ss-step-icon"><IconList size={20} /></span>
          <h3>Instant local checks</h3>
          <p>{SIGNAL_DEFINITIONS.length} scam signs and personal-data masking, in your browser.</p>
        </li>
        <li>
          <span className="ss-step-num" aria-hidden>02</span>
          <span className="ss-step-icon is-device"><IconChip size={20} /></span>
          <h3>Gemini Nano on your PC</h3>
          <p>Reads the raw text. Nothing is uploaded.</p>
        </li>
        <li>
          <span className="ss-step-num" aria-hidden>03</span>
          <span className="ss-step-icon is-cloud"><IconCloud size={20} /></span>
          <h3>Cloud only when needed</h3>
          <p>And only a redacted copy: names, numbers and links masked.</p>
        </li>
      </ol>
    </section>
  );
}

/** Anonymous totals from Firestore (counters only). Space is reserved so nothing jumps when it loads. */
function CommunityLine({ stats }: { stats: CommunityStats | null }) {
  const line = communityLine(stats);
  return (
    <p className="ss-community" aria-live="polite">
      {line && (
        <>
          <span className="ss-community-dot" aria-hidden />
          {line}
          <span className="ss-community-note"> · anonymous counters, no text stored</span>
        </>
      )}
    </p>
  );
}

const PLACEHOLDER =
  'Paste anything that feels off: a recruiter who wants you to run their repo, a "support agent" asking for your recovery phrase, a parcel fee, an invoice with new bank details…';

export function ScamShieldApp({ ai, variant = 'web', incoming = null, autoCheckIncoming = false, actions, notice, onResult, onEdit }: ScamShieldAppProps) {
  const model = useModelState(ai);
  const [text, setText] = useState('');
  const [exampleId, setExampleId] = useState<string | null>(null);
  const [source, setSource] = useState<string | null>(null);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [checkedText, setCheckedText] = useState('');
  const [busy, setBusy] = useState(false);
  const [deepBusy, setDeepBusy] = useState(false);
  const [prepared, setPrepared] = useState<PreparedDeepCheck | null>(null);
  const [live, setLive] = useState('');
  const [deepEnabled, setDeepEnabled] = useState(ai.config().deepCheckEnabled);
  const [community, setCommunity] = useState<CommunityStats | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const panel = variant === 'panel';

  useEffect(() => {
    void ai.ready.then((c) => setDeepEnabled(c.deepCheckEnabled));
  }, [ai]);

  useEffect(() => {
    if (panel || !ai.configured) return;
    let live = true;
    // Not needed for the first paint: load Firestore Lite when the browser is idle.
    const load = () => void ai.communityStats().then((s) => live && setCommunity(s));
    const idle = typeof requestIdleCallback === 'function' ? requestIdleCallback(load, { timeout: 3000 }) : null;
    const timer = idle === null ? setTimeout(load, 1500) : null;
    return () => {
      live = false;
      if (idle !== null) cancelIdleCallback(idle);
      if (timer !== null) clearTimeout(timer);
    };
  }, [ai, panel]);

  const deferred = useDeferredValue(text);
  const local = useMemo(() => analyzeLocal(deferred), [deferred]);

  const publish = useCallback(
    (r: CheckResult, value: string) => {
      setResult(r);
      setLive(announce(r));
      // This check was just counted in Firestore; show it without reading the document again.
      setCommunity((s) => (s ? addCheckToStats(s, r) : s));
      onResult?.(r, value);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }));
    },
    [onResult],
  );

  const runCheck = async (value: string) => {
    setBusy(true);
    setCheckedText(value);
    try {
      publish(await ai.quickCheck(value), value);
    } finally {
      setBusy(false);
      model.refresh();
    }
  };
  // One check at a time; a text that arrives during a check runs right after it (see check-queue.ts).
  const runRef = useRef(runCheck);
  runRef.current = runCheck;
  const queueRef = useRef<CheckQueue | null>(null);
  queueRef.current ??= createCheckQueue((value) => runRef.current(value));
  const check = (value: string, queue = false) => queueRef.current!.submit(value, { queue });

  /** The user changed the input: a waiting outside text is dropped. */
  const edited = () => {
    queueRef.current?.cancelQueued();
    onEdit?.();
  };

  useEffect(() => {
    if (!incoming) return;
    setText(incoming.text);
    setSource(incoming.source);
    setExampleId(null);
    setResult(null);
    if (autoCheckIncoming) check(incoming.text, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incoming?.nonce]);

  const pick = (ex: Example) => {
    setText(ex.text);
    setExampleId(ex.id);
    setSource(null);
    setResult(null);
    edited();
  };

  const sendDeep = async () => {
    if (!prepared) return;
    const p = prepared;
    setPrepared(null);
    setDeepBusy(true);
    try {
      publish(await ai.deepCheck(checkedText, p), checkedText);
    } finally {
      setDeepBusy(false);
    }
  };

  const signCount = local.signals.length;
  const maskCount = local.redaction.redactions.length;

  const clear = () => {
    setText('');
    setResult(null);
    setExampleId(null);
    setSource(null);
    edited();
  };

  const input = (
    <section className="ss-card ss-input" aria-label="Message to check">
      {!panel && <ExampleChips onPick={pick} activeId={exampleId} />}
      <div className="ss-field">
        <div className="ss-field-head">
          <label htmlFor="ss-text" className="ss-label">
            {source ? <>Checking: <em>{source}</em></> : 'Message, job offer, e-mail or page text'}
          </label>
          {text && (
            <button type="button" className="ss-clear" onClick={clear}>
              Clear
            </button>
          )}
        </div>
        <textarea
          id="ss-text"
          className="ss-textarea"
          value={text}
          placeholder={PLACEHOLDER}
          spellCheck={false}
          rows={panel ? 6 : 8}
          onChange={(e) => {
            setText(e.target.value);
            setExampleId(null);
            edited();
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              check(text);
            }
          }}
        />
        <div className="ss-field-foot">
          <div className="ss-live" aria-live="polite">
            <IconLock size={14} />
            {text.trim() ? (
              <span>
                Instant local scan: <strong>{signCount}</strong> warning sign{signCount === 1 ? '' : 's'} ·{' '}
                <strong>{maskCount}</strong> personal detail{maskCount === 1 ? '' : 's'} masked for any cloud use
              </span>
            ) : (
              <span>Nothing is sent anywhere while you type.</span>
            )}
          </div>
          {!panel && (
            <span className="ss-kbd-hint">
              <kbd>Ctrl</kbd> + <kbd>Enter</kbd> to check
            </span>
          )}
        </div>
      </div>
      {panel && (
        <details className="ss-panel-examples">
          <summary>Examples</summary>
          <ExampleChips onPick={pick} activeId={exampleId} />
        </details>
      )}
      <div className="ss-actions">
        <button
          type="button"
          className={`ss-btn ss-btn-primary ss-btn-big${busy ? ' is-busy' : ''}`}
          onClick={() => check(text)}
          disabled={!text.trim() || busy}
        >
          {busy ? 'Checking…' : 'Check privately'} <IconArrow size={18} />
        </button>
        {actions}
      </div>
    </section>
  );

  const output = (
    <div className="ss-output" ref={resultRef}>
      {busy && !result ? (
        <div className="ss-card ss-pending">
          <RiskShield risk={null} verdict={null} size={panel ? 72 : 96} busy />
          <p>{model.status === 'available' ? 'Gemini Nano is reading the text on this device…' : 'Checking with redacted text…'}</p>
        </div>
      ) : result ? (
        <ResultCard
          result={result}
          text={checkedText}
          compact={panel}
          canDeepCheck={ai.configured && deepEnabled}
          deepBusy={deepBusy}
          onDeepCheck={() => setPrepared(ai.prepareDeep(checkedText))}
        />
      ) : null}
    </div>
  );

  return (
    <div className={`ss-app ss-${variant}`}>
      <a className="ss-skip" href="#ss-text">Skip to the text box</a>
      <header className="ss-top">
        <div className="ss-brand">
          <ShieldMark size={panel ? 22 : 28} />
          <span className="ss-brand-name">Scam Shield</span>
          {!panel && <span className="ss-brand-tag">private by design</span>}
        </div>
        {!panel && (
          <a className="ss-btn ss-btn-primary ss-btn-top" href={EXTENSION_URL} target="_blank" rel="noopener noreferrer">
            Get the extension
          </a>
        )}
      </header>

      {!ai.configured && <SetupNotice missing={ai.missingConfig} />}
      {notice && <div className="ss-notice" role="status">{notice}</div>}

      {panel ? (
        <main className="ss-panel-main">
          <ModelStatusPanel state={model} compact />
          {input}
          {output}
        </main>
      ) : (
        <main className="ss-web-main">
          <section className="ss-hero">
            <h1>
              Is it a scam? <span className="ss-grad">Ask your own computer.</span>
            </h1>
            <p className="ss-lede">
              <strong>Gemini Nano inside Chrome</strong> checks messages, job offers, e-mails and web pages. The raw text stays on your PC.
            </p>
            <StatTiles />
            <CommunityLine stats={community} />
          </section>
          <div className="ss-stage">
            <ModelStatusPanel state={model} />
            {input}
            {output}
          </div>
          <PrivacySteps />
        </main>
      )}

      <footer className="ss-foot">
        <span>Firebase AI Logic hybrid inference · Gemini Nano on device, Gemini in the cloud as fallback · App Check</span>
        {panel ? (
          <span>Open source, Apache-2.0</span>
        ) : (
          <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
            Open source, Apache-2.0
          </a>
        )}
      </footer>

      <div className="ss-sr" aria-live="assertive">{live}</div>
      <ConsentDialog prepared={prepared} onCancel={() => setPrepared(null)} onSend={() => void sendDeep()} />
    </div>
  );
}

interface BoundaryState {
  error: Error | null;
}

/** Last line of defence: a readable message instead of a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  override state: BoundaryState = { error: null };
  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error };
  }
  override render() {
    if (this.state.error) {
      return (
        <div className="ss-crash" role="alert">
          <ShieldMark size={36} />
          <h1>Something went wrong.</h1>
          <p>{this.state.error.message}</p>
          <button type="button" className="ss-btn ss-btn-primary" onClick={() => location.reload()}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
