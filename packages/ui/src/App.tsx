import { Component, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { addCheckToStats, analyzeLocal, SIGNAL_DEFINITIONS, type CheckResult, type CommunityStats, type Example, type PreparedDeepCheck } from '@scamshield/core';
import type { ScamShieldAI } from '@scamshield/ai';
import { ConsentDialog } from './ConsentDialog';
import { ExampleChips } from './Examples';
import { announce, communityLine } from './format';
import { IconArrow, IconChip, IconCloud, IconList, IconLock, IconMoon, IconSun, ShieldMark } from './icons';
import { ModelStatusPanel, useModelState } from './ModelStatus';
import { ResultCard } from './ResultCard';
import { RiskShield } from './RiskShield';
import { useTheme } from './theme';

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
  onResult?: (r: CheckResult) => void;
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

function PrivacySteps() {
  return (
    <ol className="ss-steps" aria-label="How Scam Shield keeps your text private">
      <li>
        <span className="ss-step-icon"><IconList size={18} /></span>
        <span><strong>Instant local checks</strong> {SIGNAL_DEFINITIONS.length} scam signs and personal-data masking, in your browser.</span>
      </li>
      <li>
        <span className="ss-step-icon is-device"><IconChip size={18} /></span>
        <span><strong>Gemini Nano on your PC</strong> reads the raw text. Nothing is uploaded.</span>
      </li>
      <li>
        <span className="ss-step-icon is-cloud"><IconCloud size={18} /></span>
        <span><strong>Cloud only when needed</strong> and only a redacted copy: names, numbers and links masked.</span>
      </li>
    </ol>
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

function EmptyState() {
  return (
    <div className="ss-empty">
      <RiskShield risk={null} verdict={null} size={112} />
      <div>
        <h2>Paste anything that feels off.</h2>
        <p>A recruiter who wants you to run their repo, a "support agent" asking for your recovery phrase, a parcel fee, an invoice with new bank details.</p>
        <p className="ss-muted">Tip: press Ctrl + Enter to check.</p>
      </div>
    </div>
  );
}

export function ScamShieldApp({ ai, variant = 'web', incoming = null, autoCheckIncoming = false, actions, notice, onResult }: ScamShieldAppProps) {
  const [theme, toggleTheme] = useTheme();
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
    (r: CheckResult) => {
      setResult(r);
      setLive(announce(r));
      // This check was just counted in Firestore; show it without reading the document again.
      setCommunity((s) => (s ? addCheckToStats(s, r) : s));
      onResult?.(r);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }));
    },
    [onResult],
  );

  const check = useCallback(
    async (value: string) => {
      if (!value.trim() || busy) return;
      setBusy(true);
      setCheckedText(value);
      try {
        publish(await ai.quickCheck(value));
      } finally {
        setBusy(false);
        model.refresh();
      }
    },
    [ai, busy, publish, model],
  );

  useEffect(() => {
    if (!incoming) return;
    setText(incoming.text);
    setSource(incoming.source);
    setExampleId(null);
    setResult(null);
    if (autoCheckIncoming) void check(incoming.text);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incoming?.nonce]);

  const pick = (ex: Example) => {
    setText(ex.text);
    setExampleId(ex.id);
    setSource(null);
    setResult(null);
  };

  const sendDeep = async () => {
    if (!prepared) return;
    const p = prepared;
    setPrepared(null);
    setDeepBusy(true);
    try {
      publish(await ai.deepCheck(checkedText, p));
    } finally {
      setDeepBusy(false);
    }
  };

  const signCount = local.signals.length;
  const maskCount = local.redaction.redactions.length;

  const input = (
    <section className="ss-card ss-input" aria-label="Message to check">
      {!panel && <ExampleChips onPick={pick} activeId={exampleId} />}
      <div className="ss-field">
        <label htmlFor="ss-text" className="ss-label">
          {source ? <>Checking: <em>{source}</em></> : 'Message, job offer, e-mail or page text'}
        </label>
        <textarea
          id="ss-text"
          className="ss-textarea"
          value={text}
          placeholder="Paste the message here…"
          spellCheck={false}
          rows={panel ? 7 : 11}
          onChange={(e) => {
            setText(e.target.value);
            setExampleId(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              void check(text);
            }
          }}
        />
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
      </div>
      {panel && (
        <details className="ss-panel-examples">
          <summary>Examples</summary>
          <ExampleChips onPick={pick} activeId={exampleId} />
        </details>
      )}
      <div className="ss-actions">
        <button type="button" className="ss-btn ss-btn-primary ss-btn-big" onClick={() => void check(text)} disabled={!text.trim() || busy}>
          {busy ? 'Checking…' : 'Check privately'} <IconArrow size={18} />
        </button>
        {actions}
        {text && (
          <button type="button" className="ss-btn ss-btn-ghost" onClick={() => { setText(''); setResult(null); setExampleId(null); setSource(null); }}>
            Clear
          </button>
        )}
      </div>
    </section>
  );

  const output = (
    <div className="ss-output" ref={resultRef}>
      {busy && !result ? (
        <div className="ss-card ss-pending">
          <RiskShield risk={null} verdict={null} size={panel ? 80 : 112} busy />
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
      ) : (
        !panel && <EmptyState />
      )}
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
        <button type="button" className="ss-icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
          {theme === 'dark' ? <IconSun /> : <IconMoon />}
        </button>
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
              Is it a scam? <em>Ask your own computer.</em>
            </h1>
            <p className="ss-lede">
              Scam Shield checks messages, job offers, e-mails and web pages with Gemini Nano running inside Chrome. The raw text stays on your PC.
            </p>
            <PrivacySteps />
            <CommunityLine stats={community} />
          </section>
          <div className="ss-grid">
            {input}
            <div className="ss-side">
              <ModelStatusPanel state={model} />
              {output}
            </div>
          </div>
        </main>
      )}

      <footer className="ss-foot">
        <span>Firebase AI Logic hybrid inference · Gemini Nano on device, Gemini in the cloud as fallback · App Check</span>
        <span>Open source, Apache-2.0</span>
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
