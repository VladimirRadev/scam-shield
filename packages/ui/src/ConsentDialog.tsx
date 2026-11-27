import { useEffect, useRef, type ReactNode } from 'react';
import { REDACTION_LABELS, type PreparedDeepCheck, type RedactionKind } from '@scamshield/core';
import { formatBytes } from './format';
import { IconCloud, IconLock } from './icons';

interface Props {
  prepared: PreparedDeepCheck | null;
  onCancel: () => void;
  onSend: () => void;
}

/** Render the redacted text with each placeholder shown as a chip. */
function RedactedPreview({ prepared }: { prepared: PreparedDeepCheck }) {
  const { text, redactions } = prepared.local.redaction;
  const parts: ReactNode[] = [];
  let cursor = 0;
  for (const r of redactions) {
    if (r.redacted.start > cursor) parts.push(<span key={`t${cursor}`}>{text.slice(cursor, r.redacted.start)}</span>);
    parts.push(
      <span key={`r${r.redacted.start}`} className="ss-placeholder" title={`Removed: ${REDACTION_LABELS[r.kind]}`}>
        {r.replacement}
      </span>,
    );
    cursor = r.redacted.end;
  }
  if (cursor < text.length) parts.push(<span key={`t${cursor}`}>{text.slice(cursor)}</span>);
  return <div className="ss-redacted">{parts}</div>;
}

/** Explicit consent before anything is sent to the cloud. Shows exactly what would be sent. */
export function ConsentDialog({ prepared, onCancel, onSend }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const keepRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (prepared && !d.open) {
      d.showModal();
      // The safe choice gets the focus (showModal alone would focus the scrollable preview).
      keepRef.current?.focus();
    }
    if (!prepared && d.open) d.close();
  }, [prepared]);

  const counts = prepared ? (Object.entries(prepared.local.redaction.counts) as Array<[RedactionKind, number]>) : [];
  return (
    <dialog ref={ref} className="ss-dialog" aria-labelledby="ss-consent-title" onCancel={(e) => { e.preventDefault(); onCancel(); }}>
      {prepared && (
        <form method="dialog" className="ss-dialog-inner" onSubmit={(e) => { e.preventDefault(); onSend(); }}>
          <header className="ss-dialog-head">
            <span className="ss-dialog-icon"><IconCloud size={22} /></span>
            <div>
              <h2 id="ss-consent-title">Send a redacted copy for a deep check?</h2>
              <p>Gemini in the cloud takes a second, slower and more careful look. This is exactly the message text that would leave your device:</p>
            </div>
          </header>
          <RedactedPreview prepared={prepared} />
          <div className="ss-dialog-meta">
            <span><IconLock size={14} /> {counts.length ? counts.map(([k, n]) => `${n} ${REDACTION_LABELS[k]}`).join(' · ') + ' removed' : 'No personal data detected'}</span>
            <span>{formatBytes(prepared.bytes)} incl. instructions{prepared.truncated ? ' · long text cut' : ''}</span>
          </div>
          <details className="ss-dialog-full">
            <summary>Show the full request text</summary>
            <pre>{prepared.prompt}</pre>
          </details>
          <footer className="ss-dialog-actions">
            <button type="button" className="ss-btn ss-btn-ghost" onClick={onCancel} ref={keepRef}>
              Keep it on my device
            </button>
            <button type="submit" className="ss-btn ss-btn-primary">
              Send redacted text
            </button>
          </footer>
        </form>
      )}
    </dialog>
  );
}
