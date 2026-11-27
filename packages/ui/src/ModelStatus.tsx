import { useCallback, useEffect, useRef, useState } from 'react';
import type { OnDeviceStatus, ScamShieldAI } from '@scamshield/ai';
import { IconChip, IconCloud, IconDownload } from './icons';

export interface ModelState {
  status: OnDeviceStatus | 'checking';
  /** 0..1 while downloading, else null. */
  progress: number | null;
  error: string | null;
  download: () => void;
  refresh: () => void;
}

/** Tracks Gemini Nano availability; `download()` must be called from a click. */
export function useModelState(ai: ScamShieldAI): ModelState {
  const [status, setStatus] = useState<ModelState['status']>('checking');
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);

  const refresh = useCallback(() => {
    void ai.status().then(setStatus);
  }, [ai]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // While Chrome downloads in the background, poll so the panel flips to "ready" by itself.
  useEffect(() => {
    if (status !== 'downloading' || busy.current) return;
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [status, refresh]);

  const download = useCallback(() => {
    if (busy.current) return;
    busy.current = true;
    setError(null);
    setStatus('downloading');
    setProgress(0);
    ai.download((p) => setProgress(p))
      .then(() => {
        setProgress(null);
        refresh();
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : String(e));
        setProgress(null);
        refresh();
      })
      .finally(() => {
        busy.current = false;
      });
  }, [ai, refresh]);

  return { status, progress, error, download, refresh };
}

const COPY: Record<ModelState['status'], { title: string; body: string }> = {
  checking: { title: 'Checking this device…', body: 'Looking for Chrome\'s built-in Gemini Nano.' },
  available: { title: 'Gemini Nano is ready', body: 'Checks run on this computer. Your text never leaves it.' },
  downloadable: { title: 'Gemini Nano can be installed', body: 'A one-time download lets Chrome check text offline, on this computer.' },
  downloading: { title: 'Installing Gemini Nano…', body: 'You can keep checking meanwhile: until it is ready, only redacted text goes to the cloud.' },
  unavailable: { title: 'Gemini Nano is not available here', body: 'This device cannot run the on-device model. Checks use the cloud model with redacted text only.' },
  unsupported: { title: 'No on-device AI in this browser', body: 'Use desktop Chrome for on-device checks. Until then, only redacted text goes to the cloud.' },
};

export function ModelStatusPanel({ state, compact = false }: { state: ModelState; compact?: boolean }) {
  const { status, progress, error, download } = state;
  const copy = COPY[status];
  const pct = progress === null ? null : Math.round(progress * 100);
  const onDevice = status === 'available';
  return (
    <section className={`ss-model ss-model-${status}${compact ? ' is-compact' : ''}`} aria-live="polite" aria-label="On-device model status">
      <div className="ss-model-icon">{onDevice || status === 'downloading' || status === 'downloadable' ? <IconChip size={20} /> : <IconCloud size={20} />}</div>
      <div className="ss-model-body">
        <div className="ss-model-title">
          <span className="ss-dot" aria-hidden />
          {copy.title}
          {pct !== null && <span className="ss-model-pct">{pct}%</span>}
        </div>
        {!compact && <p className="ss-model-text">{copy.body}</p>}
        {status === 'downloading' && (
          <div className="ss-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct ?? undefined} aria-label="Gemini Nano download">
            <span style={{ width: pct === null ? '35%' : `${Math.max(3, pct)}%` }} className={pct === null ? 'is-indeterminate' : ''} />
          </div>
        )}
        {error && <p className="ss-model-error">{error}</p>}
      </div>
      {status === 'downloadable' && (
        <button type="button" className="ss-btn ss-btn-quiet" onClick={download}>
          <IconDownload size={16} /> Install
        </button>
      )}
    </section>
  );
}
