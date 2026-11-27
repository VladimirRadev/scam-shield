/**
 * Evaluation page (eval.html, not linked from the app): runs all labelled examples through the
 * real engine on ONE fixed route, one after another, and reports precision / recall / F1,
 * latency and bytes sent. The result is also exposed as `window.__evalResult` (JSON).
 *
 * Routes: device = raw text, ONLY_ON_DEVICE · cloud = redacted text, ONLY_IN_CLOUD ·
 * heuristics = no model. Evaluation checks are not counted in the community statistics.
 */
import { StrictMode, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createScamShieldAI, type AppConfig, type OnDeviceStatus } from '@scamshield/ai';
import {
  EXAMPLES,
  EXPECTED_BACKEND,
  pct,
  ROUTE_TITLES,
  routeMarkdown,
  summarizeRoute,
  type EvalRouteName,
  type EvalRow,
  type RouteSummary,
} from '@scamshield/core';
import { ErrorBoundary, IconChip, IconCloud, IconList, IconMoon, IconSun, ShieldMark, useTheme } from '@scamshield/ui';
import '@scamshield/ui/styles.css';
import './eval.css';
import { runRoute } from './eval-runner';

const ai = createScamShieldAI(import.meta.env, { isExtension: false, allowDebugToken: import.meta.env.DEV });

interface RouteRun {
  summary: RouteSummary;
  rows: EvalRow[];
  markdown: string;
  complete: boolean;
  startedAt: string;
  finishedAt: string | null;
}

interface EvalResult {
  version: 1;
  generatedAt: string;
  browser: string | null;
  userAgent: string;
  cloudModel: string;
  promptVersion: string;
  thresholds: AppConfig['thresholds'];
  configSource: AppConfig['source'];
  onDeviceStatus: OnDeviceStatus | 'checking';
  examples: number;
  routes: Partial<Record<EvalRouteName, RouteRun>>;
}

declare global {
  interface Window {
    __evalResult?: EvalResult;
  }
}

const ROUTES: EvalRouteName[] = ['device', 'cloud', 'heuristics'];

const ROUTE_INFO: Record<EvalRouteName, { button: string; sent: string; icon: typeof IconChip }> = {
  device: { button: 'Run on device', sent: 'Raw text stays in Chrome. Needs Gemini Nano.', icon: IconChip },
  cloud: { button: 'Run in the cloud', sent: 'Only the redacted text is sent.', icon: IconCloud },
  heuristics: { button: 'Run heuristics', sent: 'No model, nothing sent.', icon: IconList },
};

function browserName(): string | null {
  const m = /(?:Chrome|Chromium)\/(\d+)/.exec(navigator.userAgent);
  return m ? `Chrome ${m[1]}` : null;
}

const ms = (x: number | null) => (x === null ? 'n/a' : `${x.toLocaleString('en-US')} ms`);
const bytes = (n: number) => (n < 1000 ? `${n} B` : `${(n / 1000).toFixed(1)} kB`);

function EvalPage() {
  const [theme, toggleTheme] = useTheme();
  const [config, setConfig] = useState<AppConfig>(ai.config());
  const [status, setStatus] = useState<OnDeviceStatus | 'checking'>('checking');
  const [download, setDownload] = useState<number | null>(null);
  const [running, setRunning] = useState<EvalRouteName | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number; id: string | null }>({ done: 0, total: EXAMPLES.length, id: null });
  const [runs, setRuns] = useState<Partial<Record<EvalRouteName, RouteRun>>>({});
  const [pauseMs, setPauseMs] = useState(4000);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    void ai.ready.then(setConfig);
    void ai.status().then(setStatus);
  }, []);

  // Keep window.__evalResult in step with what is on screen.
  useEffect(() => {
    window.__evalResult = {
      version: 1,
      generatedAt: new Date().toISOString(),
      browser: browserName(),
      userAgent: navigator.userAgent,
      cloudModel: config.cloudModel,
      promptVersion: config.promptVersion,
      thresholds: config.thresholds,
      configSource: config.source,
      onDeviceStatus: status,
      examples: EXAMPLES.length,
      routes: runs,
    };
  }, [runs, config, status]);

  const start = useCallback(
    async (route: EvalRouteName) => {
      if (running) return;
      setError(null);
      setRunning(route);
      try {
        // The click is the user gesture Chrome needs to download / start Gemini Nano.
        if (route === 'device' && (status === 'downloadable' || status === 'downloading')) {
          setDownload(0);
          await ai.download((p) => setDownload(p));
          setDownload(null);
          setStatus(await ai.status());
        }
        const cfg = await ai.ready;
        const ctrl = new AbortController();
        abort.current = ctrl;
        const startedAt = new Date().toISOString();
        const rows: EvalRow[] = [];
        const publish = (complete: boolean) => {
          const summary = summarizeRoute(route, rows, cfg.thresholds);
          const markdown = routeMarkdown(summary, { browser: browserName() ?? undefined, model: cfg.cloudModel, date: startedAt.slice(0, 10) });
          setRuns((r) => ({ ...r, [route]: { summary, rows: [...rows], markdown, complete, startedAt, finishedAt: complete ? new Date().toISOString() : null } }));
        };
        setProgress({ done: 0, total: EXAMPLES.length, id: EXAMPLES[0]?.id ?? null });
        await runRoute({
          route,
          examples: EXAMPLES,
          check: (text, r) => ai.evalCheck(text, r),
          pauseMs: route === 'cloud' ? pauseMs : 0,
          signal: ctrl.signal,
          onProgress: (done, total, row) => {
            rows.push(row);
            setProgress({ done, total, id: EXAMPLES[done]?.id ?? null });
            publish(false);
          },
        });
        publish(rows.length === EXAMPLES.length);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        abort.current = null;
        setRunning(null);
        setDownload(null);
        void ai.status().then(setStatus);
      }
    },
    [running, status, pauseMs],
  );

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      setError('The clipboard is blocked here; select the text in the Markdown box instead.');
    }
  };

  const deviceUsable = status === 'available' || status === 'downloadable' || status === 'downloading';
  const done = ROUTES.filter((r) => runs[r]);
  const pctDone = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div className="ss-app ss-web ev">
      <header className="ss-top">
        <div className="ss-brand">
          <ShieldMark size={28} />
          <span className="ss-brand-name">Scam Shield</span>
          <span className="ss-brand-tag">model evaluation</span>
        </div>
        <button type="button" className="ss-icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
          {theme === 'dark' ? <IconSun /> : <IconMoon />}
        </button>
      </header>

      <main className="ev-main">
        <section className="ev-intro">
          <h1>
            {EXAMPLES.length} labelled messages, <em>one route at a time.</em>
          </h1>
          <p>
            Every example ({EXAMPLES.filter((e) => e.label === 'scam').length} scams, {EXAMPLES.filter((e) => e.label === 'legit').length} legitimate look-alikes) goes
            through the real engine, one after another. Results stay in this tab and in <code>window.__evalResult</code>; they are not counted in the
            community statistics.
          </p>
          <dl className="ev-facts">
            <div>
              <dt>Browser</dt>
              <dd>{browserName() ?? 'not Chrome'}</dd>
            </div>
            <div>
              <dt>Gemini Nano</dt>
              <dd className={deviceUsable ? 'is-ok' : 'is-bad'}>{status}</dd>
            </div>
            <div>
              <dt>Cloud model</dt>
              <dd>{config.cloudModel}</dd>
            </div>
            <div>
              <dt>Thresholds</dt>
              <dd>
                suspicious ≥ {config.thresholds.suspicious}, scam ≥ {config.thresholds.scam} ({config.source})
              </dd>
            </div>
          </dl>
          {!ai.configured && <p className="ev-warn">Firebase is not configured: device and cloud routes will fall back to heuristics.</p>}
        </section>

        <section className="ev-routes" aria-label="Routes">
          {ROUTES.map((route) => {
            const info = ROUTE_INFO[route];
            const Icon = info.icon;
            return (
              <div key={route} className={`ss-card ev-route ev-route-${route}`}>
                <div className="ev-route-head">
                  <span className="ev-route-icon">
                    <Icon size={18} />
                  </span>
                  <div>
                    <h2>{ROUTE_TITLES[route](route === 'cloud' ? config.cloudModel : undefined)}</h2>
                    <p>{info.sent}</p>
                  </div>
                </div>
                {route === 'cloud' && (
                  <label className="ev-pause">
                    Pause between calls
                    <input type="number" min={0} step={500} value={pauseMs} onChange={(e) => setPauseMs(Math.max(0, Number(e.target.value) || 0))} disabled={Boolean(running)} />
                    ms
                  </label>
                )}
                {route === 'device' && !deviceUsable && status !== 'checking' && (
                  <p className="ev-warn">Gemini Nano is "{status}" here, so every row will be a heuristics-only fallback.</p>
                )}
                <button type="button" className="ss-btn ss-btn-primary" onClick={() => void start(route)} disabled={Boolean(running)} data-route={route}>
                  {running === route ? 'Running…' : info.button}
                </button>
              </div>
            );
          })}
        </section>

        {(running || download !== null) && (
          <section className="ss-card ev-progress" aria-live="polite">
            <div className="ev-progress-line">
              <strong>{download !== null ? `Downloading Gemini Nano… ${Math.round(download * 100)}%` : `${running}: ${progress.done} / ${progress.total}`}</strong>
              {progress.id && download === null && <span className="ss-muted">next: {progress.id}</span>}
              <button type="button" className="ss-btn ss-btn-ghost" onClick={() => abort.current?.abort()}>
                Stop
              </button>
            </div>
            <div className="ev-bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={download !== null ? Math.round(download * 100) : pctDone}>
              <span style={{ width: `${download !== null ? Math.round(download * 100) : pctDone}%` }} />
            </div>
          </section>
        )}

        {error && (
          <p className="ev-warn" role="alert">
            {error}
          </p>
        )}

        {done.length > 0 && (
          <section className="ss-card ev-summary" aria-label="Summary">
            <div className="ev-table-wrap">
              <table className="ev-table" id="ev-summary">
                <thead>
                  <tr>
                    <th>Route</th>
                    <th>Done</th>
                    <th>Flagged P / R / F1</th>
                    <th>Scam P / R / F1</th>
                    <th>Median</th>
                    <th>p90</th>
                    <th>Avg sent</th>
                    <th>Answered by</th>
                    <th>Misclassified</th>
                  </tr>
                </thead>
                <tbody>
                  {done.map((route) => {
                    const run = runs[route]!;
                    const s = run.summary;
                    return (
                      <tr key={route}>
                        <th scope="row">{route}</th>
                        <td>
                          {s.n}/{EXAMPLES.length}
                          {!run.complete && running !== route ? ' (stopped)' : ''}
                        </td>
                        <td>
                          {pct(s.flagged.precision)} / {pct(s.flagged.recall)} / {pct(s.flagged.f1)}
                        </td>
                        <td>
                          {pct(s.scam.precision)} / {pct(s.scam.recall)} / {pct(s.scam.f1)}
                        </td>
                        <td>{ms(s.latencyMs.median)}</td>
                        <td>{ms(s.latencyMs.p90)}</td>
                        <td>{bytes(s.avgBytesSent)}</td>
                        <td className={s.offRoute ? 'is-bad' : ''}>
                          {Object.entries(s.backends)
                            .map(([b, n]) => `${n} ${b}`)
                            .join(', ')}
                        </td>
                        <td className="ev-ids">{s.misclassified.length ? s.misclassified.join(', ') : 'none'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="ss-actions">
              <button type="button" className="ss-btn ss-btn-ghost" onClick={() => void copy('json', JSON.stringify(window.__evalResult, null, 2))}>
                {copied === 'json' ? 'Copied' : 'Copy JSON'}
              </button>
            </div>
          </section>
        )}

        {done.map((route) => {
          const run = runs[route]!;
          return (
            <section key={route} className="ss-card ev-detail" aria-label={`${route} details`}>
              <div className="ev-detail-head">
                <h2>{ROUTE_TITLES[route](config.cloudModel)}</h2>
                <button type="button" className="ss-btn ss-btn-ghost" onClick={() => void copy(route, run.markdown)}>
                  {copied === route ? 'Copied' : 'Copy Markdown for README'}
                </button>
              </div>
              {run.summary.offRoute > 0 && (
                <p className="ev-warn">
                  {run.summary.offRoute} of {run.summary.n} examples were not answered by {EXPECTED_BACKEND[route]} (see the notes below).
                </p>
              )}
              <textarea className="ev-md" readOnly value={run.markdown} rows={Math.min(14, run.markdown.split('\n').length + 1)} aria-label={`Markdown for ${route}`} />
              <details>
                <summary>All {run.rows.length} rows</summary>
                <div className="ev-table-wrap">
                  <table className="ev-table ev-rows">
                    <thead>
                      <tr>
                        <th>Example</th>
                        <th>Label</th>
                        <th>Risk</th>
                        <th>Verdict</th>
                        <th>Backend</th>
                        <th>ms</th>
                        <th>Sent</th>
                        <th>Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {run.rows.map((r) => (
                        <tr key={r.id} className={run.summary.misclassified.includes(r.id) ? 'is-miss' : ''}>
                          <td>{r.id}</td>
                          <td>{r.label}</td>
                          <td>{r.risk}</td>
                          <td>{r.verdict}</td>
                          <td>{r.backend}</td>
                          <td>{r.latencyMs}</td>
                          <td>{bytes(r.bytesSent)}</td>
                          <td className="ev-note">{r.note ?? ''}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </section>
          );
        })}
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <EvalPage />
    </ErrorBoundary>
  </StrictMode>,
);
