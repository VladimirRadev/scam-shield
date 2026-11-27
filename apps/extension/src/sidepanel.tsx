/// <reference types="chrome" />
import { StrictMode, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { createScamShieldAI } from '@scamshield/ai';
import type { CheckResult } from '@scamshield/core';
import { ErrorBoundary, IconPage, ScamShieldApp, type IncomingText } from '@scamshield/ui';
import '@scamshield/ui/styles.css';
import { badgeFor, badgeTabFor, type BadgeSource } from './badge';
import { extractVisibleText } from './page-text';
import { PENDING_KEY, type PendingText } from './pending';

// Extension pages cannot load the remote reCAPTCHA script, so App Check runs on the
// registered debug token here (see packages/ai/src/firebase.ts).
const ai = createScamShieldAI(import.meta.env, { isExtension: true, allowDebugToken: true });

const SCAN_HELP =
  'Chrome lets Scam Shield read a page only after you use it on that page: click the toolbar icon while the page is open, or right-click the page and choose "Scan this page with Scam Shield". Chrome settings pages and the Web Store cannot be read.';

function Panel() {
  const [incoming, setIncoming] = useState<IncomingText | null>(null);
  // Page texts that came from a tab, newest last; a result badges a tab only for its own text.
  const sources = useRef<BadgeSource[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const remember = (tabId: number | undefined, text: string) => {
    if (tabId === undefined) return;
    sources.current = [...sources.current.filter((s) => s.text !== text), { tabId, text }].slice(-5);
  };

  const accept = useCallback((p: PendingText | undefined) => {
    if (!p) return;
    void chrome.storage.session.remove(PENDING_KEY);
    if (p.error || !p.text.trim()) {
      setNotice(p.error ? `${SCAN_HELP} (${p.error})` : 'No text found to check.');
      return;
    }
    setNotice(null);
    remember(p.tabId, p.text);
    setIncoming({ text: p.text, source: p.source, nonce: p.nonce });
  }, []);

  useEffect(() => {
    void chrome.storage.session.get(PENDING_KEY).then((v) => accept(v[PENDING_KEY] as PendingText | undefined));
    const onChange = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      if (area === 'session' && changes[PENDING_KEY]?.newValue) accept(changes[PENDING_KEY].newValue as PendingText);
    };
    chrome.storage.onChanged.addListener(onChange);
    return () => chrome.storage.onChanged.removeListener(onChange);
  }, [accept]);

  const scan = async () => {
    setScanning(true);
    setNotice(null);
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id === undefined) throw new Error('no active tab');
      const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: extractVisibleText, args: [12000] });
      const page = res?.result;
      if (!page?.text.trim()) throw new Error('the page has no readable text');
      remember(tab.id, page.text);
      setIncoming({ text: page.text, source: `Page: ${page.host}`, nonce: Date.now() });
    } catch (e) {
      setNotice(`${SCAN_HELP} (${e instanceof Error ? e.message : String(e)})`);
    } finally {
      setScanning(false);
    }
  };

  const onResult = async (r: CheckResult, checkedText: string) => {
    // Typed text or an example is not about any tab: no badge.
    const target = badgeTabFor(sources.current, checkedText);
    if (target === undefined) return;
    const b = badgeFor(r.verdict, r.risk);
    const scope = { tabId: target };
    await chrome.action.setBadgeBackgroundColor({ ...scope, color: b.color });
    await chrome.action.setBadgeTextColor?.({ ...scope, color: '#ffffff' });
    await chrome.action.setBadgeText({ ...scope, text: b.text });
    await chrome.action.setTitle({ ...scope, title: b.title });
  };

  return (
    <ScamShieldApp
      ai={ai}
      variant="panel"
      incoming={incoming}
      autoCheckIncoming
      notice={notice}
      onResult={(r, checkedText) => void onResult(r, checkedText).catch(() => undefined)}
      onEdit={() => {
        // The text box no longer holds a page text: no tab gets a badge for what comes next.
        sources.current = [];
      }}
      actions={
        <button type="button" className="ss-btn ss-btn-ghost" onClick={() => void scan()} disabled={scanning}>
          <IconPage size={16} /> {scanning ? 'Reading page…' : 'Scan this page'}
        </button>
      }
    />
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <Panel />
    </ErrorBoundary>
  </StrictMode>,
);
