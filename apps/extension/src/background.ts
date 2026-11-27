/// <reference types="chrome" />
/**
 * Service worker: context-menu entries, opening the side panel, and reading text from the
 * tab the user pointed at (activeTab + scripting; granted by the context-menu click).
 */
import { extractVisibleText, readSelection } from './page-text';
import { PENDING_KEY, type PendingText } from './pending';

const MENU_SELECTION = 'scam-shield-check-selection';
const MENU_PAGE = 'scam-shield-scan-page';
const MAX_PAGE_CHARS = 12000;

function setup() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU_SELECTION, title: 'Check with Scam Shield', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU_PAGE, title: 'Scan this page with Scam Shield', contexts: ['page'] });
  });
  void chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
}

chrome.runtime.onInstalled.addListener(setup);
chrome.runtime.onStartup.addListener(setup);

async function push(p: Omit<PendingText, 'nonce'>) {
  await chrome.storage.session.set({ [PENDING_KEY]: { ...p, nonce: Date.now() } satisfies PendingText });
}

async function runInTab<T>(tabId: number, func: (...args: never[]) => T, args: unknown[] = []): Promise<T | undefined> {
  const [res] = await chrome.scripting.executeScript({ target: { tabId }, func: func as () => T, args: args as [] });
  return res?.result as T | undefined;
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab || tab.windowId === undefined) return;
  // sidePanel.open() must be called synchronously inside the user gesture.
  void chrome.sidePanel.open({ windowId: tab.windowId });
  const tabId = tab.id;

  if (info.menuItemId === MENU_SELECTION) {
    const fallback = info.selectionText ?? '';
    const read = tabId === undefined ? Promise.resolve(undefined) : runInTab(tabId, readSelection).catch(() => undefined);
    void read.then((sel) => push({ text: sel?.trim() ? sel : fallback, source: 'Selected text', tabId }));
  }

  if (info.menuItemId === MENU_PAGE && tabId !== undefined) {
    void runInTab(tabId, extractVisibleText, [MAX_PAGE_CHARS])
      .then((page) => push({ text: page?.text ?? '', source: `Page: ${page?.host ?? 'this tab'}`, tabId }))
      .catch((e: unknown) => push({ text: '', source: 'This page', tabId, error: e instanceof Error ? e.message : String(e) }));
  }
});
