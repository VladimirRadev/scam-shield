/**
 * Runs INSIDE the inspected tab via chrome.scripting.executeScript, so it must be
 * self-contained (no imports, no closures). Returns the visible text of the page plus the
 * external domains its links point to (link text often hides a look-alike address).
 */
export interface PageText {
  text: string;
  host: string;
  title: string;
}

export function extractVisibleText(maxChars: number): PageText {
  const visible = (document.body?.innerText ?? '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  const hosts: string[] = [];
  for (const a of Array.from(document.querySelectorAll('a[href]'))) {
    try {
      const u = new URL((a as HTMLAnchorElement).href);
      if (/^https?:$/.test(u.protocol) && u.hostname !== location.hostname && !hosts.includes(u.hostname)) hosts.push(u.hostname);
    } catch {
      /* ignore malformed links */
    }
    if (hosts.length >= 40) break;
  }
  let text = `Web page: ${location.origin}\nTitle: ${document.title}\n\n${visible.slice(0, maxChars)}`;
  if (hosts.length) text += `\n\nLinks on this page go to: ${hosts.join(', ')}`;
  return { text, host: location.hostname, title: document.title };
}

/** Runs inside the tab: the current selection with its line breaks (selectionText flattens them). */
export function readSelection(): string {
  return window.getSelection()?.toString() ?? '';
}
