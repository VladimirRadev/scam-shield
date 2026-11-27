/**
 * The side panel is a new page every time it is opened, so a Gemini Nano failure (no session, or
 * an answer that timed out) is kept in chrome.storage.session: a panel opened later in the same
 * browser session starts as "failed" and goes straight to the redacted cloud route, like the web
 * app does for the rest of its page load. Chrome clears this storage when the browser restarts.
 */
import type { OnDeviceFailureStore } from '@scamshield/ai';

export const NANO_FAILED_KEY = 'scamShieldNanoFailed';

/** The two calls of chrome.storage.StorageArea that the store needs. */
export interface SessionArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export function sessionFailureStore(area: SessionArea): OnDeviceFailureStore {
  return {
    async load() {
      const v = (await area.get(NANO_FAILED_KEY))[NANO_FAILED_KEY];
      return typeof v === 'string' && v ? v : null;
    },
    save: (reason) => area.set({ [NANO_FAILED_KEY]: reason }),
  };
}
