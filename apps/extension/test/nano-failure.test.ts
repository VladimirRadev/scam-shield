import { describe, expect, it } from 'vitest';
import { NANO_FAILED_KEY, sessionFailureStore } from '../src/nano-failure';

/** chrome.storage.session stand-in with the two calls the store uses. */
function fakeArea(initial: Record<string, unknown> = {}) {
  const data: Record<string, unknown> = { ...initial };
  return {
    data,
    async get(key: string) {
      return key in data ? { [key]: data[key] } : {};
    },
    async set(items: Record<string, unknown>) {
      Object.assign(data, items);
    },
  };
}

describe('sessionFailureStore()', () => {
  it('saves the failure reason in chrome.storage.session and reads it back', async () => {
    const area = fakeArea();
    const store = sessionFailureStore(area);
    expect(await store.load()).toBeNull();
    await store.save('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s');
    expect(area.data[NANO_FAILED_KEY]).toBe('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s');
    // A side panel opened later reads the same browser-session storage.
    expect(await sessionFailureStore(area).load()).toBe('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s');
  });

  it('ignores a stored value that is not a non-empty string', async () => {
    expect(await sessionFailureStore(fakeArea({ [NANO_FAILED_KEY]: 42 })).load()).toBeNull();
    expect(await sessionFailureStore(fakeArea({ [NANO_FAILED_KEY]: '' })).load()).toBeNull();
  });

  it('does not share the key of the pending page text', async () => {
    const { PENDING_KEY } = await import('../src/pending');
    expect(NANO_FAILED_KEY).not.toBe(PENDING_KEY);
  });
});
