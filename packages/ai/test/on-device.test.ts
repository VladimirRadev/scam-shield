import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ON_DEVICE_STARTUP_TIMEOUT_MS,
  OnDeviceTimeoutError,
  downloadOnDeviceModel,
  markOnDeviceFailed,
  onDeviceFailureReason,
  onDeviceStatus,
  resetOnDeviceState,
  setOnDeviceFailureStore,
  type OnDeviceFailureStore,
} from '../src/on-device';

type G = { LanguageModel?: unknown };

function stubLanguageModel(availability: string, create: () => Promise<unknown>) {
  (globalThis as G).LanguageModel = { availability: vi.fn(async () => availability), create: vi.fn(create) };
  return (globalThis as G).LanguageModel as { availability: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn> };
}

describe('on-device status', () => {
  beforeEach(() => resetOnDeviceState());
  afterEach(() => {
    delete (globalThis as G).LanguageModel;
    resetOnDeviceState();
  });

  it('is "unsupported" without the Prompt API', async () => {
    expect(await onDeviceStatus()).toBe('unsupported');
  });

  it('is "available" when a session can really be created', async () => {
    const destroy = vi.fn();
    const lm = stubLanguageModel('available', async () => ({ destroy }));
    expect(await onDeviceStatus()).toBe('available');
    expect(destroy).toHaveBeenCalled();
    // The probe runs once per session, not on every status check.
    await onDeviceStatus();
    expect(lm.create).toHaveBeenCalledTimes(1);
  });

  it('is "failed" when availability() says available but create() throws (no usable GPU)', async () => {
    stubLanguageModel('available', async () => {
      throw Object.assign(new Error('The device is unable to create a session to run the model'), { name: 'InvalidStateError' });
    });
    expect(await onDeviceStatus()).toBe('failed');
    expect(onDeviceFailureReason()).toMatch(/unable to create a session/);
  });

  it('stays "failed" for the session once an on-device call failed', async () => {
    stubLanguageModel('available', async () => ({ destroy() {} }));
    expect(await onDeviceStatus()).toBe('available');
    markOnDeviceFailed('InvalidStateError: session lost');
    expect(await onDeviceStatus()).toBe('failed');
  });

  it('does not probe a model that is still downloadable (no user gesture yet)', async () => {
    const lm = stubLanguageModel('downloadable', async () => ({ destroy() {} }));
    expect(await onDeviceStatus()).toBe('downloadable');
    expect(lm.create).not.toHaveBeenCalled();
  });

  it('marks the model failed when the download finishes but no session can start', async () => {
    stubLanguageModel('downloadable', async () => {
      throw new Error('The device is unable to create a session to run the model');
    });
    await expect(downloadOnDeviceModel(() => {})).rejects.toThrow(/unable to create a session/);
    expect(await onDeviceStatus()).toBe('failed');
  });
});

describe('on-device start-up timeout', () => {
  beforeEach(() => {
    resetOnDeviceState();
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
    delete (globalThis as G).LanguageModel;
    resetOnDeviceState();
  });

  it('marks the model failed when the start-up session does not open within 60 s', async () => {
    stubLanguageModel('available', () => new Promise(() => {}));
    let status: string | null = null;
    void onDeviceStatus().then((s) => (status = s));
    await vi.advanceTimersByTimeAsync(ON_DEVICE_STARTUP_TIMEOUT_MS - 1);
    expect(status).toBeNull();
    await vi.advanceTimersByTimeAsync(1);
    expect(status).toBe('failed');
    expect(onDeviceFailureReason()).toMatch(/timed out after 60 s/);
  });

  it('closes a session that opens after the timeout', async () => {
    const destroy = vi.fn();
    let open: (s: unknown) => void = () => {};
    stubLanguageModel('available', () => new Promise((r) => (open = r)));
    void onDeviceStatus();
    await vi.advanceTimersByTimeAsync(ON_DEVICE_STARTUP_TIMEOUT_MS);
    open({ destroy });
    await vi.advanceTimersByTimeAsync(0);
    expect(destroy).toHaveBeenCalled();
  });
});

/** chrome.storage.session stand-in: one value that outlives the page (the side panel document). */
function memoryStore(initial: string | null = null) {
  let value = initial;
  const store: OnDeviceFailureStore = {
    load: vi.fn(async () => value),
    save: vi.fn(async (reason: string) => {
      value = reason;
    }),
  };
  return { store, value: () => value };
}

describe('failure store: the failed state outlives the page (extension side panel)', () => {
  beforeEach(() => resetOnDeviceState());
  afterEach(() => {
    delete (globalThis as G).LanguageModel;
    resetOnDeviceState();
  });

  it('a failure saved by an earlier panel makes the status "failed" without probing Gemini Nano again', async () => {
    const lm = stubLanguageModel('available', async () => ({ destroy() {} }));
    setOnDeviceFailureStore(memoryStore('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s').store);
    expect(await onDeviceStatus()).toBe('failed');
    expect(onDeviceFailureReason()).toBe('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s');
    expect(lm.availability).not.toHaveBeenCalled();
    expect(lm.create).not.toHaveBeenCalled();
  });

  it('a timeout is saved, and the next panel (a new page) starts as "failed"', async () => {
    stubLanguageModel('available', async () => ({ destroy() {} }));
    const mem = memoryStore();
    setOnDeviceFailureStore(mem.store);
    expect(await onDeviceStatus()).toBe('available');
    markOnDeviceFailed(new OnDeviceTimeoutError('Gemini Nano answer timed out after 90 s'));
    await vi.waitFor(() => expect(mem.value()).toBe('OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s'));

    // The user closes the side panel and opens it again: module state is gone, the store is not.
    resetOnDeviceState();
    setOnDeviceFailureStore(mem.store);
    expect(await onDeviceStatus()).toBe('failed');
    expect(onDeviceFailureReason()).toMatch(/timed out after 90 s/);
  });

  it('without a store the failure lasts for the page load only (web app)', async () => {
    stubLanguageModel('available', async () => ({ destroy() {} }));
    markOnDeviceFailed('InvalidStateError: session lost');
    expect(await onDeviceStatus()).toBe('failed');
    resetOnDeviceState();
    expect(await onDeviceStatus()).toBe('available');
  });

  it('a store that cannot be read or written never breaks the status', async () => {
    stubLanguageModel('available', async () => ({ destroy() {} }));
    setOnDeviceFailureStore({
      load: async () => Promise.reject(new Error('storage unavailable')),
      save: () => {
        throw new Error('quota exceeded');
      },
    });
    expect(await onDeviceStatus()).toBe('available');
    expect(() => markOnDeviceFailed('InvalidStateError: session lost')).not.toThrow();
    expect(await onDeviceStatus()).toBe('failed');
  });
});
