import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createScamShieldAI } from '../src/index';
import { resetOnDeviceState, type OnDeviceFailureStore } from '../src/on-device';

type G = { LanguageModel?: unknown };

describe('createScamShieldAI() failure store option', () => {
  beforeEach(() => {
    resetOnDeviceState();
    (globalThis as G).LanguageModel = { availability: vi.fn(async () => 'available'), create: vi.fn(async () => ({ destroy() {} })) };
  });
  afterEach(() => {
    delete (globalThis as G).LanguageModel;
    resetOnDeviceState();
  });

  it('with a store holding an earlier failure, the status is "failed" from the first check (side panel)', async () => {
    const failureStore: OnDeviceFailureStore = { load: async () => 'OnDeviceTimeoutError: Gemini Nano answer timed out after 90 s', save: vi.fn() };
    const ai = createScamShieldAI({}, { isExtension: true, allowDebugToken: true, failureStore });
    expect(await ai.status()).toBe('failed');
  });

  it('without a store, a fresh page starts from the real availability (web app)', async () => {
    const ai = createScamShieldAI({}, { isExtension: false, allowDebugToken: false });
    expect(await ai.status()).toBe('available');
  });
});
