import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  downloadOnDeviceModel,
  markOnDeviceFailed,
  onDeviceFailureReason,
  onDeviceStatus,
  resetOnDeviceState,
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
