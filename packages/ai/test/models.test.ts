import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { initializeApp } from 'firebase/app';
import { getAI, GoogleAIBackend, InferenceMode, InferenceSource } from 'firebase/ai';
import { VERDICT_JSON_SCHEMA } from '@scamshield/core';
import { createModels, hybridParams, OnDeviceUnavailableError, sdkGenerate, type ScamShieldModels } from '../src/models';
import { ON_DEVICE_CREATE_OPTIONS, resetOnDeviceState } from '../src/on-device';

type G = { LanguageModel?: unknown };

const fakeModel = (text: string, source: string, extra: Record<string, unknown> = {}) =>
  ({ ...extra, generateContent: vi.fn(async () => ({ response: { text: () => text, inferenceSource: source } })) }) as never;

/** The SDK sets `chromeAdapter` on a model only when the page has the Prompt API. */
const deviceModel = (text: string, source: string = InferenceSource.ON_DEVICE) => fakeModel(text, source, { chromeAdapter: {} });

function stubLanguageModel(availability: string, create: () => Promise<unknown> = async () => ({ destroy() {} })) {
  (globalThis as G).LanguageModel = { availability: vi.fn(async () => availability), create: vi.fn(create) };
}

beforeEach(() => resetOnDeviceState());
afterEach(() => {
  delete (globalThis as G).LanguageModel;
  resetOnDeviceState();
  vi.unstubAllGlobals();
});

describe('hybridParams()', () => {
  it('builds PREFER_ON_DEVICE params with structured output for both backends', () => {
    const p = hybridParams(InferenceMode.PREFER_ON_DEVICE, 'gemini-3.5-flash-lite');
    expect(p.mode).toBe('prefer_on_device');
    expect(p.onDeviceParams?.createOptions?.expectedInputs).toEqual(ON_DEVICE_CREATE_OPTIONS.expectedInputs);
    expect(p.onDeviceParams?.promptOptions?.responseConstraint).toBe(VERDICT_JSON_SCHEMA);
    expect(p.inCloudParams?.model).toBe('gemini-3.5-flash-lite');
    expect(p.inCloudParams?.generationConfig?.responseMimeType).toBe('application/json');
    expect(p.inCloudParams?.generationConfig?.responseJsonSchema).toBe(VERDICT_JSON_SCHEMA);
  });
});

describe('sdkGenerate()', () => {
  it('maps the SDK inferenceSource to the engine source', async () => {
    stubLanguageModel('available');
    const models: ScamShieldModels = {
      quick: fakeModel('{"a":1}', InferenceSource.IN_CLOUD),
      device: deviceModel('{"b":2}'),
      cloud: fakeModel('{"d":4}', InferenceSource.IN_CLOUD),
      deep: fakeModel('{"c":3}', InferenceSource.IN_CLOUD),
    };
    const gen = sdkGenerate(models);
    expect(await gen('p', 'hybrid')).toEqual({ text: '{"a":1}', source: 'cloud' });
    expect(await gen('p', 'device')).toEqual({ text: '{"b":2}', source: 'on-device' });
    expect(await gen('p', 'cloud')).toEqual({ text: '{"d":4}', source: 'cloud' });
    expect(await gen('p', 'deep')).toEqual({ text: '{"c":3}', source: 'cloud' });
  });

  it('refuses a raw-text answer that did not come from the device', async () => {
    stubLanguageModel('available');
    const models: ScamShieldModels = {
      quick: fakeModel('', InferenceSource.IN_CLOUD),
      device: deviceModel('{}', InferenceSource.IN_CLOUD),
      cloud: fakeModel('', InferenceSource.IN_CLOUD),
      deep: fakeModel('', InferenceSource.IN_CLOUD),
    };
    await expect(sdkGenerate(models)('raw', 'device')).rejects.toThrow(/privacy guard/);
  });
});

describe('sdkGenerate() raw-text guard on the device route', () => {
  const RAW = 'RAW TEXT: Hi Elena, my IBAN is DE89370400440532013000';

  it('makes no network request when the page has no LanguageModel (real SDK, fetch mocked)', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ candidates: [{ content: { role: 'model', parts: [{ text: '{"risk":5,"verdict":"safe","category":"none","reasons":[],"advice":"ok"}' }] }, finishReason: 'STOP' }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);
    expect(typeof (globalThis as G).LanguageModel).toBe('undefined');
    const app = initializeApp({ apiKey: 'demo-key', projectId: 'demo-proj', appId: '1:1:web:1' }, `guard-${Date.now()}`);
    const models = createModels(getAI(app, { backend: new GoogleAIBackend() }), 'gemini-3.5-flash-lite');

    const err = await sdkGenerate(models)(RAW, 'device').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OnDeviceUnavailableError);
    expect((err as OnDeviceUnavailableError).requestSent).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refuses when the ONLY_ON_DEVICE model has no on-device adapter, even if LanguageModel exists now', async () => {
    stubLanguageModel('available');
    const device = fakeModel('{}', InferenceSource.ON_DEVICE);
    const models = { quick: device, device, cloud: device, deep: device } as ScamShieldModels;
    await expect(sdkGenerate(models)(RAW, 'device')).rejects.toBeInstanceOf(OnDeviceUnavailableError);
    expect((device as unknown as { generateContent: ReturnType<typeof vi.fn> }).generateContent).not.toHaveBeenCalled();
  });

  it.each([
    ['downloadable', async () => ({ destroy() {} })],
    ['available', async () => Promise.reject(new Error('The device is unable to create a session to run the model'))],
  ] as const)('refuses when the on-device status is not "available" (%s)', async (availability, create) => {
    stubLanguageModel(availability, create);
    const device = deviceModel('{}');
    const models = { quick: device, device, cloud: device, deep: device } as ScamShieldModels;
    await expect(sdkGenerate(models)(RAW, 'device')).rejects.toBeInstanceOf(OnDeviceUnavailableError);
    expect((device as unknown as { generateContent: ReturnType<typeof vi.fn> }).generateContent).not.toHaveBeenCalled();
  });
});
