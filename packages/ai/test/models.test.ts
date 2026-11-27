import { describe, expect, it } from 'vitest';
import { InferenceMode, InferenceSource } from 'firebase/ai';
import { VERDICT_JSON_SCHEMA } from '@scamshield/core';
import { hybridParams, sdkGenerate, type ScamShieldModels } from '../src/models';
import { ON_DEVICE_CREATE_OPTIONS } from '../src/on-device';

const fakeModel = (text: string, source: string) =>
  ({ generateContent: async () => ({ response: { text: () => text, inferenceSource: source } }) }) as never;

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
    const models: ScamShieldModels = {
      quick: fakeModel('{"a":1}', InferenceSource.IN_CLOUD),
      device: fakeModel('{"b":2}', InferenceSource.ON_DEVICE),
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
    const models: ScamShieldModels = {
      quick: fakeModel('', InferenceSource.IN_CLOUD),
      device: fakeModel('{}', InferenceSource.IN_CLOUD),
      cloud: fakeModel('', InferenceSource.IN_CLOUD),
      deep: fakeModel('', InferenceSource.IN_CLOUD),
    };
    await expect(sdkGenerate(models)('raw', 'device')).rejects.toThrow(/privacy guard/);
  });
});
