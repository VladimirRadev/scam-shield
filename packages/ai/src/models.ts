/**
 * Firebase AI Logic hybrid inference models.
 *
 * - quick  : InferenceMode.PREFER_ON_DEVICE. Gemini Nano in Chrome when available, otherwise
 *            the cloud model. It only ever receives REDACTED text.
 * - device : InferenceMode.ONLY_ON_DEVICE twin of `quick` (identical on-device params). The RAW
 *            text is sent only through this model, so the SDK can never fall back to the cloud
 *            with raw text; it throws instead and the engine retries `quick` with redacted text.
 * - deep   : InferenceMode.ONLY_IN_CLOUD, used after explicit consent with redacted text.
 *
 * The answer's `response.inferenceSource` ("on_device" | "in_cloud") tells which backend ran.
 */
import {
  getGenerativeModel,
  InferenceMode,
  InferenceSource,
  ThinkingLevel,
  type AI,
  type GenerationConfig,
  type GenerativeModel,
  type HybridParams,
} from 'firebase/ai';
import { VERDICT_JSON_SCHEMA, type Generate, type Route } from '@scamshield/core';
import { ON_DEVICE_CREATE_OPTIONS } from './on-device';

export interface ScamShieldModels {
  quick: GenerativeModel;
  device: GenerativeModel;
  deep: GenerativeModel;
}

const cloudGenerationConfig = (thinkingLevel: ThinkingLevel): GenerationConfig => ({
  responseMimeType: 'application/json',
  responseJsonSchema: VERDICT_JSON_SCHEMA as unknown as Record<string, unknown>,
  maxOutputTokens: 2048,
  thinkingConfig: { thinkingLevel },
});

export function hybridParams(mode: InferenceMode, cloudModel: string, thinkingLevel: ThinkingLevel = ThinkingLevel.LOW): HybridParams {
  return {
    mode,
    onDeviceParams: {
      createOptions: { ...ON_DEVICE_CREATE_OPTIONS },
      // Chrome Prompt API structured output: constrains Gemini Nano to the verdict JSON schema.
      promptOptions: { responseConstraint: VERDICT_JSON_SCHEMA },
    },
    inCloudParams: {
      model: cloudModel,
      generationConfig: cloudGenerationConfig(thinkingLevel),
    },
  };
}

export function createModels(ai: AI, cloudModel: string): ScamShieldModels {
  return {
    quick: getGenerativeModel(ai, hybridParams(InferenceMode.PREFER_ON_DEVICE, cloudModel)),
    device: getGenerativeModel(ai, hybridParams(InferenceMode.ONLY_ON_DEVICE, cloudModel)),
    deep: getGenerativeModel(ai, {
      mode: InferenceMode.ONLY_IN_CLOUD,
      inCloudParams: { model: cloudModel, generationConfig: cloudGenerationConfig(ThinkingLevel.MEDIUM) },
    }),
  };
}

/** The engine's `Generate` function, backed by the Firebase AI Logic SDK. */
export function sdkGenerate(models: ScamShieldModels): Generate {
  const pick: Record<Route, GenerativeModel> = { device: models.device, hybrid: models.quick, cloud: models.deep };
  return async (prompt, route) => {
    const result = await pick[route].generateContent(prompt);
    const source = result.response.inferenceSource === InferenceSource.ON_DEVICE ? 'on-device' : 'cloud';
    if (route === 'device' && source !== 'on-device') {
      // Cannot happen with ONLY_ON_DEVICE; kept as a hard privacy assertion.
      throw new Error('privacy guard: raw text route did not run on the device');
    }
    return { text: result.response.text(), source };
  };
}
