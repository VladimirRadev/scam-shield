/**
 * Firebase AI Logic hybrid inference models.
 *
 * - quick  : InferenceMode.PREFER_ON_DEVICE. Gemini Nano in Chrome when available, otherwise
 *            the cloud model. It only ever receives REDACTED text.
 * - device : InferenceMode.ONLY_ON_DEVICE twin of `quick` (identical on-device params). The RAW
 *            text is sent only through this model, so the SDK can never fall back to the cloud
 *            with raw text; it throws instead and the engine retries `quick` with redacted text.
 * - cloud  : InferenceMode.ONLY_IN_CLOUD, quick-check fallback with redacted text when Gemini Nano
 *            reports "available" but cannot run (PREFER_ON_DEVICE would pick the broken device).
 * - deep   : InferenceMode.ONLY_IN_CLOUD, used after explicit consent with redacted text.
 *
 * The answer's `response.inferenceSource` ("on_device" | "in_cloud") tells which backend ran.
 *
 * Raw-text guard: the SDK builds its on-device adapter only when `globalThis.LanguageModel`
 * exists when the model is created. Without that adapter even an ONLY_ON_DEVICE model sends the
 * request to the cloud. So `sdkGenerate()` refuses the `device` route (no SDK call, no network)
 * unless the Prompt API exists, the model has its adapter and `onDeviceStatus()` is "available".
 */
import {
  AIError,
  AIErrorCode,
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
import {
  markOnDeviceFailed,
  markOnDeviceWarm,
  ON_DEVICE_CREATE_OPTIONS,
  onDeviceCallTimeoutMs,
  onDeviceStatus,
  OnDeviceTimeoutError,
  withTimeout,
  type OnDeviceStatus,
} from './on-device';

export interface ScamShieldModels {
  quick: GenerativeModel;
  device: GenerativeModel;
  cloud: GenerativeModel;
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
    cloud: getGenerativeModel(ai, {
      mode: InferenceMode.ONLY_IN_CLOUD,
      inCloudParams: { model: cloudModel, generationConfig: cloudGenerationConfig(ThinkingLevel.LOW) },
    }),
    deep: getGenerativeModel(ai, {
      mode: InferenceMode.ONLY_IN_CLOUD,
      inCloudParams: { model: cloudModel, generationConfig: cloudGenerationConfig(ThinkingLevel.MEDIUM) },
    }),
  };
}

/** The raw-text route was refused before any SDK call: nothing left the device. */
export class OnDeviceUnavailableError extends Error {
  override readonly name = 'OnDeviceUnavailableError';
  /** Read by the engine: this refusal happened before any request was issued. */
  readonly requestSent = false;
}

/** True when the SDK gave this model its Chrome on-device adapter (it did only if LanguageModel existed). */
export function hasOnDeviceAdapter(model: GenerativeModel): boolean {
  return Boolean((model as unknown as { chromeAdapter?: unknown }).chromeAdapter);
}

export interface SdkGenerateOptions {
  /** Fresh on-device status; defaults to `onDeviceStatus()` (it also reports a session-wide failure). */
  deviceStatus?: () => Promise<OnDeviceStatus>;
}

/** Throws `OnDeviceUnavailableError` unless the raw text can only be processed on this device. */
async function assertOnDeviceOnly(model: GenerativeModel, status: () => Promise<OnDeviceStatus>): Promise<void> {
  if (typeof (globalThis as { LanguageModel?: unknown }).LanguageModel === 'undefined') {
    throw new OnDeviceUnavailableError('raw text not sent: this browser has no on-device Prompt API (LanguageModel)');
  }
  if (!hasOnDeviceAdapter(model)) {
    throw new OnDeviceUnavailableError('raw text not sent: the on-device model was created without its on-device adapter');
  }
  const s = await status();
  if (s !== 'available') throw new OnDeviceUnavailableError(`raw text not sent: the on-device model is ${s}`);
}

/**
 * Did this SDK error happen after the cloud request was handed to the network?
 * - FETCH_ERROR: the server answered with an HTTP error (or the WebSocket failed);
 * - API_NOT_ENABLED with an HTTP status: the server answered 403;
 * - RESPONSE_ERROR / PARSE_FAILED: an answer arrived but was blocked or unreadable;
 * - ERROR "Error fetching from ...": fetch() itself failed. The bytes may or may not have left,
 *   so this counts as sent (the result must never claim "nothing left the device" by mistake);
 * - AbortError: the SDK's fetch timeout aborted a request in flight.
 * Everything else (UNSUPPORTED, INVALID_CONTENT, REQUEST_ERROR, NO_*, errors that are not an
 * AIError) is a refusal before any request.
 */
export function cloudRequestIssued(e: unknown): boolean {
  if (e instanceof Error && e.name === 'AbortError') return true;
  if (!(e instanceof AIError)) return false;
  switch (e.code) {
    case AIErrorCode.FETCH_ERROR:
    case AIErrorCode.RESPONSE_ERROR:
    case AIErrorCode.PARSE_FAILED:
      return true;
    case AIErrorCode.API_NOT_ENABLED:
      return typeof e.customErrorData?.status === 'number';
    case AIErrorCode.ERROR:
      return /Error fetching from/.test(e.message);
    default:
      return false;
  }
}

/** Attach `requestSent` (read by the engine's `requestWasSent()`) to a thrown value. */
function withRequestSent(e: unknown, sent: boolean): Error {
  const err = e instanceof Error ? e : new Error(String(e));
  try {
    Object.defineProperty(err, 'requestSent', { value: sent, configurable: true });
  } catch {
    // A frozen error: rethrow a plain one that carries the flag.
    return Object.assign(new Error(err.message), { name: err.name, requestSent: sent });
  }
  return err;
}

/** The engine's `Generate` function, backed by the Firebase AI Logic SDK. */
export function sdkGenerate(models: ScamShieldModels, opts: SdkGenerateOptions = {}): Generate {
  const pick: Record<Route, GenerativeModel> = { device: models.device, hybrid: models.quick, cloud: models.cloud, deep: models.deep };
  const deviceStatus = opts.deviceStatus ?? onDeviceStatus;
  return async (prompt, route) => {
    if (route === 'device') await assertOnDeviceOnly(models.device, deviceStatus);
    let result: Awaited<ReturnType<GenerativeModel['generateContent']>>;
    try {
      if (route === 'device') {
        // A hanging Gemini Nano must not block the check: time out, mark it failed for this page
        // load, and let the engine retry with redacted text in the cloud.
        result = await withTimeout(models.device.generateContent(prompt), onDeviceCallTimeoutMs(), 'Gemini Nano answer');
        markOnDeviceWarm();
      } else {
        result = await pick[route].generateContent(prompt);
      }
    } catch (e) {
      if (e instanceof OnDeviceTimeoutError) {
        markOnDeviceFailed(e);
        throw e;
      }
      throw withRequestSent(e, route !== 'device' && cloudRequestIssued(e));
    }
    const source = result.response.inferenceSource === InferenceSource.ON_DEVICE ? 'on-device' : 'cloud';
    if (route === 'device' && source !== 'on-device') {
      // Cannot happen with ONLY_ON_DEVICE and its adapter; kept as a hard privacy assertion.
      throw withRequestSent(new Error('privacy guard: raw text route did not run on the device'), true);
    }
    try {
      return { text: result.response.text(), source };
    } catch (e) {
      // A blocked or empty answer: the request left the device if the cloud answered it.
      throw withRequestSent(e, source === 'cloud');
    }
  };
}
