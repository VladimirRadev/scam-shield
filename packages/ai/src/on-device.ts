/**
 * Chrome's built-in Prompt API (Gemini Nano). Minimal typings plus two helpers:
 * `onDeviceStatus()` and `downloadOnDeviceModel()`.
 *
 * The same create-options object is handed to the Firebase SDK (`onDeviceParams.createOptions`),
 * because the SDK decides "on-device available" by calling
 * `LanguageModel.availability(createOptions)` with exactly these options.
 */
import type { LanguageModelCreateOptions } from 'firebase/ai';

export type OnDeviceStatus = 'available' | 'downloadable' | 'downloading' | 'unavailable' | 'unsupported';

interface LanguageModelSession {
  destroy(): void;
}

interface LanguageModelStatic {
  availability(options?: LanguageModelCreateOptions): Promise<'available' | 'downloadable' | 'downloading' | 'unavailable'>;
  create(options?: LanguageModelCreateOptions): Promise<LanguageModelSession>;
}

/** English text in, English text out. No image input, so availability does not depend on it. */
export const ON_DEVICE_CREATE_OPTIONS: LanguageModelCreateOptions = {
  expectedInputs: [{ type: 'text', languages: ['en'] }],
  expectedOutputs: [{ type: 'text', languages: ['en'] }],
};

function languageModel(): LanguageModelStatic | null {
  const lm = (globalThis as { LanguageModel?: LanguageModelStatic }).LanguageModel;
  return lm && typeof lm.availability === 'function' ? lm : null;
}

/** Fresh availability check of the on-device model. Never throws. */
export async function onDeviceStatus(): Promise<OnDeviceStatus> {
  const lm = languageModel();
  if (!lm) return 'unsupported';
  try {
    return await lm.availability(ON_DEVICE_CREATE_OPTIONS);
  } catch {
    return 'unavailable';
  }
}

/**
 * Start (or join) the Gemini Nano download. Must be called from a user gesture
 * (click / key press), as Chrome requires. Resolves when the model is ready.
 * `onProgress` receives 0..1.
 */
export async function downloadOnDeviceModel(onProgress: (fraction: number) => void): Promise<void> {
  const lm = languageModel();
  if (!lm) throw new Error('This browser has no built-in Prompt API (Chrome 138+ on desktop is required).');
  const session = await lm.create({
    ...ON_DEVICE_CREATE_OPTIONS,
    monitor(m) {
      m.addEventListener('downloadprogress', (e) => onProgress(Math.max(0, Math.min(1, e.loaded))));
    },
  });
  onProgress(1);
  session.destroy();
}
