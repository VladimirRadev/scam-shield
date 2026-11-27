/**
 * Chrome's built-in Prompt API (Gemini Nano). Minimal typings plus helpers:
 * `onDeviceStatus()`, `downloadOnDeviceModel()` and the session-wide failure flag.
 *
 * The same create-options object is handed to the Firebase SDK (`onDeviceParams.createOptions`),
 * because the SDK decides "on-device available" by calling
 * `LanguageModel.availability(createOptions)` with exactly these options.
 *
 * `availability()` can say "available" on a device that still cannot run the model (for example
 * Chrome on a machine with only a software GPU: `create()` then throws InvalidStateError
 * "The device is unable to create a session to run the model"). So "available" is confirmed by
 * creating one real session once per page session; any later on-device failure also marks the
 * model as failed until the page is reloaded.
 */
import type { LanguageModelCreateOptions } from 'firebase/ai';

export type OnDeviceStatus = 'available' | 'downloadable' | 'downloading' | 'unavailable' | 'unsupported' | 'failed';

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

let failure: string | null = null;
let probe: Promise<boolean> | null = null;

const message = (e: unknown) => (e instanceof Error ? `${e.name && e.name !== 'Error' ? `${e.name}: ` : ''}${e.message}` : String(e));

/** Mark the on-device model as not usable for the rest of this page session. */
export function markOnDeviceFailed(reason: unknown): void {
  failure = typeof reason === 'string' ? reason : message(reason);
}

/** Why the on-device model failed, or null. */
export function onDeviceFailureReason(): string | null {
  return failure;
}

/** For tests. */
export function resetOnDeviceState(): void {
  failure = null;
  probe = null;
}

function languageModel(): LanguageModelStatic | null {
  const lm = (globalThis as { LanguageModel?: LanguageModelStatic }).LanguageModel;
  return lm && typeof lm.availability === 'function' ? lm : null;
}

/** Create and destroy one session to prove the model really runs here. Cached per page session. */
function probeSession(lm: LanguageModelStatic): Promise<boolean> {
  probe ??= lm
    .create({ ...ON_DEVICE_CREATE_OPTIONS })
    .then((session) => {
      session.destroy();
      return true;
    })
    .catch((e: unknown) => {
      markOnDeviceFailed(e);
      return false;
    });
  return probe;
}

/** Fresh availability check of the on-device model. Never throws. */
export async function onDeviceStatus(): Promise<OnDeviceStatus> {
  if (failure) return 'failed';
  const lm = languageModel();
  if (!lm) return 'unsupported';
  let availability: Awaited<ReturnType<LanguageModelStatic['availability']>>;
  try {
    availability = await lm.availability(ON_DEVICE_CREATE_OPTIONS);
  } catch {
    return 'unavailable';
  }
  if (availability !== 'available') return availability;
  return (await probeSession(lm)) ? 'available' : 'failed';
}

/**
 * Start (or join) the Gemini Nano download. Must be called from a user gesture
 * (click / key press), as Chrome requires. Resolves when the model is ready.
 * `onProgress` receives 0..1.
 */
export async function downloadOnDeviceModel(onProgress: (fraction: number) => void): Promise<void> {
  const lm = languageModel();
  if (!lm) throw new Error('This browser has no built-in Prompt API (Chrome 138+ on desktop is required).');
  let session: LanguageModelSession;
  try {
    session = await lm.create({
      ...ON_DEVICE_CREATE_OPTIONS,
      monitor(m) {
        m.addEventListener('downloadprogress', (e) => onProgress(Math.max(0, Math.min(1, e.loaded))));
      },
    });
  } catch (e) {
    // Downloaded (or not) but no session can run: treat the device model as failed.
    if (/unable to create a session|InvalidStateError/i.test(message(e))) markOnDeviceFailed(e);
    throw e;
  }
  onProgress(1);
  session.destroy();
  // A working session was just created, so the probe is settled.
  probe = Promise.resolve(true);
}
