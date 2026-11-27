/**
 * One quick check at a time. A text that arrives from outside while a check runs (a context-menu
 * selection or a page scan in the extension) waits and runs right after the current check; only
 * the newest waiting text is kept. A manual submit while busy is ignored (the button is disabled).
 */
export interface CheckQueue {
  submit(text: string, opts?: { queue?: boolean }): void;
  /** Forget the waiting text (the user started editing). */
  cancelQueued(): void;
  running(): boolean;
}

export function createCheckQueue(run: (text: string) => Promise<void>): CheckQueue {
  let busy = false;
  let waiting: string | null = null;
  const start = (text: string) => {
    busy = true;
    void run(text)
      .catch((e: unknown) => console.error('[scam-shield] check failed', e))
      .finally(() => {
        busy = false;
        const next = waiting;
        waiting = null;
        if (next !== null) start(next);
      });
  };
  return {
    submit(text, opts = {}) {
      if (!text.trim()) return;
      if (!busy) start(text);
      else if (opts.queue) waiting = text;
    },
    cancelQueued() {
      waiting = null;
    },
    running: () => busy,
  };
}
