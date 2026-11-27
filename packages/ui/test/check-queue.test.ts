import { describe, expect, it } from 'vitest';
import { createCheckQueue } from '../src/check-queue';

function deferredRun() {
  const calls: string[] = [];
  const resolvers: Array<() => void> = [];
  const run = (text: string) =>
    new Promise<void>((resolve) => {
      calls.push(text);
      resolvers.push(resolve);
    });
  const finish = async () => {
    resolvers.shift()?.();
    // let the queue's continuation run
    await new Promise((r) => setTimeout(r, 0));
  };
  return { calls, run, finish };
}

describe('createCheckQueue()', () => {
  it('runs a text at once when idle', () => {
    const d = deferredRun();
    const q = createCheckQueue(d.run);
    q.submit('a');
    expect(d.calls).toEqual(['a']);
    expect(q.running()).toBe(true);
  });

  it('queues a text that arrives while a check runs and runs it afterwards', async () => {
    const d = deferredRun();
    const q = createCheckQueue(d.run);
    q.submit('first');
    q.submit('page text', { queue: true });
    expect(d.calls).toEqual(['first']);
    await d.finish();
    expect(d.calls).toEqual(['first', 'page text']);
    await d.finish();
    expect(q.running()).toBe(false);
  });

  it('keeps only the newest queued text', async () => {
    const d = deferredRun();
    const q = createCheckQueue(d.run);
    q.submit('first');
    q.submit('older', { queue: true });
    q.submit('newest', { queue: true });
    await d.finish();
    expect(d.calls).toEqual(['first', 'newest']);
  });

  it('drops a manual submit while busy, and cancel() forgets the queued text', async () => {
    const d = deferredRun();
    const q = createCheckQueue(d.run);
    q.submit('first');
    q.submit('typed again');
    q.submit('page text', { queue: true });
    q.cancelQueued();
    await d.finish();
    expect(d.calls).toEqual(['first']);
  });

  it('ignores blank text and survives a failing run', async () => {
    const calls: string[] = [];
    const q = createCheckQueue(async (t) => {
      calls.push(t);
      throw new Error('boom');
    });
    q.submit('   ');
    expect(calls).toEqual([]);
    q.submit('x');
    q.submit('y', { queue: true });
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toEqual(['x', 'y']);
  });
});
