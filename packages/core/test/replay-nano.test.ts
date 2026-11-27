import { describe, expect, it } from 'vitest';
import { loadFixture, replay, replayMarkdown } from '../scripts/replay-nano';
import { analyzeLocal, DEFAULT_THRESHOLDS, MODEL_ONLY_MIN_RISK } from '../src/engine';
import { EXAMPLES } from '../src/examples';
import { summarizeRoute } from '../src/metrics';
import { parseModelVerdict } from '../src/prompt';

// 50 raw Gemini Nano answers (prompt v1, CPU backend) recorded by E2E run 45965556713.
const fixture = loadFixture();
const t = DEFAULT_THRESHOLDS;

describe('replay of recorded Gemini Nano answers', () => {
  it('holds one parseable answer per example, in eval order', () => {
    expect(fixture.promptVersion).toBe('v1');
    expect(fixture.answers.map((a) => a.id)).toEqual(EXAMPLES.map((e) => e.id));
    for (const a of fixture.answers) expect(parseModelVerdict(a.out).ok, a.id).toBe(true);
  });

  it('reproduces the recorded run except where the corroboration rule applies', async () => {
    const rows = await replay(fixture);
    for (const r of rows) {
      const local = analyzeLocal(EXAMPLES.find((e) => e.id === r.id)!.text);
      const silent = local.score.hard === 0 && local.score.total < t.suspicious;
      const modelRisk = r.result.modelRisk!;
      const cap = modelRisk >= MODEL_ONLY_MIN_RISK ? t.scam - 1 : t.suspicious - 1;
      const expected = silent ? Math.min(r.before.risk, cap) : r.before.risk;
      expect(r.after.risk, r.id).toBe(expected);
      expect(r.result.backend, r.id).toBe('on-device');
    }
  });

  it('cuts the false alarms on legitimate examples and keeps every scam', async () => {
    const rows = await replay(fixture);
    const before = summarizeRoute('device', rows.map((r) => r.before), t);
    const after = summarizeRoute('device', rows.map((r) => r.after), t);
    expect(before.flagged).toMatchObject({ tp: 30, fp: 13, fn: 0, tn: 7 });
    expect(before.scam).toMatchObject({ tp: 30, fp: 2, fn: 0, tn: 18 });
    expect(after.flagged).toMatchObject({ tp: 30, fp: 1, fn: 0, tn: 19 });
    expect(after.scam).toMatchObject({ tp: 30, fp: 0, fn: 0, tn: 20 });
    // The one left: Nano rated the requested Revolut code 90, at or above the model-only minimum.
    expect(after.misclassified).toEqual(['legit-otp']);
    expect(rows.find((r) => r.id === 'legit-otp')!.after).toMatchObject({ risk: t.scam - 1, verdict: 'suspicious' });
  });

  it('prints both tables', async () => {
    const md = replayMarkdown(fixture, await replay(fixture));
    expect(md).toMatch(/\*\*Before\*\*/);
    expect(md).toMatch(/\*\*After\*\*/);
    expect(md).toMatch(/\| flagged \(risk >= 40\) \| 30 \| 1 \| 0 \| 19 \|/);
  });
});
