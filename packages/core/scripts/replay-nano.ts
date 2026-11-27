/**
 * Replay recorded Gemini Nano answers through the CURRENT engine, offline.
 *
 * The on-device E2E run (scripts/ci/on-device-e2e.mjs) records every raw Nano answer of the
 * device eval in `nano-calls-eval.json` and the final rows in `eval-device.json`. This script feeds
 * those answers back into `runQuickCheck` (device route, as the eval page runs it) and prints the
 * confusion table of the recorded run ("before") next to the replayed one ("after"). Only the
 * engine changes: the answers were produced by the prompt version stored in the fixture.
 *
 *   npm run replay:nano                                # the committed fixture
 *   npm run replay:nano -- <e2e-results dir>           # a downloaded CI artifact
 *   npm run replay:nano -- <e2e-results dir> --source <run URL> --save <fixture.json>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DEFAULT_THRESHOLDS, runQuickCheck, verdictFor } from '../src/engine';
import { EXAMPLES } from '../src/examples';
import { prfTable, summarizeRoute, type EvalRow } from '../src/metrics';
import type { CheckResult, Thresholds } from '../src/types';

export interface RecordedAnswer {
  id: string;
  label: 'scam' | 'legit';
  /** Final risk the engine produced in the recorded run. */
  recordedRisk: number;
  latencyMs: number;
  /** Raw Gemini Nano answer text. */
  out: string;
}

export interface ReplayFixture {
  source: string;
  browser: string;
  promptVersion: string;
  thresholds: Thresholds;
  answers: RecordedAnswer[];
}

export const DEFAULT_FIXTURE = fileURLToPath(new URL('../test/fixtures/nano-device-v1-run-45965556713.json', import.meta.url));

export function loadFixture(path = DEFAULT_FIXTURE): ReplayFixture {
  return JSON.parse(readFileSync(path, 'utf8')) as ReplayFixture;
}

/**
 * Pair the recorded prompts with the eval rows. The eval runs the examples one after another, so
 * the n-th prompt call belongs to the n-th row.
 */
export function fixtureFromArtifact(dir: string, source = dir): ReplayFixture {
  const calls = (JSON.parse(readFileSync(`${dir}/nano-calls-eval.json`, 'utf8')) as Array<{ kind: string; out?: string }>).filter((c) => c.kind === 'prompt');
  const ev = JSON.parse(readFileSync(`${dir}/eval-device.json`, 'utf8')) as {
    browser: string;
    promptVersion: string;
    thresholds: Thresholds;
    routes: { device?: { rows: EvalRow[] } };
  };
  const rows = ev.routes.device?.rows ?? [];
  if (!rows.length) throw new Error(`${dir}: eval-device.json has no device rows`);
  if (calls.length !== rows.length) throw new Error(`${dir}: ${calls.length} prompt calls but ${rows.length} eval rows`);
  const answers = rows.map((row, i) => {
    const out = calls[i]!.out;
    if (typeof out !== 'string') throw new Error(`${dir}: prompt call ${i} (${row.id}) has no recorded answer`);
    return { id: row.id, label: row.label, recordedRisk: row.risk, latencyMs: row.latencyMs, out };
  });
  return { source, browser: ev.browser, promptVersion: ev.promptVersion, thresholds: ev.thresholds, answers };
}

export interface ReplayedRow {
  id: string;
  label: 'scam' | 'legit';
  before: EvalRow;
  after: EvalRow;
  result: CheckResult;
}

/** Run every recorded answer through the current engine on the device route. */
export async function replay(fixture: ReplayFixture, thresholds: Thresholds = { ...DEFAULT_THRESHOLDS, ...fixture.thresholds }): Promise<ReplayedRow[]> {
  const out: ReplayedRow[] = [];
  for (const a of fixture.answers) {
    const ex = EXAMPLES.find((e) => e.id === a.id);
    if (!ex) throw new Error(`unknown example ${a.id}`);
    const result = await runQuickCheck(ex.text, {
      onDeviceAvailable: true,
      allowCloudFallback: false,
      generate: async () => ({ text: a.out, source: 'on-device' }),
      thresholds,
      now: () => 0,
    });
    const row = (risk: number): EvalRow => ({ id: a.id, label: a.label, risk, verdict: verdictFor(risk, thresholds), backend: result.backend, latencyMs: a.latencyMs, bytesSent: result.bytesSent, note: result.note });
    out.push({ id: a.id, label: a.label, before: row(a.recordedRisk), after: row(result.risk), result });
  }
  return out;
}

export function replayMarkdown(fixture: ReplayFixture, rows: readonly ReplayedRow[], thresholds: Thresholds = { ...DEFAULT_THRESHOLDS, ...fixture.thresholds }): string {
  const before = summarizeRoute('device', rows.map((r) => r.before), thresholds);
  const after = summarizeRoute('device', rows.map((r) => r.after), thresholds);
  const changed = rows.filter((r) => r.before.risk !== r.after.risk);
  const lines = [
    `### Replay of ${rows.length} recorded Gemini Nano answers (prompt ${fixture.promptVersion}, ${fixture.browser})`,
    '',
    `Source: ${fixture.source}`,
    '',
    '**Before** (as recorded):',
    '',
    ...prfTable(before),
    '',
    `**After** (current engine, model-only minimum ${thresholds.modelOnlyMinRisk ?? DEFAULT_THRESHOLDS.modelOnlyMinRisk}):`,
    '',
    ...prfTable(after),
    '',
    `Misclassified after (flagged rule): ${after.misclassified.map((id) => `\`${id}\``).join(', ') || 'none'}`,
    '',
    '| Example | Label | Model | Heuristics | Before | After |',
    '|---|---|---:|---:|---:|---:|',
    ...changed.map((r) => `| ${r.id} | ${r.label} | ${r.result.modelRisk ?? 'n/a'} | ${r.result.heuristicRisk} | ${r.before.risk} ${r.before.verdict} | ${r.after.risk} ${r.after.verdict} |`),
    '',
    `${changed.length} of ${rows.length} final risks changed. The model answers are fixed, so this measures the engine only.`,
  ];
  return lines.join('\n');
}

async function main(argv: string[]) {
  const flags: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--save' || a === '--source') {
      const v = argv[++i];
      if (!v) throw new Error(`${a} needs a value`);
      flags[a] = v;
    } else positional.push(a);
  }
  const dir = positional[0];
  const savePath = flags['--save'];
  const fixture = dir ? fixtureFromArtifact(dir, flags['--source'] ?? dir) : loadFixture();
  if (savePath) writeFileSync(savePath, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(replayMarkdown(fixture, await replay(fixture)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
