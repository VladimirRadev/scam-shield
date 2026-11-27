/**
 * Evaluate the deterministic (heuristic) layer alone on the labelled examples.
 * Prints precision / recall / F1 as Markdown tables.
 *
 *   npm run eval              # summary
 *   npm run eval -- --all     # every example with its score and signs
 */
import { analyzeLocal, DEFAULT_THRESHOLDS, verdictFor } from '../src/engine';
import { EXAMPLES } from '../src/examples';
import type { Verdict } from '../src/types';

const verbose = process.argv.includes('--all');
const t = DEFAULT_THRESHOLDS;

interface Row {
  id: string;
  label: 'scam' | 'legit';
  category: string;
  risk: number;
  verdict: Verdict;
  signs: string[];
}

const rows: Row[] = EXAMPLES.map((ex) => {
  const local = analyzeLocal(ex.text);
  return {
    id: ex.id,
    label: ex.label,
    category: ex.category,
    risk: local.score.total,
    verdict: verdictFor(local.score.total, t),
    signs: local.signals.map((s) => `${s.id}(${s.weight})`),
  };
});

const pct = (x: number) => (Number.isFinite(x) ? `${(x * 100).toFixed(1)}%` : 'n/a');

function metrics(isPositive: (r: Row) => boolean) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const r of rows) {
    const pred = isPositive(r);
    const actual = r.label === 'scam';
    if (pred && actual) tp++;
    else if (pred && !actual) fp++;
    else if (!pred && actual) fn++;
    else tn++;
  }
  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  const f1 = (2 * precision * recall) / (precision + recall);
  return { tp, fp, fn, tn, precision, recall, f1 };
}

const scams = rows.filter((r) => r.label === 'scam').length;
const legit = rows.length - scams;

const lines: string[] = [];
lines.push(`### Heuristic layer only (no model), ${rows.length} examples: ${scams} scams, ${legit} legitimate`);
lines.push('');
lines.push(`Thresholds: suspicious >= ${t.suspicious}, scam >= ${t.scam} (Remote Config defaults).`);
lines.push('');
lines.push('| Positive when | TP | FP | FN | TN | Precision | Recall | F1 |');
lines.push('|---|---:|---:|---:|---:|---:|---:|---:|');
for (const [name, fn] of [
  [`flagged (risk >= ${t.suspicious})`, (r: Row) => r.verdict !== 'safe'],
  [`scam (risk >= ${t.scam})`, (r: Row) => r.verdict === 'scam'],
] as const) {
  const m = metrics(fn);
  lines.push(`| ${name} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} |`);
}

lines.push('');
lines.push('| Scam category | Examples | Flagged | Recall |');
lines.push('|---|---:|---:|---:|');
const cats = [...new Set(rows.filter((r) => r.label === 'scam').map((r) => r.category))].sort();
for (const c of cats) {
  const inCat = rows.filter((r) => r.label === 'scam' && r.category === c);
  const flagged = inCat.filter((r) => r.verdict !== 'safe').length;
  lines.push(`| ${c} | ${inCat.length} | ${flagged} | ${pct(flagged / inCat.length)} |`);
}

const errors = rows.filter((r) => (r.label === 'scam') !== (r.verdict !== 'safe'));
lines.push('');
if (errors.length) {
  lines.push('Misclassified by heuristics alone (the model layer is meant to catch these):');
  lines.push('');
  for (const r of errors) lines.push(`- \`${r.id}\` (${r.label}) risk ${r.risk}: ${r.signs.join(', ') || 'no signs'}`);
} else {
  lines.push('No misclassified examples.');
}

if (verbose) {
  lines.push('', '| Example | Label | Risk | Verdict | Signs |', '|---|---|---:|---|---|');
  for (const r of rows) lines.push(`| ${r.id} | ${r.label} | ${r.risk} | ${r.verdict} | ${r.signs.join(', ')} |`);
}

lines.push('', '_Examples are synthetic and were written together with the heuristics, so these numbers are optimistic._');
console.log(lines.join('\n'));
