/**
 * The engine combines the deterministic layer (redaction + signals) with the model's
 * verdict, enforces the privacy routing rule and produces the final result.
 *
 * Privacy rule: RAW text goes only to the on-device model. Any text that may be
 * processed in the cloud is the output of `redact()`.
 */
import { buildPrompt, parseModelVerdict, PROMPT_VERSION } from './prompt';
import { mapRedactedSpanToOriginal, redact } from './redact';
import { dominantCategory, heuristicScore, signals, type HeuristicScore } from './signals';
import type {
  Backend,
  Category,
  CheckKind,
  CheckResult,
  Highlight,
  ModelVerdict,
  RedactResult,
  Severity,
  Signal,
  Span,
  Thresholds,
  Verdict,
} from './types';

export const DEFAULT_THRESHOLDS: Thresholds = { scam: 70, suspicious: 40 };

export interface LocalAnalysis {
  text: string;
  redaction: RedactResult;
  signals: Signal[];
  score: HeuristicScore;
}

/** Instant, fully local analysis. */
export function analyzeLocal(text: string): LocalAnalysis {
  const list = signals(text);
  return { text, redaction: redact(text), signals: list, score: heuristicScore(list) };
}

export function verdictFor(risk: number, t: Thresholds = DEFAULT_THRESHOLDS): Verdict {
  return risk >= t.scam ? 'scam' : risk >= t.suspicious ? 'suspicious' : 'safe';
}

const ADVICE: Record<Verdict, string> = {
  scam: 'Do not reply, click links, pay, or run anything from this message. Contact the company through its official app or website, and report the sender.',
  suspicious: 'Slow down and verify through a channel you already trust (official app, website or phone number) before you click, pay or reply.',
  safe: 'No strong scam signs found. Still never share passwords, one-time codes or recovery phrases.',
};

const CATEGORY_ADVICE: Partial<Record<Category, string>> = {
  'malware-task': 'Do not clone, install or run the project. If you already did, disconnect, move crypto to a new wallet and change your passwords from another device.',
  'wallet-drainer': 'Never type your recovery phrase anywhere and do not connect your wallet to the linked site.',
  'fake-invoice': 'Call the supplier on a number you already have before paying to any new bank details.',
  'tech-support': 'Hang up or close the page. Do not install remote-access tools or pay for "support".',
  'fake-recruiter': 'Check the company and recruiter on the official careers site. Real employers never charge fees or ask you to move money.',
};

// ------------------------------------------------------------------ quotes and spans

const norm = (s: string) => s.toLowerCase();

/** Collapse whitespace and keep a map from normalised index to original index. */
function normaliseWithMap(text: string): { s: string; map: number[] } {
  let s = '';
  const map: number[] = [];
  let inSpace = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (/\s/.test(ch)) {
      if (inSpace) continue;
      inSpace = true;
      s += ' ';
      map.push(i);
    } else {
      inSpace = false;
      s += ch.toLowerCase();
      map.push(i);
    }
  }
  return { s, map };
}

function findIn(text: string, quote: string): Span | null {
  const exact = text.indexOf(quote);
  if (exact >= 0) return { start: exact, end: exact + quote.length };
  const ci = norm(text).indexOf(norm(quote));
  if (ci >= 0) return { start: ci, end: ci + quote.length };
  const { s, map } = normaliseWithMap(text);
  const q = quote.replace(/\s+/g, ' ').trim().toLowerCase();
  const idx = s.indexOf(q);
  if (idx >= 0 && q.length > 0) {
    const start = map[idx]!;
    const end = map[idx + q.length - 1]! + 1;
    return { start, end };
  }
  return null;
}

/**
 * Locate a model quote in the original text. When the model saw the redacted text,
 * pass the redaction so quotes containing placeholders can be mapped back.
 */
export function locateQuote(original: string, quote: string, redaction?: RedactResult): Span | null {
  const q = quote
    .trim()
    .replace(/^["'“”‘’«»]+|["'“”‘’«»]+$/g, '')
    .replace(/^(?:\.\.\.|…)\s*|\s*(?:\.\.\.|…)$/g, '')
    .trim();
  if (q.length < 2) return null;
  const direct = findIn(original, q);
  if (direct) return direct;
  if (redaction && redaction.redactions.length) {
    const inRedacted = findIn(redaction.text, q);
    if (inRedacted) return mapRedactedSpanToOriginal(inRedacted, redaction.redactions);
  }
  return null;
}

export interface Segment {
  text: string;
  start: number;
  end: number;
  highlights: Highlight[];
}

/** Split a text into consecutive segments with the highlights that cover each one. */
export function toSegments(text: string, highlights: Highlight[]): Segment[] {
  const cuts = new Set<number>([0, text.length]);
  for (const h of highlights) {
    cuts.add(Math.max(0, Math.min(text.length, h.start)));
    cuts.add(Math.max(0, Math.min(text.length, h.end)));
  }
  const points = [...cuts].sort((a, b) => a - b);
  const segs: Segment[] = [];
  for (let i = 0; i < points.length - 1; i++) {
    const start = points[i]!;
    const end = points[i + 1]!;
    if (end <= start) continue;
    const covering = highlights.filter((h) => h.start <= start && h.end >= end);
    const prev = segs[segs.length - 1];
    if (prev && sameSet(prev.highlights, covering)) {
      prev.end = end;
      prev.text = text.slice(prev.start, end);
    } else {
      segs.push({ text: text.slice(start, end), start, end, highlights: covering });
    }
  }
  return segs;
}

function sameSet(a: Highlight[], b: Highlight[]): boolean {
  return a.length === b.length && a.every((x) => b.includes(x));
}

// ------------------------------------------------------------------ combine

export interface CombineInput {
  text: string;
  local: LocalAnalysis;
  model: ModelVerdict | null;
  backend: Backend;
  latencyMs: number;
  /** Exact text that left the device, or null. */
  sentText: string | null;
  kind?: CheckKind;
  thresholds?: Thresholds;
  note?: string | null;
  truncated?: boolean;
  promptVersion?: string;
  /** True when the model saw the redacted text (quotes must be mapped back). */
  modelSawRedacted?: boolean;
}

const encoder = new TextEncoder();
export const utf8Bytes = (s: string) => encoder.encode(s).length;

/**
 * Final risk:
 * - no model: the heuristic score;
 * - with a model: max(model, hard-sign floor, average of model and heuristics).
 * So heuristics can only raise the model's number, and hard red flags (seed-phrase
 * requests, gift cards, pasted commands, look-alike domains...) set a floor that a
 * fooled or prompt-injected model cannot talk down.
 */
export function combine(input: CombineInput): CheckResult {
  const t = input.thresholds ?? DEFAULT_THRESHOLDS;
  const { local, model } = input;
  const h = local.score;
  const risk = model ? Math.round(Math.max(model.risk, h.hard, (model.risk + h.total) / 2)) : h.total;
  const verdict = verdictFor(risk, t);

  let category: Category = 'none';
  if (verdict !== 'safe') {
    const fromModel = model && model.category !== 'none' && model.category !== 'other' ? model.category : null;
    category = fromModel ?? dominantCategory(h) ?? 'other';
  }

  const modelSeverity: Severity = verdict === 'scam' ? 'high' : verdict === 'suspicious' ? 'medium' : 'low';
  const highlights: Highlight[] = [];
  const reasons: CheckResult['reasons'] = [];
  for (const r of model?.reasons ?? []) {
    const span = r.quote ? locateQuote(input.text, r.quote, input.modelSawRedacted ? local.redaction : undefined) : null;
    reasons.push({ quote: span ? input.text.slice(span.start, span.end) : r.quote, why: r.why, source: 'model', span: span ?? undefined });
    if (span) highlights.push({ ...span, source: 'model', label: 'AI', why: r.why, severity: modelSeverity });
  }
  for (const s of local.signals) {
    const first = s.spans[0];
    reasons.push({
      quote: first ? input.text.slice(first.start, first.end) : '',
      why: s.explanation,
      source: 'signal',
      span: first,
    });
    for (const span of s.spans) highlights.push({ ...span, source: 'signal', label: s.label, why: s.explanation, severity: s.severity });
  }
  highlights.sort((a, b) => a.start - b.start || b.end - a.end);

  // Use the model's advice only when the model and the final verdict agree on safe vs. not safe.
  const modelAgrees = model ? (model.verdict === 'safe') === (verdict === 'safe') : false;
  const advice =
    model?.advice && modelAgrees
      ? model.advice
      : (verdict !== 'safe' ? CATEGORY_ADVICE[category] : undefined) ?? ADVICE[verdict];

  return {
    kind: input.kind ?? 'quick',
    risk,
    verdict,
    category,
    reasons,
    advice,
    signals: local.signals,
    heuristicRisk: h.total,
    modelRisk: model ? model.risk : null,
    highlights,
    backend: input.backend,
    latencyMs: Math.max(0, Math.round(input.latencyMs)),
    bytesSent: input.sentText ? utf8Bytes(input.sentText) : 0,
    sentText: input.sentText,
    redaction: local.redaction,
    truncated: input.truncated ?? false,
    note: input.note ?? null,
    promptVersion: input.promptVersion ?? PROMPT_VERSION,
  };
}

// ------------------------------------------------------------------ orchestration

/**
 * How the AI layer must run a prompt:
 * - `device`: RAW text. Must run on the device only (the AI layer pins ONLY_ON_DEVICE).
 * - `hybrid`: REDACTED text. The PREFER_ON_DEVICE hybrid model decides device or cloud.
 * - `cloud`:  REDACTED text, deep check after explicit consent.
 */
export type Route = 'device' | 'hybrid' | 'cloud';

export interface GenerateResult {
  text: string;
  /** Where inference actually happened (from the SDK's `inferenceSource`). */
  source: 'on-device' | 'cloud';
}

export type Generate = (prompt: string, route: Route) => Promise<GenerateResult>;

export interface QuickCheckDeps {
  /** Result of a fresh on-device availability check (Chrome `LanguageModel.availability()`). */
  onDeviceAvailable: boolean;
  generate: Generate;
  now?: () => number;
  thresholds?: Thresholds;
  /** Remote-config switch: when false, a failed on-device call does not go to the cloud. */
  allowCloudFallback?: boolean;
}

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function runQuickCheck(text: string, deps: QuickCheckDeps): Promise<CheckResult> {
  const now = deps.now ?? (() => Date.now());
  const thresholds = deps.thresholds ?? DEFAULT_THRESHOLDS;
  const t0 = now();
  const local = analyzeLocal(text);
  const base = { text, local, thresholds, kind: 'quick' as const };

  if (!text.trim()) {
    return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null });
  }

  let note: string | null = null;

  if (deps.onDeviceAvailable) {
    const built = buildPrompt(text, { redacted: false, thresholds });
    try {
      const res = await deps.generate(built.prompt, 'device');
      const parsed = parseModelVerdict(res.text, thresholds);
      if (!parsed.ok) {
        return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, note: `On-device answer ignored (${parsed.error}).`, truncated: built.truncated });
      }
      return combine({ ...base, model: parsed.value, backend: 'on-device', latencyMs: now() - t0, sentText: null, truncated: built.truncated });
    } catch (e) {
      note = `On-device model failed (${errMsg(e)}).`;
      if (deps.allowCloudFallback === false) {
        return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, note });
      }
    }
  }

  const built = buildPrompt(local.redaction.text, { redacted: true, thresholds });
  try {
    const res = await deps.generate(built.prompt, 'hybrid');
    const parsed = parseModelVerdict(res.text, thresholds);
    const onDevice = res.source === 'on-device';
    const sentText = onDevice ? null : built.prompt;
    if (!parsed.ok) {
      return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText, note: `Model answer ignored (${parsed.error}).`, truncated: built.truncated });
    }
    return combine({
      ...base,
      model: parsed.value,
      backend: onDevice ? 'on-device' : 'cloud-redacted',
      latencyMs: now() - t0,
      sentText,
      note,
      truncated: built.truncated,
      modelSawRedacted: true,
    });
  } catch (e) {
    const msg = `${note ? `${note} ` : ''}Model unavailable (${errMsg(e)}); showing the local heuristic check only.`;
    return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, note: msg });
  }
}

export interface PreparedDeepCheck {
  local: LocalAnalysis;
  /** The redacted message shown in the consent dialog. */
  redactedText: string;
  /** The full request text that will be sent (instructions + redacted message). */
  prompt: string;
  bytes: number;
  truncated: boolean;
}

/** Build exactly what a deep check would send, for the consent dialog. */
export function prepareDeepCheck(text: string, thresholds: Thresholds = DEFAULT_THRESHOLDS): PreparedDeepCheck {
  const local = analyzeLocal(text);
  const built = buildPrompt(local.redaction.text, { redacted: true, deep: true, thresholds });
  return { local, redactedText: local.redaction.text, prompt: built.prompt, bytes: utf8Bytes(built.prompt), truncated: built.truncated };
}

export interface DeepCheckDeps {
  generate: Generate;
  now?: () => number;
  thresholds?: Thresholds;
}

/** Deep check: sends the prepared (consented) redacted prompt to the cloud model. */
export async function runDeepCheck(text: string, deps: DeepCheckDeps, prepared?: PreparedDeepCheck): Promise<CheckResult> {
  const now = deps.now ?? (() => Date.now());
  const thresholds = deps.thresholds ?? DEFAULT_THRESHOLDS;
  const t0 = now();
  const prep = prepared ?? prepareDeepCheck(text, thresholds);
  const base = { text, local: prep.local, thresholds, kind: 'deep' as const, truncated: prep.truncated };
  try {
    const res = await deps.generate(prep.prompt, 'cloud');
    const parsed = parseModelVerdict(res.text, thresholds);
    if (!parsed.ok) {
      return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: prep.prompt, note: `Cloud answer ignored (${parsed.error}).` });
    }
    return combine({
      ...base,
      model: parsed.value,
      backend: res.source === 'on-device' ? 'on-device' : 'cloud-redacted',
      latencyMs: now() - t0,
      sentText: res.source === 'on-device' ? null : prep.prompt,
      modelSawRedacted: true,
    });
  } catch (e) {
    return combine({ ...base, model: null, backend: 'heuristics-only', latencyMs: now() - t0, sentText: null, note: `Deep check failed (${errMsg(e)}).` });
  }
}
