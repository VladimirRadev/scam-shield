/**
 * Shared types of the Scam Shield core. Pure data: no Firebase, no DOM.
 */

/** Final verdict shown to the user. */
export type Verdict = 'safe' | 'suspicious' | 'scam';
export const VERDICTS: readonly Verdict[] = ['safe', 'suspicious', 'scam'];

/** Scam families Scam Shield knows about. `none` = legitimate message. */
export const CATEGORIES = [
  'fake-recruiter',
  'malware-task',
  'wallet-drainer',
  'advance-fee',
  'fake-invoice',
  'phishing',
  'tech-support',
  'investment-romance',
  'off-platform-lure',
  'lookalike-domain',
  'other',
  'none',
] as const;
export type Category = (typeof CATEGORIES)[number];

export const CATEGORY_LABELS: Record<Category, string> = {
  'fake-recruiter': 'Fake recruiter / job offer',
  'malware-task': 'Malware "run this code" task',
  'wallet-drainer': 'Crypto wallet drainer',
  'advance-fee': 'Advance-fee fraud',
  'fake-invoice': 'Fake invoice / payment redirect',
  phishing: 'Phishing (bank, delivery, account)',
  'tech-support': 'Tech-support scam',
  'investment-romance': 'Investment / romance scam',
  'off-platform-lure': 'Move-to-another-app lure',
  'lookalike-domain': 'Lookalike domain',
  other: 'Other scam',
  none: 'No scam pattern',
};

/** Half-open character range [start, end) in a string. */
export interface Span {
  start: number;
  end: number;
}

// ---------------------------------------------------------------- redaction

export type RedactionKind =
  | 'email'
  | 'phone'
  | 'iban'
  | 'card'
  | 'cvv'
  | 'key'
  | 'crypto'
  | 'seed'
  | 'street'
  | 'id'
  | 'dob'
  | 'code'
  | 'handle'
  | 'url'
  | 'name';

/** One piece of personal data that was replaced. Offsets refer to both strings. */
export interface Redaction {
  kind: RedactionKind;
  /** Range in the ORIGINAL text. */
  original: Span;
  /** Range of the placeholder in the REDACTED text. */
  redacted: Span;
  /** The placeholder that replaced the original, e.g. `[EMAIL]`. */
  replacement: string;
}

export interface RedactResult {
  /** Text that is safe to send off the device. */
  text: string;
  redactions: Redaction[];
  counts: Partial<Record<RedactionKind, number>>;
}

// ---------------------------------------------------------------- signals

export type Severity = 'low' | 'medium' | 'high';

/** A deterministic scam indicator found in the text. */
export interface Signal {
  id: string;
  /** Short title, e.g. "Asks for your recovery phrase". */
  label: string;
  /** Points this sign adds to the heuristic score (0-100). */
  weight: number;
  severity: Severity;
  /** One line, plain English: why this is a warning sign. */
  explanation: string;
  /** Category this sign points to. */
  category: Category;
  /** Where it was found in the original text. */
  spans: Span[];
}

// ---------------------------------------------------------------- model

export interface ModelReason {
  quote: string;
  why: string;
}

/** The strict JSON the language model must return. */
export interface ModelVerdict {
  risk: number;
  verdict: Verdict;
  category: Category;
  reasons: ModelReason[];
  advice: string;
}

// ---------------------------------------------------------------- result

/** Where the language-model judgement came from. */
export type Backend = 'on-device' | 'cloud-redacted' | 'heuristics-only';

/** Which check produced the result. */
export type CheckKind = 'quick' | 'deep';

export interface Highlight extends Span {
  source: 'signal' | 'model';
  /** Short label shown on hover / in the legend. */
  label: string;
  /** Explanation for the user. */
  why: string;
  severity: Severity;
}

export interface Thresholds {
  /** risk >= scam -> "scam" */
  scam: number;
  /** risk >= suspicious -> "suspicious" */
  suspicious: number;
  /**
   * Corroboration rule: when no local red flag fired, the model alone needs at least this risk to
   * make a message "suspicious", and even then it cannot make it "scam". Missing: MODEL_ONLY_MIN_RISK.
   */
  modelOnlyMinRisk?: number;
}

export interface CheckResult {
  kind: CheckKind;
  /** Final risk 0-100 after combining heuristics and the model. */
  risk: number;
  verdict: Verdict;
  category: Category;
  /**
   * Explanations shown to the user: an `engine` note first (the AI's "safe" was overruled by
   * local red flags, or the AI's concern was capped because no local red flag confirmed it),
   * then the model reasons, then the signals.
   */
  reasons: Array<{ quote: string; why: string; source: 'signal' | 'model' | 'engine'; span?: Span }>;
  advice: string;
  signals: Signal[];
  /** Heuristic-only score (sum of signal weights, capped at 100). */
  heuristicRisk: number;
  /** Risk the model reported, or null when no model answered. */
  modelRisk: number | null;
  /**
   * Set when the corroboration rule lowered the model's verdict because no local red flag
   * confirmed it: the verdict it was capped to. null when the rule changed nothing.
   */
  modelCapped: 'safe' | 'suspicious' | null;
  /** Highlights on the ORIGINAL text, sorted, may overlap. */
  highlights: Highlight[];
  backend: Backend;
  latencyMs: number;
  /** UTF-8 bytes of text that left the device (0 for on-device / heuristics-only). */
  bytesSent: number;
  /** The exact text that left the device, if any (always redacted). */
  sentText: string | null;
  redaction: RedactResult;
  /** True when the input was cut to fit the model's context. */
  truncated: boolean;
  /** Non-fatal problem, e.g. model unavailable or unparseable answer. */
  note: string | null;
  promptVersion: string;
}
