/**
 * Deterministic redaction of personal data. Runs locally, instantly, always.
 *
 * Rule of the product: any text that may leave the device goes through `redact()` first.
 * Offsets of every replacement are kept so that quotes from a cloud model (which only
 * saw the redacted text) can be mapped back onto the user's original text.
 */
import { BIP39_WORDS } from './bip39';
import { BRANDS, hostOf, registrableDomain, trimUrl, COMMON_TLDS } from './domains';
import type { Redaction, RedactionKind, RedactResult, Span } from './types';

export { registrableDomain } from './domains';

interface Candidate {
  kind: RedactionKind;
  start: number;
  end: number;
  replacement: string;
}

/** Lower number wins when two candidates overlap. */
const PRIORITY: Record<RedactionKind, number> = {
  url: 0,
  seed: 1,
  crypto: 2,
  iban: 3,
  card: 4,
  email: 5,
  phone: 6,
  street: 7,
  name: 8,
};

/** Placeholders this module produces; never redact inside them (makes redact idempotent). */
const PLACEHOLDER_RE =
  /\[(?:EMAIL@[^\]\s]*|PHONE|IBAN|CARD|CRYPTO_ADDRESS|SEED_PHRASE|STREET_ADDRESS|NAME|URL:[^\]\s]*)\]/g;

// ------------------------------------------------------------------ detectors

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'()[\]{}]+/gi;
const BARE_URL_RE = new RegExp(
  `(?<![@\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${COMMON_TLDS.join('|')})\\/[^\\s<>"'()\\[\\]{}]*`,
  'gi',
);

function urls(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const re of [URL_RE, BARE_URL_RE]) {
    for (const m of text.matchAll(re)) {
      const raw = trimUrl(m[0]);
      const host = hostOf(raw);
      if (!host.includes('.')) continue;
      out.push({ kind: 'url', start: m.index, end: m.index + raw.length, replacement: `[URL:${registrableDomain(host)}]` });
    }
  }
  return out;
}

const EMAIL_RE = /[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24})\b/g;

function emails(text: string): Candidate[] {
  return [...text.matchAll(EMAIL_RE)].map((m) => ({
    kind: 'email' as const,
    start: m.index,
    end: m.index + m[0].length,
    // The domain stays: it carries no personal data in most cases and is a strong scam hint.
    replacement: `[EMAIL@${(m[1] ?? '').toLowerCase()}]`,
  }));
}

const PHONE_RES = [
  /(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){1,4}\b/g,
  /(?<!\w)\(\d{2,4}\)\s?\d{3,4}[\s.-]?\d{3,4}\b/g,
  /\b0\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b/g,
  /\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b/g,
];

function phones(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const re of PHONE_RES) {
    for (const m of text.matchAll(re)) {
      const digits = m[0].replace(/\D/g, '').length;
      if (digits < 8 || digits > 15) continue;
      out.push({ kind: 'phone', start: m.index, end: m.index + m[0].length, replacement: '[PHONE]' });
    }
  }
  return out;
}

const IBAN_RE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g;

function ibans(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(IBAN_RE)) {
    const digits = m[0].replace(/\D/g, '').length;
    if (digits < 10) continue;
    out.push({ kind: 'iban', start: m.index, end: m.index + m[0].length, replacement: '[IBAN]' });
  }
  return out;
}

function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

const CARD_RE = /\b(?:\d[ -]?){12,18}\d\b/g;

function cards(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(CARD_RE)) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19 || !luhn(digits)) continue;
    out.push({ kind: 'card', start: m.index, end: m.index + m[0].length, replacement: '[CARD]' });
  }
  return out;
}

const CRYPTO_RES = [
  /\b0x[a-fA-F0-9]{40}(?:[a-fA-F0-9]{24})?\b/g, // EVM address or tx hash
  /\b(?:bc1|tb1)[a-z0-9]{25,62}\b/gi, // Bitcoin bech32
  /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, // Bitcoin legacy
  /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g, // TRON
  /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g, // Solana-style base58
];

function cryptos(text: string): Candidate[] {
  const out: Candidate[] = [];
  CRYPTO_RES.forEach((re, i) => {
    for (const m of text.matchAll(re)) {
      const s = m[0];
      if (i >= 2) {
        // base58 forms: demand a mix of digits, upper and lower case letters
        if (!/\d/.test(s) || !/[A-Z]/.test(s) || !/[a-z]/.test(s)) continue;
      }
      out.push({ kind: 'crypto', start: m.index, end: m.index + s.length, replacement: '[CRYPTO_ADDRESS]' });
    }
  });
  return out;
}

const SEED_GAP_RE = /^[\s,;]*(?:\(?\d{1,2}[.):-]?[\s,;]*)?$/;
const SEED_LEAD_RE = /(?:^|[\s,;])(\(?\d{1,2}[.):-]?\s*)$/;

/** Find runs of 12-24 BIP39 words (wallet recovery phrases), optionally numbered. */
export function findSeedPhrases(text: string): Span[] {
  const words = [...text.matchAll(/[A-Za-z]+/g)].map((m) => ({
    w: m[0].toLowerCase(),
    start: m.index,
    end: m.index + m[0].length,
  }));
  const spans: Span[] = [];
  let runStart = -1;
  const flush = (lastIdx: number) => {
    if (runStart < 0) return;
    const count = lastIdx - runStart + 1;
    if (count >= 12) {
      let start = words[runStart]!.start;
      const lead = SEED_LEAD_RE.exec(text.slice(Math.max(0, start - 6), start));
      if (lead?.[1]) start -= lead[1].length;
      spans.push({ start, end: words[lastIdx]!.end });
    }
    runStart = -1;
  };
  for (let i = 0; i < words.length; i++) {
    const cur = words[i]!;
    const inList = BIP39_WORDS.has(cur.w);
    if (!inList) {
      flush(i - 1);
      continue;
    }
    if (runStart < 0) {
      runStart = i;
      continue;
    }
    const prev = words[i - 1]!;
    if (!SEED_GAP_RE.test(text.slice(prev.end, cur.start))) {
      flush(i - 1);
      runStart = i;
    }
  }
  flush(words.length - 1);
  return spans;
}

function seeds(text: string): Candidate[] {
  return findSeedPhrases(text).map((s) => ({ kind: 'seed' as const, ...s, replacement: '[SEED_PHRASE]' }));
}

const STREET_TYPES =
  'Street|St\\.?|Avenue|Ave\\.?|Road|Rd\\.?|Boulevard|Blvd\\.?|Lane|Ln\\.?|Drive|Dr\\.?|Court|Ct\\.?|Way|Place|Pl\\.?|Terrace|Close|Square|Sq\\.?|Crescent|Parkway|Highway|Hwy\\.?|Alley|Row|Gardens|Grove|Strasse|Straße|Str\\.?';
const STREET_RES = [
  new RegExp(`\\b\\d{1,5}[A-Za-z]?\\s+(?:[A-Z][A-Za-z'’-]+\\s+){1,4}(?:${STREET_TYPES})(?![A-Za-z])`, 'g'),
  /\b(?:ul|bul|blvd|str)\.\s*["„]?[A-Z][\w'’-]+(?:\s+[A-Z][\w'’-]+){0,3}["“]?,?\s+(?:No\.?\s*)?\d{1,4}[A-Za-z]?\b/g,
  /\b(?:Apt|Apartment|Flat|Suite|Unit)\.?\s*#?\d{1,5}[A-Za-z]?\b/g,
];

function streets(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const re of STREET_RES) {
    for (const m of text.matchAll(re)) {
      out.push({ kind: 'street', start: m.index, end: m.index + m[0].length, replacement: '[STREET_ADDRESS]' });
    }
  }
  return out;
}

/** Words after "Dear" / "Hi" that are not names. Generic greetings are kept: they are a scam sign. */
const NOT_NAMES = new Set(
  [
    'customer', 'customers', 'user', 'users', 'client', 'clients', 'member', 'members', 'team', 'all', 'there',
    'everyone', 'everybody', 'friend', 'friends', 'sir', 'madam', 'sirs', 'valued', 'esteemed', 'beneficiary',
    'winner', 'candidate', 'applicant', 'folks', 'guys', 'colleague', 'colleagues', 'partner', 'partners',
    'account', 'holder', 'subscriber', 'dear', 'again', 'hiring', 'manager', 'recruiter', 'sender', 'buyer',
    'seller', 'shopper', 'investor', 'participant', 'student', 'parent', 'patient', 'owner', 'cardholder',
    'mr', 'mrs', 'ms', 'dr', 'world', 'support', 'admin', 'administrator', 'it', 'hr', 'and', 'from',
  ].map((w) => w.toLowerCase()),
);
const ORG_WORDS =
  /\b(?:Team|Support|Department|Dept|Service|Services|Desk|Group|Inc|Ltd|LLC|GmbH|Bank|Security|Customer|Care|Center|Centre|Office|Administration|Notifications?|Billing|Recruitment|Talent|Account|Accounts)\b/;
const BRAND_WORDS = new Set(BRANDS.flatMap((b) => [b.name.toLowerCase(), ...b.keys]));

const NAME = `[A-Z][a-zA-Z'’-]+(?:\\s+[A-Z]\\.)?(?:\\s+[A-Z][a-zA-Z'’-]+){0,2}`;
const TITLE = `(?:(?:Mr|Mrs|Ms|Miss|Dr|Prof)\\.?\\s+)?`;
const GREETING_RE = new RegExp(
  `\\b(?:[Hh]i|[Hh]ello|[Hh]ey|[Dd]ear|[Gg]ood (?:morning|afternoon|evening)|[Gg]reetings)[ \\t]+(${TITLE}${NAME})(?=[ \\t]*[,!.:\\n]|$)`,
  'dg',
);
const SIGNOFF_RE = new RegExp(
  `(?:^|\\n)[ \\t]*(?:Best regards|Kind regards|Warm regards|Regards|Best wishes|Best|Thanks|Thank you|Many thanks|Sincerely|Yours sincerely|Yours truly|Cheers|Respectfully|All the best|Talk soon|Br)[,.!]?[ \\t]*\\n[ \\t]*(${TITLE}${NAME})[ \\t]*(?=\\n|$)`,
  'dg',
);
const INTRO_RE = new RegExp(`\\b(?:[Mm]y name is|[Tt]his is|I am|I'm|I’m)[ \\t]+(${TITLE}${NAME})`, 'dg');

function nameCandidate(m: RegExpExecArray | RegExpMatchArray, strict: boolean): Candidate | null {
  const idx = m.indices?.[1];
  const value = m[1];
  if (!idx || !value) return null;
  const words = value.replace(/^(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+/, '').split(/\s+/);
  const first = (words[0] ?? '').toLowerCase();
  if (NOT_NAMES.has(first) || BRAND_WORDS.has(first)) return null;
  if (ORG_WORDS.test(value)) return null;
  if (strict && words.some((w) => BRAND_WORDS.has(w.toLowerCase()))) return null;
  return { kind: 'name', start: idx[0], end: idx[1], replacement: '[NAME]' };
}

function names(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(GREETING_RE)) {
    const c = nameCandidate(m, false);
    if (c) out.push(c);
  }
  for (const m of text.matchAll(SIGNOFF_RE)) {
    const c = nameCandidate(m, false);
    if (c) out.push(c);
  }
  for (const m of text.matchAll(INTRO_RE)) {
    const c = nameCandidate(m, true);
    if (c) out.push(c);
  }
  return out;
}

// ------------------------------------------------------------------ main

const DETECTORS = [urls, seeds, cryptos, ibans, cards, emails, phones, streets, names];

/**
 * Replace personal data with placeholders. Pure, synchronous and deterministic.
 * Every placeholder is recorded with its offsets in the original and in the redacted text.
 */
export function redact(text: string): RedactResult {
  const protectedSpans: Span[] = [...text.matchAll(PLACEHOLDER_RE)].map((m) => ({
    start: m.index,
    end: m.index + m[0].length,
  }));
  const overlaps = (a: Span, b: Span) => a.start < b.end && b.start < a.end;

  const candidates = DETECTORS.flatMap((d) => d(text))
    .filter((c) => c.end > c.start && !protectedSpans.some((p) => overlaps(p, c)))
    .sort((a, b) => PRIORITY[a.kind] - PRIORITY[b.kind] || a.start - b.start || b.end - a.end);

  const accepted: Candidate[] = [];
  for (const c of candidates) {
    if (!accepted.some((a) => overlaps(a, c))) accepted.push(c);
  }
  accepted.sort((a, b) => a.start - b.start);

  let out = '';
  let cursor = 0;
  const redactions: Redaction[] = [];
  const counts: Partial<Record<RedactionKind, number>> = {};
  for (const c of accepted) {
    out += text.slice(cursor, c.start);
    const rStart = out.length;
    out += c.replacement;
    redactions.push({
      kind: c.kind,
      original: { start: c.start, end: c.end },
      redacted: { start: rStart, end: out.length },
      replacement: c.replacement,
    });
    counts[c.kind] = (counts[c.kind] ?? 0) + 1;
    cursor = c.end;
  }
  out += text.slice(cursor);
  return { text: out, redactions, counts };
}

function mapPos(pos: number, redactions: Redaction[], side: 'start' | 'end'): number {
  let delta = 0;
  for (const r of redactions) {
    if (pos >= r.redacted.end) {
      delta = r.original.end - r.redacted.end;
      continue;
    }
    if (pos <= r.redacted.start) break;
    return side === 'start' ? r.original.start : r.original.end;
  }
  return pos + delta;
}

/** Map a span of the redacted text back to the original text. */
export function mapRedactedSpanToOriginal(span: Span, redactions: Redaction[]): Span {
  return { start: mapPos(span.start, redactions, 'start'), end: mapPos(span.end, redactions, 'end') };
}

export const REDACTION_LABELS: Record<RedactionKind, string> = {
  email: 'e-mail',
  phone: 'phone',
  iban: 'IBAN',
  card: 'card number',
  crypto: 'crypto address',
  seed: 'recovery phrase',
  street: 'street address',
  url: 'link (kept domain)',
  name: 'name',
};
