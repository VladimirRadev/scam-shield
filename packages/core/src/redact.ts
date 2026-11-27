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
  key: 2,
  crypto: 3,
  iban: 4,
  card: 5,
  cvv: 6,
  email: 7,
  phone: 8,
  street: 9,
  name: 10,
};

/** Placeholders this module produces; never redact inside them (makes redact idempotent). */
const PLACEHOLDER_RE =
  /\[(?:EMAIL@[^\]\s]*|PHONE|IBAN|CARD|CVV|PRIVATE_KEY|CRYPTO_ADDRESS|SEED_PHRASE|STREET_ADDRESS|NAME|URL:[^\]\s]*)\]/g;

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

/** Formats with a country code, a trunk 0 or brackets: 8-15 digits. */
const PHONE_RES = [
  /(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){1,4}\b/g,
  /(?<!\w)\(\d{2,4}\)\s?\d{3,4}[\s.-]?\d{3,4}\b/g,
  /\b0\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b/g,
  /\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b/g,
];
/**
 * Plain digit runs that are 10-15 digits long, with or without spaces, dots or dashes between
 * groups ("5551234567", "44 7700 900123"). A run that continues as part of a longer number, or
 * that follows a shipment / order / invoice word, is not a phone number.
 */
const PLAIN_PHONE_RES = [/(?<![\w+./-])\d{10,15}(?![\w/-])/g, /(?<![\w+./-])\d{2,4}(?:[ .-]\d{2,6}){1,5}(?![\w/]|[.-]\d)/g];
const NOT_PHONE_CONTEXT_RE =
  /\b(?:shipment|tracking|parcel|package|order|invoice|ref|reference|ticket|case|booking|confirmation|build|version)\b(?:\s*(?:no\.?|number|nr\.?|id|#))?[\s:#.]*$/i;

function phones(text: string): Candidate[] {
  const out: Candidate[] = [];
  const add = (m: RegExpMatchArray, min: number) => {
    const digits = m[0].replace(/\D/g, '').length;
    if (digits < min || digits > 15) return;
    out.push({ kind: 'phone', start: m.index!, end: m.index! + m[0].length, replacement: '[PHONE]' });
  };
  for (const re of PHONE_RES) for (const m of text.matchAll(re)) add(m, 8);
  for (const re of PLAIN_PHONE_RES) {
    for (const m of text.matchAll(re)) {
      if (NOT_PHONE_CONTEXT_RE.test(text.slice(Math.max(0, m.index - 30), m.index))) continue;
      add(m, 10);
    }
  }
  return out;
}

/** Upper-case IBANs: accepted on shape alone (also fake ones in scam messages are masked). */
const IBAN_RE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/g;
/** IBANs in any letter case ("de89 3704 ..."): accepted only with a valid ISO 13616 checksum. */
const IBAN_ANYCASE_RE = /\b[A-Za-z]{2}\d{2}(?: ?[A-Za-z0-9]){11,30}\b/g;

/** ISO 13616 mod-97 check of a compact IBAN. */
function ibanChecksumOk(iban: string): boolean {
  const s = (iban.slice(4) + iban.slice(0, 4)).toUpperCase();
  let rem = 0;
  for (const ch of s) {
    const v = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const d of v) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

function ibans(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(IBAN_RE)) {
    const digits = m[0].replace(/\D/g, '').length;
    if (digits < 10) continue;
    out.push({ kind: 'iban', start: m.index, end: m.index + m[0].length, replacement: '[IBAN]' });
  }
  for (const m of text.matchAll(IBAN_ANYCASE_RE)) {
    // The pattern may run on into the next word ("... 00 please"): take the longest valid prefix.
    const pos = [...m[0]].flatMap((ch, i) => (ch === ' ' ? [] : [i]));
    const compact = pos.map((i) => m[0][i]).join('');
    for (let n = Math.min(34, compact.length); n >= 15; n--) {
      if (ibanChecksumOk(compact.slice(0, n))) {
        out.push({ kind: 'iban', start: m.index, end: m.index + pos[n - 1]! + 1, replacement: '[IBAN]' });
        break;
      }
    }
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

/** A run of at least 13 digits with single spaces or dashes between them. */
const DIGIT_RUN_RE = /\b\d(?:[ -]?\d){12,40}\b/g;

/**
 * The card number inside one digit run, or null. A card is followed by other digits often
 * ("4111 1111 1111 1111 12/26", "... 1111 123"), so the run is not judged as a whole:
 * 13-19-digit pieces that start and end on a digit-group boundary are tried first (longest
 * wins), then the longest Luhn-valid prefix of each group start.
 */
function cardIn(run: string): Span | null {
  const groups = [...run.matchAll(/\d+/g)].map((g) => ({ start: g.index, end: g.index + g[0].length, digits: g[0] }));
  let best: Span | null = null;
  let bestLen = 0;
  for (let a = 0; a < groups.length; a++) {
    let digits = '';
    for (let b = a; b < groups.length; b++) {
      digits += groups[b]!.digits;
      if (digits.length > 19) break;
      if (digits.length >= 13 && digits.length > bestLen && luhn(digits)) {
        best = { start: groups[a]!.start, end: groups[b]!.end };
        bestLen = digits.length;
      }
    }
  }
  if (best) return best;
  for (let a = 0; a < groups.length; a++) {
    const positions: number[] = [];
    for (let b = a; b < groups.length && positions.length < 19; b++) {
      for (let i = groups[b]!.start; i < groups[b]!.end && positions.length < 19; i++) positions.push(i);
    }
    for (let n = positions.length; n >= 13; n--) {
      const digits = positions.slice(0, n).map((i) => run[i]).join('');
      if (luhn(digits)) return { start: positions[0]!, end: positions[n - 1]! + 1 };
    }
  }
  return null;
}

function cards(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(DIGIT_RUN_RE)) {
    const span = cardIn(m[0]);
    if (span) out.push({ kind: 'card', start: m.index + span.start, end: m.index + span.end, replacement: '[CARD]' });
  }
  return out;
}

/** The 3-4 digit security code after "CVV", "CVC", "CID" or "security code". */
const CVV_RE = /\b(?:CVV2?|CVC2?|CVN|CID|CSC|security code)\b[^\d\n]{0,12}?(\d{3,4})\b/dgi;

function cvvs(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const m of text.matchAll(CVV_RE)) {
    const idx = m.indices?.[1];
    if (idx) out.push({ kind: 'cvv', start: idx[0], end: idx[1], replacement: '[CVV]' });
  }
  return out;
}

const B58 = '[1-9A-HJ-NP-Za-km-z]';
/** A word about keys shortly before a 0x-prefixed 64-hex value makes it a private key, not a tx hash. */
const KEY_CONTEXT_RE = /\b(?:private|secret|priv)[ _-]?key|\bprivkey\b|\bkey\b/i;

function keys(text: string): Candidate[] {
  const out: Candidate[] = [];
  const push = (start: number, end: number) => out.push({ kind: 'key', start, end, replacement: '[PRIVATE_KEY]' });
  // 64 hex characters: an EVM / raw private key. With 0x and no key word it may be a tx hash (crypto).
  for (const m of text.matchAll(/\b(?:0x)?[a-fA-F0-9]{64}\b/g)) {
    if (m[0].startsWith('0x') && !KEY_CONTEXT_RE.test(text.slice(Math.max(0, m.index - 40), m.index))) continue;
    push(m.index, m.index + m[0].length);
  }
  const base58 = [
    new RegExp(`\\b5${B58}{50}\\b`, 'g'), // WIF, uncompressed
    new RegExp(`\\b[KL]${B58}{51}\\b`, 'g'), // WIF, compressed
    new RegExp(`\\b[xyzt]prv${B58}{100,108}\\b`, 'g'), // BIP32 extended private key
    new RegExp(`\\b${B58}{86,90}\\b`, 'g'), // Solana secret key (Phantom export)
  ];
  for (const re of base58) {
    for (const m of text.matchAll(re)) {
      if (!/\d/.test(m[0]) || !/[A-Z]/.test(m[0]) || !/[a-z]/.test(m[0])) continue;
      push(m.index, m.index + m[0].length);
    }
  }
  return out;
}

const CRYPTO_RES = [
  new RegExp(`\\b[xyzt]pub${B58}{100,108}\\b`, 'g'), // BIP32 extended public key
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
      if (i >= 3) {
        // base58 forms: demand a mix of digits, upper and lower case letters
        if (!/\d/.test(s) || !/[A-Z]/.test(s) || !/[a-z]/.test(s)) continue;
      }
      out.push({ kind: 'crypto', start: m.index, end: m.index + s.length, replacement: '[CRYPTO_ADDRESS]' });
    }
  });
  return out;
}

/** What may stand between two words of a phrase: spaces, newlines, , ; / | - and a list number ("2." "3)"). */
const SEED_GAP_RE = /^[\s,;/|·•-]*(?:\(?\d{1,2}[.):-]?[\s,;/|·•-]*)?$/;
const SEED_LEAD_RE = /(?:^|[\s,;])(\(?\d{1,2}[.):-]?\s*)$/;
/** Recovery phrases have 12, 15, 18, 21 or 24 words. */
const PHRASE_LENGTHS = new Set([12, 15, 18, 21, 24]);
const MIN_SEED_WORDS = 11;

/** True when `w` is one typo (insert, delete, replace or swap) away from a BIP39 word. */
function nearBip39(w: string): boolean {
  if (w.length < 3 || w.length > 9) return false;
  for (const b of BIP39_WORDS) {
    if (Math.abs(b.length - w.length) > 1) continue;
    if (oneEditApart(w, b)) return true;
  }
  return false;
}

function oneEditApart(a: string, b: string): boolean {
  if (a === b) return true;
  if (a.length === b.length) {
    const diff: number[] = [];
    for (let i = 0; i < a.length && diff.length <= 2; i++) if (a[i] !== b[i]) diff.push(i);
    if (diff.length === 1) return true;
    const [i, j] = diff as [number, number];
    return diff.length === 2 && j === i + 1 && a[i] === b[j] && a[j] === b[i];
  }
  const [s, l] = a.length < b.length ? [a, b] : [b, a];
  let i = 0;
  while (i < s.length && s[i] === l[i]) i++;
  return s.slice(i) === l.slice(i + 1);
}

/**
 * Find wallet recovery ("seed") phrases: at least 11 BIP39 words in a row, with one unknown or
 * misspelt word allowed, separated by spaces, newlines, commas, slashes or dashes, optionally
 * numbered ("1. word 2. word" or one per line).
 *
 * - a run of >= 11 known words is a phrase;
 * - two runs joined by one unknown word are one phrase when the total is a real phrase length
 *   (12, 15, 18, 21 or 24), so a neighbouring word is not glued onto a complete phrase;
 * - a run one word short of a real length takes in a misspelt neighbour ("acident").
 */
export function findSeedPhrases(text: string): Span[] {
  const words = [...text.matchAll(/[A-Za-z]+/g)].map((m) => ({
    w: m[0].toLowerCase(),
    start: m.index,
    end: m.index + m[0].length,
  }));
  const linked = (i: number) => i > 0 && SEED_GAP_RE.test(text.slice(words[i - 1]!.end, words[i]!.start));

  // Runs of consecutive known words: [first, last] word indices.
  const runs: Array<[number, number]> = [];
  for (let i = 0; i < words.length; i++) {
    if (!BIP39_WORDS.has(words[i]!.w)) continue;
    const last = runs[runs.length - 1];
    if (last && last[1] === i - 1 && linked(i)) last[1] = i;
    else runs.push([i, i]);
  }
  const size = (r: [number, number]) => r[1] - r[0] + 1;

  const found: Array<[number, number]> = [];
  for (let k = 0; k < runs.length; k++) {
    const r = runs[k]!;
    const next = runs[k + 1];
    // Two runs around exactly one unknown word.
    if (next && next[0] === r[1] + 2 && linked(r[1] + 1) && linked(next[0]) && PHRASE_LENGTHS.has(size(r) + 1 + size(next))) {
      found.push([r[0], next[1]]);
      continue;
    }
    if (size(r) < MIN_SEED_WORDS) continue;
    let [a, b] = r;
    if (PHRASE_LENGTHS.has(size(r) + 1)) {
      if (b + 1 < words.length && linked(b + 1) && nearBip39(words[b + 1]!.w)) b++;
      else if (a > 0 && linked(a) && nearBip39(words[a - 1]!.w)) a--;
    }
    found.push([a, b]);
  }

  const spans: Span[] = [];
  for (const [a, b] of found) {
    let start = words[a]!.start;
    const lead = SEED_LEAD_RE.exec(text.slice(Math.max(0, start - 6), start));
    if (lead?.[1]) start -= lead[1].length;
    const span = { start, end: words[b]!.end };
    const prev = spans[spans.length - 1];
    if (prev && span.start <= prev.end) prev.end = Math.max(prev.end, span.end);
    else spans.push(span);
  }
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

const DETECTORS = [urls, seeds, keys, cryptos, ibans, cards, cvvs, emails, phones, streets, names];

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
  cvv: 'card security code',
  key: 'private key',
  crypto: 'crypto address',
  seed: 'recovery phrase',
  street: 'street address',
  url: 'link (kept domain)',
  name: 'name',
};
