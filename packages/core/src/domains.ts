/**
 * Domain helpers: registrable-domain reduction, host extraction and the list of
 * brands that scammers imitate most often.
 */
import type { Span } from './types';

/** Multi-label public suffixes (a small, practical subset of the Public Suffix List). */
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk', 'me.uk', 'net.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au', 'co.nz', 'org.nz', 'co.jp', 'ne.jp', 'or.jp',
  'co.kr', 'com.br', 'com.mx', 'com.ar', 'com.cn', 'com.tr', 'com.sg', 'com.my', 'com.hk', 'com.tw',
  'co.in', 'net.in', 'org.in', 'co.za', 'com.ng', 'com.ua', 'com.pl', 'co.il', 'com.ph', 'com.vn',
  'com.pk', 'com.eg', 'com.sa', 'co.id', 'co.th', 'com.co', 'com.pe', 'com.ve',
  // Hosting platforms whose sub-domains belong to different owners (PSL "private" section).
  'github.io', 'pages.dev', 'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com', 'herokuapp.com',
  'blogspot.com', 'azurewebsites.net', 'workers.dev', 'glitch.me', 'repl.co', 'ngrok.io',
  'ngrok-free.app', 'onrender.com', 'fly.dev', 'surge.sh', 'wixsite.com', 'weebly.com', 'square.site',
]);

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** Reduce a host name to its registrable domain (eTLD+1), e.g. a.b.example.co.uk -> example.co.uk. */
export function registrableDomain(host: string): string {
  let h = host.trim().toLowerCase().replace(/\.$/, '');
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '');
  h = h.split(/[/?#]/)[0] ?? h;
  h = h.replace(/:\d+$/, '');
  if (IPV4.test(h)) return h;
  const labels = h.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(last2)) return labels.slice(-3).join('.');
  return last2;
}

/** The part of a registrable domain before its public suffix, e.g. paypa1-security.com -> paypa1-security. */
export function domainLabel(rd: string): string {
  const labels = rd.split('.');
  if (labels.length >= 3 && MULTI_SUFFIXES.has(labels.slice(-2).join('.'))) return labels[0] ?? rd;
  return labels.length >= 2 ? labels.slice(0, -1).join('.') : rd;
}

export function topLevelDomain(rd: string): string {
  const labels = rd.split('.');
  return labels[labels.length - 1] ?? '';
}

/** TLDs accepted for bare domains written without http:// (keeps file names like report.pdf out). */
export const COMMON_TLDS = [
  'com', 'net', 'org', 'io', 'co', 'app', 'dev', 'ai', 'me', 'info', 'biz', 'us', 'uk', 'de', 'fr', 'es',
  'it', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk', 'fi', 'pl', 'cz', 'bg', 'ro', 'gr', 'pt', 'ie', 'ru',
  'ua', 'cn', 'jp', 'kr', 'in', 'au', 'nz', 'ca', 'br', 'mx', 'eu', 'xyz', 'top', 'online', 'site',
  'shop', 'store', 'live', 'click', 'link', 'icu', 'cfd', 'sbs', 'buzz', 'rest', 'support', 'help',
  'services', 'finance', 'gg', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws', 'ly', 'to', 'tv', 'gov',
  'edu', 'cyou', 'monster', 'quest', 'bond', 'win', 'vip', 'pro', 'tech', 'cloud', 'website', 'space',
  'zone', 'today', 'world', 'network', 'wallet', 'exchange', 'trade', 'money', 'cash', 'bank', 'events',
];

/** TLDs that are cheap and heavily abused for throw-away scam sites. */
export const ABUSED_TLDS = new Set([
  'top', 'xyz', 'icu', 'click', 'rest', 'zip', 'mov', 'cfd', 'sbs', 'buzz', 'cyou', 'monster', 'quest',
  'bond', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'work', 'country', 'kim', 'loan', 'win', 'bid', 'men',
  'party', 'review', 'stream', 'download', 'racing', 'date', 'faith', 'science', 'accountant', 'cricket',
  'support', 'help', 'vip', 'online', 'site', 'live',
]);

export interface FoundHost {
  host: string;
  rd: string;
  span: Span;
  /** True when written as a full URL (with scheme or www.). */
  isUrl: boolean;
}

const TLD_ALT = COMMON_TLDS.join('|');
const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'()[\]{}]+/gi;
const BARE_RE = new RegExp(
  `(?<![@\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${TLD_ALT})\\b(?:\\/[^\\s<>"'()\\[\\]{}]*)?`,
  'gi',
);
const EMAIL_DOMAIN_RE = /[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,24})\b/g;

/** Trailing punctuation that belongs to the sentence, not the URL. */
export function trimUrl(raw: string): string {
  let s = raw;
  while (/[.,;:!?'")\]}>]$/.test(s)) s = s.slice(0, -1);
  return s;
}

export function hostOf(url: string): string {
  return (
    url
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .replace(/^[^@/]*@/, '')
      .split(/[/?#]/)[0]
      ?.replace(/:\d+$/, '')
      .toLowerCase() ?? ''
  );
}

/** Find URLs, bare domains and e-mail domains in a text. */
export function findHosts(text: string): FoundHost[] {
  const out: FoundHost[] = [];
  const taken: Span[] = [];
  const overlaps = (s: Span) => taken.some((t) => s.start < t.end && t.start < s.end);

  for (const m of text.matchAll(URL_RE)) {
    const raw = trimUrl(m[0]);
    const span = { start: m.index, end: m.index + raw.length };
    const host = hostOf(raw);
    if (!host.includes('.')) continue;
    out.push({ host, rd: registrableDomain(host), span, isUrl: true });
    taken.push(span);
  }
  for (const m of text.matchAll(EMAIL_DOMAIN_RE)) {
    const domain = (m[1] ?? '').toLowerCase();
    const start = m.index + m[0].length - domain.length;
    const span = { start, end: m.index + m[0].length };
    if (overlaps(span)) continue;
    out.push({ host: domain, rd: registrableDomain(domain), span, isUrl: false });
    taken.push({ start: m.index, end: span.end });
  }
  for (const m of text.matchAll(BARE_RE)) {
    const raw = trimUrl(m[0]);
    const span = { start: m.index, end: m.index + raw.length };
    if (overlaps(span)) continue;
    const host = hostOf(raw);
    out.push({ host, rd: registrableDomain(host), span, isUrl: raw.includes('/') });
    taken.push(span);
  }
  return out.sort((a, b) => a.span.start - b.span.start);
}

export interface Brand {
  name: string;
  /** Lower-case labels that identify the brand inside a domain. */
  keys: string[];
  /** Registrable domains the brand really uses. */
  official: string[];
}

export const BRANDS: Brand[] = [
  { name: 'PayPal', keys: ['paypal'], official: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { name: 'Apple', keys: ['apple', 'appleid', 'icloud', 'itunes'], official: ['apple.com', 'icloud.com', 'itunes.com', 'apple.news'] },
  { name: 'Microsoft', keys: ['microsoft', 'office365', 'outlook', 'onedrive', 'msonline'], official: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'office365.com', 'onedrive.com', 'sharepoint.com', 'windows.com', 'msn.com', 'bing.com', 'skype.com', 'azure.com'] },
  { name: 'Google', keys: ['google', 'gmail', 'youtube'], official: ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com', 'withgoogle.com', 'gstatic.com', 'youtu.be', 'goo.gl', 'google.co.uk', 'google.de', 'blog.google', 'firebase.google.com'] },
  { name: 'Amazon', keys: ['amazon', 'amzn'], official: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.in', 'amzn.to', 'amazon.jobs', 'aws.amazon.com', 'amazonaws.com'] },
  { name: 'Netflix', keys: ['netflix'], official: ['netflix.com'] },
  { name: 'Facebook / Meta', keys: ['facebook', 'instagram'], official: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'facebookmail.com'] },
  { name: 'WhatsApp', keys: ['whatsapp'], official: ['whatsapp.com', 'wa.me'] },
  { name: 'Telegram', keys: ['telegram'], official: ['telegram.org', 't.me', 'telegram.me'] },
  { name: 'LinkedIn', keys: ['linkedin'], official: ['linkedin.com', 'lnkd.in'] },
  { name: 'GitHub', keys: ['github'], official: ['github.com', 'github.io', 'githubusercontent.com', 'github.blog'] },
  { name: 'Binance', keys: ['binance'], official: ['binance.com'] },
  { name: 'Coinbase', keys: ['coinbase'], official: ['coinbase.com'] },
  { name: 'Kraken', keys: ['kraken'], official: ['kraken.com'] },
  { name: 'MetaMask', keys: ['metamask'], official: ['metamask.io'] },
  { name: 'OpenSea', keys: ['opensea'], official: ['opensea.io'] },
  { name: 'Uniswap', keys: ['uniswap'], official: ['uniswap.org'] },
  { name: 'Ledger', keys: ['ledger'], official: ['ledger.com'] },
  { name: 'Trezor', keys: ['trezor'], official: ['trezor.io'] },
  { name: 'DHL', keys: ['dhl'], official: ['dhl.com', 'dhl.de', 'dhl.co.uk'] },
  { name: 'FedEx', keys: ['fedex'], official: ['fedex.com'] },
  { name: 'UPS', keys: ['ups'], official: ['ups.com'] },
  { name: 'USPS', keys: ['usps'], official: ['usps.com'] },
  { name: 'Royal Mail', keys: ['royalmail'], official: ['royalmail.com'] },
  { name: 'DPD', keys: ['dpd'], official: ['dpd.com', 'dpd.co.uk'] },
  { name: 'eBay', keys: ['ebay'], official: ['ebay.com', 'ebay.co.uk', 'ebay.de'] },
  { name: 'Chase', keys: ['chase'], official: ['chase.com'] },
  { name: 'Wells Fargo', keys: ['wellsfargo'], official: ['wellsfargo.com'] },
  { name: 'Bank of America', keys: ['bankofamerica', 'bofa'], official: ['bankofamerica.com'] },
  { name: 'HSBC', keys: ['hsbc'], official: ['hsbc.com', 'hsbc.co.uk'] },
  { name: 'Barclays', keys: ['barclays'], official: ['barclays.co.uk', 'barclays.com'] },
  { name: 'Revolut', keys: ['revolut'], official: ['revolut.com'] },
  { name: 'Wise', keys: ['transferwise'], official: ['wise.com'] },
  { name: 'Stripe', keys: ['stripe'], official: ['stripe.com'] },
  { name: 'Steam', keys: ['steamcommunity', 'steampowered'], official: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'Norton', keys: ['norton'], official: ['norton.com'] },
  { name: 'McAfee', keys: ['mcafee'], official: ['mcafee.com'] },
  { name: 'IRS', keys: ['irs'], official: ['irs.gov'] },
  { name: 'HMRC', keys: ['hmrc'], official: ['gov.uk'] },
];

const OFFICIAL = new Set(BRANDS.flatMap((b) => b.official));

export function isOfficialDomain(rd: string, host = rd): boolean {
  if (OFFICIAL.has(rd)) return true;
  return BRANDS.some((b) => b.official.some((o) => host === o || host.endsWith(`.${o}`)));
}

/** Undo common look-alike character tricks: 0->o, 1->l, rn->m, vv->w ... */
export function deconfuse(label: string, oneAs: 'l' | 'i' = 'l'): string {
  return label
    .toLowerCase()
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/1/g, oneAs)
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/\$/g, 's');
}

export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const dp = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]!;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j]!;
      dp[j] = Math.min(dp[j]! + 1, dp[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length]!;
}

export interface LookalikeHit {
  brand: Brand;
  host: string;
  rd: string;
  reason: string;
}

/** Decide whether a host imitates a known brand. Returns null for official or unrelated hosts. */
export function lookalikeOf(host: string, rd = registrableDomain(host)): LookalikeHit | null {
  if (isOfficialDomain(rd, host)) return null;
  const label = domainLabel(rd);
  if (label.startsWith('xn--') || host.split('.').some((l) => l.startsWith('xn--'))) {
    return { brand: { name: 'a known site', keys: [], official: [] }, host, rd, reason: 'uses look-alike international letters (punycode)' };
  }
  const tokens = label.split(/[-.]+/).filter(Boolean);
  const subLabels = host.slice(0, Math.max(0, host.length - rd.length)).split(/[-.]+/).filter(Boolean);
  for (const brand of BRANDS) {
    for (const key of brand.keys) {
      for (const tok of tokens) {
        const variants = new Set([tok, deconfuse(tok, 'l'), deconfuse(tok, 'i')]);
        for (const v of variants) {
          if (v === key) {
            return tok === key
              ? { brand, host, rd, reason: `puts "${key}" inside a domain ${brand.name} does not own` }
              : { brand, host, rd, reason: `swaps letters to look like ${brand.name}` };
          }
          if (key.length >= 6 && v.length > key.length && (v.startsWith(key) || v.endsWith(key))) {
            return { brand, host, rd, reason: `glues "${key}" to other words in a domain ${brand.name} does not own` };
          }
        }
        if (key.length >= 6 && tok.length >= 5 && editDistance(deconfuse(tok), key) === 1) {
          return { brand, host, rd, reason: `is one letter away from ${brand.name}` };
        }
      }
      if (key.length >= 4 && subLabels.includes(key)) {
        return { brand, host, rd, reason: `hides "${key}" in front of an unrelated domain` };
      }
    }
  }
  return null;
}

export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 't.ly', 'tiny.cc', 'rebrand.ly',
  's.id', 'v.gd', 'ow.ly', 'shorte.st', 'adf.ly', 'bl.ink', 'short.io', 'tny.im',
]);
