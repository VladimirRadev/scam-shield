import { describe, expect, it } from 'vitest';
import { redact, registrableDomain, mapRedactedSpanToOriginal } from '../src/redact';

describe('redact()', () => {
  it('removes email addresses but keeps the domain as a hint', () => {
    const r = redact('Write to anna.petrova@gmail.com today.');
    expect(r.text).toBe('Write to [EMAIL@gmail.com] today.');
    expect(r.counts.email).toBe(1);
  });

  it('removes phone numbers in common formats', () => {
    const r = redact('Call +1 (415) 555-0132 or 0888 123 456 or +44 7700 900123.');
    expect(r.text).not.toMatch(/555|0888|7700/);
    expect(r.counts.phone).toBe(3);
  });

  it('does not treat money, dates or times as phone numbers', () => {
    const t = 'Pay $1,250.00 by 2026-12-15 at 14:00. Order 42 ships in 3 days.';
    expect(redact(t).text).toBe(t);
  });

  it('removes IBANs', () => {
    const r = redact('New account: GB33 BUKB 2020 1555 5555 55, ref INV-77.');
    expect(r.text).toBe('New account: [IBAN], ref INV-77.');
  });

  it('removes payment card numbers (Luhn-valid)', () => {
    const r = redact('Card 4111 1111 1111 1111 exp 09/29');
    expect(r.text).toContain('[CARD]');
    expect(r.text).not.toContain('4111');
  });

  it('removes crypto addresses', () => {
    const r = redact(
      'Send to 0x52908400098527886E0F7030069857D2E4169EE7 or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq.',
    );
    expect(r.text).toBe('Send to [CRYPTO_ADDRESS] or [CRYPTO_ADDRESS].');
  });

  it('removes a 12-word seed phrase', () => {
    const seed = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
    const r = redact(`My phrase is ${seed} and I need help`);
    expect(r.text).toBe('My phrase is [SEED_PHRASE] and I need help');
    expect(r.counts.seed).toBe(1);
  });

  it('removes a numbered seed phrase', () => {
    const seed =
      '1. zoo 2. zone 3. zero 4. zebra 5. youth 6. young 7. you 8. yellow 9. year 10. yard 11. wrong 12. write';
    const r = redact(seed);
    expect(r.text).toBe('[SEED_PHRASE]');
  });

  it('does not redact ordinary English as a seed phrase', () => {
    const t = 'Please let me know if you have any questions about the role and the team before Friday.';
    expect(redact(t).text).toBe(t);
  });

  it('reduces full URLs to their registrable domain', () => {
    const r = redact('Track: https://track.dhl-parcel-help.top/u/88213?id=anna%40mail.com now');
    expect(r.text).toBe('Track: [URL:dhl-parcel-help.top] now');
  });

  it('handles multi-part public suffixes', () => {
    expect(registrableDomain('secure.login.barclays.co.uk')).toBe('barclays.co.uk');
    expect(registrableDomain('www.github.com')).toBe('github.com');
  });

  it('removes street addresses', () => {
    const r = redact('Deliver to 221B Baker Street, London.');
    expect(r.text).toBe('Deliver to [STREET_ADDRESS], London.');
  });

  it('removes names after greetings and in signatures', () => {
    const r = redact('Hi Maria,\nThanks for the call.\n\nBest regards,\nDaniel Novak\nTalent Partner');
    expect(r.text).toBe('Hi [NAME],\nThanks for the call.\n\nBest regards,\n[NAME]\nTalent Partner');
  });

  it('keeps generic greetings, which are themselves a scam sign', () => {
    const t = 'Dear Customer, your parcel is waiting.';
    expect(redact(t).text).toBe(t);
  });

  it('removes a self-introduced name', () => {
    expect(redact('Hello, my name is Sarah Lee and I work at Coinbase.').text).toBe(
      'Hello, my name is [NAME] and I work at Coinbase.',
    );
  });

  it('records offsets that map placeholders back to the original', () => {
    const original = 'Mail bob@x.io or call +359 888 123 456.';
    const r = redact(original);
    for (const red of r.redactions) {
      expect(r.text.slice(red.redacted.start, red.redacted.end)).toBe(red.replacement);
      expect(original.slice(red.original.start, red.original.end).length).toBeGreaterThan(0);
    }
    const idx = r.text.indexOf('[PHONE]');
    const mapped = mapRedactedSpanToOriginal({ start: idx, end: idx + '[PHONE]'.length }, r.redactions);
    expect(original.slice(mapped.start, mapped.end)).toBe('+359 888 123 456');
  });

  it('maps a span that lies between redactions by shifting offsets', () => {
    const original = 'Mail bob@x.io now, then wait.';
    const r = redact(original);
    const idx = r.text.indexOf('then wait');
    const mapped = mapRedactedSpanToOriginal({ start: idx, end: idx + 9 }, r.redactions);
    expect(original.slice(mapped.start, mapped.end)).toBe('then wait');
  });

  it('is idempotent on already-redacted text', () => {
    const once = redact('Mail bob@x.io, IBAN DE89 3704 0044 0532 0130 00').text;
    expect(redact(once).text).toBe(once);
  });
});
