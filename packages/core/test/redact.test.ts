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

describe('redact(): card numbers', () => {
  it.each([
    ['Card: 4111 1111 1111 1111 12/26 CVV 123', 'Card: [CARD] 12/26 CVV [CVV]'],
    ['Card 4111 1111 1111 1111 123', 'Card [CARD] 123'],
    ['card number 4111111111111111, exp 12/26', 'card number [CARD], exp 12/26'],
    ['Pay with 5500-0000-0000-0004 99 today', 'Pay with [CARD] 99 today'],
    ['Ref 12 4111 1111 1111 1111 thanks', 'Ref 12 [CARD] thanks'],
  ])('masks the longest Luhn-valid card number inside a longer digit run: %s', (input, expected) => {
    expect(redact(input).text).toBe(expected);
  });

  it.each([
    ['CVV: 123', 'CVV: [CVV]'],
    ['cvc 9876 please', 'cvc [CVV] please'],
    ['the CVV2 is 456', 'the CVV2 is [CVV]'],
    ['security code (CVC) 321', 'security code (CVC) [CVV]'],
  ])('masks the security code after CVV / CVC: %s', (input, expected) => {
    expect(redact(input).text).toBe(expected);
  });

  it('keeps a Luhn-invalid digit run that is not a card', () => {
    expect(redact('card 4111-1111-1111-1112').text).toBe('card 4111-1111-1111-1112');
  });
});

describe('redact(): recovery phrases', () => {
  const W = 'abandon ability able about above absent absorb abstract absurd abuse access accident'.split(' ');

  it.each([
    ['11 words (one missing)', W.slice(0, 11).join(' ')],
    ['one misspelt word at the end', [...W.slice(0, 11), 'acident'].join(' ')],
    ['one misspelt word at the start', ['abandn', ...W.slice(1)].join(' ')],
    ['one unknown word in the middle', [...W.slice(0, 4), 'abuve', ...W.slice(5)].join(' ')],
    ['dash separators', W.join(' - ')],
    ['slash separators', W.join('/')],
    ['comma separators', W.join(', ')],
    ['one word per line', W.join('\n')],
    ['a numbered list on one line', W.map((w, i) => `${i + 1}. ${w}`).join(' ')],
    ['a numbered list, one per line', W.map((w, i) => `${i + 1}) ${w}`).join('\n')],
    ['upper case', W.join(' ').toUpperCase()],
  ])('masks a phrase with %s', (_name, seed) => {
    expect(redact(`Here: ${seed}`).text).toBe('Here: [SEED_PHRASE]');
  });

  it('masks a 24-word phrase with one misspelt word as one phrase', () => {
    const w24 = [...W, ...'zoo zone zero zebra youth young you yellow year yard wrong write'.split(' ')];
    w24[15] = 'yuong';
    expect(redact(w24.join(' ')).text).toBe('[SEED_PHRASE]');
  });

  it('does not glue a neighbouring word onto a complete phrase', () => {
    expect(redact(`My phrase is ${W.join(' ')} and I need help`).text).toBe('My phrase is [SEED_PHRASE] and I need help');
    expect(redact(`Seed: ${W.join(' ')}`).text).toBe('Seed: [SEED_PHRASE]');
  });

  it('needs at least 11 recovery-phrase words and allows only one unknown word', () => {
    const ten = W.slice(0, 10).join(' ');
    expect(redact(ten).text).toBe(ten);
    const twoUnknown = [...W.slice(0, 4), 'the', ...W.slice(4, 8), 'and', ...W.slice(8)].join(' ');
    expect(redact(twoUnknown).text).toBe(twoUnknown);
  });

  it('leaves ordinary English with many common words alone', () => {
    const t =
      'I hope you are able to come to the event about the new office. Bring your laptop and a pen, we will start early, have lunch at noon and finish by four. All of us can help you find the room.';
    expect(redact(t).text).toBe(t);
  });
});

describe('redact(): private keys', () => {
  const HEX = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

  it.each([
    [`private key: ${HEX}`, 'private key: [PRIVATE_KEY]'],
    [`my key is 0x${HEX}`, 'my key is [PRIVATE_KEY]'],
    [`here it is ${HEX} thanks`, 'here it is [PRIVATE_KEY] thanks'],
    ['WIF 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ', 'WIF [PRIVATE_KEY]'],
    ['key KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ok', 'key [PRIVATE_KEY] ok'],
    [
      'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
      '[PRIVATE_KEY]',
    ],
    [
      'Phantom export: 4Z7cXSyeFR8wNGMVXUE1TwtKn5D5Vu7FzEv69dokLv7KrQk7h6pu4LF8ZRR9yQBhc7uSM6RTTZtU1fmaxiNrxXrs',
      'Phantom export: [PRIVATE_KEY]',
    ],
  ])('masks %s', (input, expected) => {
    expect(redact(input).text).toBe(expected);
  });

  it('masks an extended public key as a crypto address, not as a private key', () => {
    const r = redact('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8');
    expect(r.text).toBe('[CRYPTO_ADDRESS]');
  });

  it('keeps a 0x transaction hash without a key word a crypto address', () => {
    expect(redact(`tx 0x${HEX} confirmed`).text).toBe('tx [CRYPTO_ADDRESS] confirmed');
  });
});

describe('redact(): phone numbers and IBANs', () => {
  it.each([
    ['Call me on 5551234567 tonight', 'Call me on [PHONE] tonight'],
    ['WhatsApp: 44 7700 900123', 'WhatsApp: [PHONE]'],
    ['text 359 879 324 734 please', 'text [PHONE] please'],
    ['Call +359 879 324 734.', 'Call [PHONE].'],
    ['my number +359888123456 ok', 'my number [PHONE] ok'],
    ['ring 0044 20 7946 0958', 'ring [PHONE]'],
  ])('masks a 10-15 digit phone number: %s', (input, expected) => {
    expect(redact(input).text).toBe(expected);
  });

  it.each([
    'Invoice INV-2026-00417, total EUR 18,420.00, due 2026-12-15 at 14:00.',
    'Your DHL shipment 4829 1137 26 is out for delivery.',
    'Order 112-7654321-1234567 has shipped.',
    'Version 10.2.3 and build 20261127 are live.',
  ])('does not mask order numbers, amounts, dates or versions: %s', (t) => {
    expect(redact(t).text).toBe(t);
  });

  it.each([
    ['iban de89 3704 0044 0532 0130 00 please', 'iban [IBAN] please'],
    ['IBAN de89370400440532013000.', 'IBAN [IBAN].'],
    ['Pay to Gb33 bukb 2020 1555 5555 55 today', 'Pay to [IBAN] today'],
    ['IBAN DE89 3704 0044 0532 0130 00 please', 'IBAN [IBAN] please'],
  ])('detects IBANs in any letter case before phone numbers: %s', (input, expected) => {
    const r = redact(input);
    expect(r.text).toBe(expected);
    expect(r.counts.phone).toBeUndefined();
  });

  it('does not take a lower-case word with digits for an IBAN unless the checksum is valid', () => {
    expect(redact('ab12 3456 7890 1234 5678 90').counts.iban).toBeUndefined();
  });
});
