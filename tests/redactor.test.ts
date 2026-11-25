import { describe, expect, it } from 'vitest';
import { redact } from '../src/redactor.js';

const out = (s: string) => redact(s).text;

describe('redact: emails', () => {
  it.each([
    ['contact john.doe@example.com now', 'contact <REDACTED: EMAIL> now'],
    ['a+tag@sub.domain.co.uk', '<REDACTED: EMAIL>'],
    ['(jane_doe@example.org).', '(<REDACTED: EMAIL>).'],
    ['USER@EXAMPLE.COM', '<REDACTED: EMAIL>'],
  ])('%s', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('redacts a very long local part (no bypass by length)', () => {
    const email = `${'a'.repeat(300)}@example.com`;
    expect(out(email)).toBe('<REDACTED: EMAIL>');
  });

  it('leaves non-emails alone', () => {
    expect(out('meet @ noon, user@localhost, foo@bar')).toBe('meet @ noon, user@localhost, foo@bar');
  });

  it('does not read digits inside an email as a card or SSN', () => {
    const r = redact('4111111111111111@example.com');
    expect(r.text).toBe('<REDACTED: EMAIL>');
    expect(r.counts).toEqual({ EMAIL: 1, CREDIT_CARD: 0, SSN: 0 });
  });
});

describe('redact: credit cards', () => {
  it.each([
    ['4111111111111111', '<REDACTED: CREDIT_CARD>'],
    ['4111 1111 1111 1111', '<REDACTED: CREDIT_CARD>'],
    ['4111-1111-1111-1111', '<REDACTED: CREDIT_CARD>'],
    ['3782 822463 10005', '<REDACTED: CREDIT_CARD>'], // Amex 4-6-5
    ['4111111111111', '<REDACTED: CREDIT_CARD>'], // 13 digits
    ['4111111111111111111', '<REDACTED: CREDIT_CARD>'], // 19 digits
    ['pay with 5500 0000 0000 0004 today', 'pay with <REDACTED: CREDIT_CARD> today'],
  ])('%s', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('is not partly consumed by the 9-digit SSN rule', () => {
    const r = redact('4111111111111111');
    expect(r.text).toBe('<REDACTED: CREDIT_CARD>');
    expect(r.counts.SSN).toBe(0);
  });

  it('does not require a valid Luhn checksum (fail safe)', () => {
    expect(out('1234567812345678')).toBe('<REDACTED: CREDIT_CARD>');
  });

  it('leaves digit runs outside 13-19 digits alone (12 and 20)', () => {
    expect(out('123456789012')).toBe('123456789012');
    expect(out('12345678901234567890')).toBe('12345678901234567890');
  });
});

describe('redact: SSNs', () => {
  it.each([
    ['123-45-6789', '<REDACTED: SSN>'],
    ['123 45 6789', '<REDACTED: SSN>'],
    ['123456789', '<REDACTED: SSN>'], // standalone 9 digits
    ['SSN: 123-45-6789.', 'SSN: <REDACTED: SSN>.'],
    ['id=123456789;', 'id=<REDACTED: SSN>;'],
  ])('%s', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('does not touch digit runs of other lengths', () => {
    expect(out('12345678 and 1234567890')).toBe('12345678 and 1234567890');
  });

  it('does not redact 9 digits that are part of a longer run', () => {
    expect(out('12345678901')).toBe('12345678901');
  });

  it('does not mix separators', () => {
    expect(out('123-45 6789')).toBe('123-45 6789');
  });
});

describe('redact: mixed and repeated content', () => {
  it('redacts every type in one message and counts them', () => {
    const r = redact('Mail a@b.com or c@d.org, card 4111 1111 1111 1111, ssn 123-45-6789, alt 987654321');
    expect(r.text).toBe(
      'Mail <REDACTED: EMAIL> or <REDACTED: EMAIL>, card <REDACTED: CREDIT_CARD>, ssn <REDACTED: SSN>, alt <REDACTED: SSN>',
    );
    expect(r.counts).toEqual({ EMAIL: 2, CREDIT_CARD: 1, SSN: 2 });
  });

  it('is idempotent on already-redacted text', () => {
    const once = out('a@b.com 123-45-6789');
    expect(out(once)).toBe(once);
  });

  it('returns input unchanged when there is no PII', () => {
    const r = redact('Hello, how are you? Call me on 555-1234.');
    expect(r.text).toBe('Hello, how are you? Call me on 555-1234.');
    expect(r.counts).toEqual({ EMAIL: 0, CREDIT_CARD: 0, SSN: 0 });
  });

  it('handles empty input', () => {
    expect(redact('').text).toBe('');
  });
});

describe('redact: evasion via unicode', () => {
  it('catches full-width digits', () => {
    expect(out('４１１１ １１１１ １１１１ １１１１')).toBe('<REDACTED: CREDIT_CARD>');
    expect(out('１２３４５６７８９')).toBe('<REDACTED: SSN>');
  });

  it('catches full-width @ in emails', () => {
    expect(out('john＠example.com')).toBe('<REDACTED: EMAIL>');
  });

  it('catches digits split by zero-width characters', () => {
    expect(out('123​-45‍-6789')).toBe('<REDACTED: SSN>');
  });

  it('catches en-dash and NBSP separators', () => {
    expect(out('123–45–6789')).toBe('<REDACTED: SSN>');
    expect(out('4111 1111 1111 1111')).toBe('<REDACTED: CREDIT_CARD>');
  });
});

describe('redact: safety', () => {
  it('stays fast on adversarial input', () => {
    const inputs = ['a'.repeat(100_000), 'a.'.repeat(50_000), '1 '.repeat(50_000), `${'a'.repeat(50_000)}@`];
    const start = performance.now();
    for (const i of inputs) redact(i);
    expect(performance.now() - start).toBeLessThan(1500);
  });

  it('never leaves the original sensitive values in the output', () => {
    const secrets = ['john@example.com', '4111111111111111', '123-45-6789', '987654321'];
    const text = out(`x ${secrets.join(' | ')} y`);
    for (const s of secrets) expect(text).not.toContain(s);
  });
});
