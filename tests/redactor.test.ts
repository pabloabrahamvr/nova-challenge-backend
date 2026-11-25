import { describe, expect, it } from 'vitest';
import { luhnValid, redact } from '../src/redactor.js';

const out = (s: string) => redact(s).text;
const CARD = '<REDACTED: CREDIT_CARD>';
const EMAIL = '<REDACTED: EMAIL>';
const SSN = '<REDACTED: SSN>';

describe('luhnValid', () => {
  it.each(['4111111111111111', '4222222222222', '378282246310005', '6799990100000000019'])('accepts %s', (n) => {
    expect(luhnValid(n)).toBe(true);
  });
  it.each(['4111111111111112', '1234567812345678', '4111111111111'])('rejects %s', (n) => {
    expect(luhnValid(n)).toBe(false);
  });
});

describe('emails', () => {
  it.each([
    ['contact john.doe@example.com now', `contact ${EMAIL} now`],
    ['a+tag@sub.domain.co.uk', EMAIL],
    ['first_last-99@my-host.io', EMAIL],
    ['USER@EXAMPLE.COM', EMAIL],
    ['(jane@example.org).', `(${EMAIL}).`],
    ['<jane@example.org>', `<${EMAIL}>`],
    ['"quoted" a%b@x.co,next', `"quoted" ${EMAIL},next`],
  ])('%s', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('redacts a very long local part (no bypass by length)', () => {
    expect(out(`${'a'.repeat(300)}@example.com`)).toBe(EMAIL);
  });

  it('leaves non-emails alone', () => {
    const text = 'meet @ noon, user@localhost, foo@bar, @handle';
    expect(out(text)).toBe(text);
  });
});

describe('credit cards (13-19 digits, Luhn-valid)', () => {
  it.each([
    ['4111111111111111', 'contiguous 16'],
    ['4111 1111 1111 1111', 'spaces'],
    ['4111-1111-1111-1111', 'hyphens'],
    ['3782 822463 10005', 'Amex 4-6-5'],
    ['5500-0000-0000-0004', 'Mastercard'],
    ['4222222222222', '13 digits'],
    ['6799990100000000019', '19 digits'],
    ['6011 1111 1111 1117', 'Discover'],
  ])('%s (%s)', (input) => {
    expect(out(input)).toBe(CARD);
  });

  it('is not partly consumed by the 9-digit SSN rule', () => {
    expect(redact('4111111111111111').counts).toEqual({ EMAIL: 0, CREDIT_CARD: 1, SSN: 0 });
  });

  it('redacts two adjacent cards separately', () => {
    expect(out('4111111111111111 5500000000000004')).toBe(`${CARD} ${CARD}`);
  });

  it('finds a valid card next to unrelated digits', () => {
    expect(out('4111111111111111 123')).toBe(`${CARD} 123`);
  });
});

describe('invalid credit card candidates are left alone', () => {
  it.each([
    ['1234 5678 1234 5678', 'fails Luhn'],
    ['4111111111111112', 'one digit off'],
    ['4111111111111111111', '19 digits, fails Luhn'],
    ['411111111111', '12 digits'],
    ['41111111111111111111', '20 digits (outside 13-19)'],
    ['2024-01-01 2024-02-02', 'date range'],
    ['555-123-4567', 'phone number'],
  ])('%s (%s)', (input) => {
    expect(out(input)).toBe(input);
  });

  it('does not redact a valid card number hidden inside a longer unbroken digit run', () => {
    const text = '9' + '4111111111111111' + '9'; // 18 contiguous digits, fails Luhn as a whole
    expect(luhnValid(text)).toBe(false);
    expect(out(text)).toBe(text);
  });
});

describe('SSNs', () => {
  it.each([
    ['123-45-6789', SSN],
    ['123 45 6789', SSN],
    ['123456789', SSN],
    ['SSN: 123-45-6789.', `SSN: ${SSN}.`],
    ['id=123456789;', `id=${SSN};`],
    ['(987654321)', `(${SSN})`],
  ])('%s', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it.each([
    ['12345678', '8 digits'],
    ['1234567890', '10 digits'],
    ['12345678901', '11 digits'],
    ['123-45 6789', 'mixed separators'],
    ['12-345-6789', 'wrong grouping'],
  ])('leaves %s alone (%s)', (input) => {
    expect(out(input)).toBe(input);
  });
});

describe('overlap priority (no partial or double redaction)', () => {
  it('email beats SSN: digits in the local part', () => {
    const r = redact('123456789@example.com');
    expect(r.text).toBe(EMAIL);
    expect(r.counts).toEqual({ EMAIL: 1, CREDIT_CARD: 0, SSN: 0 });
  });

  it('email beats card', () => {
    expect(redact('4111111111111111@example.com').counts).toEqual({ EMAIL: 1, CREDIT_CARD: 0, SSN: 0 });
  });

  it('two SSNs separated by a space are not merged into one card', () => {
    const r = redact('123-45-6789 987-65-4321');
    expect(r.text).toBe(`${SSN} ${SSN}`);
    expect(r.counts.CREDIT_CARD).toBe(0);
  });

  it('is idempotent', () => {
    const once = out('a@b.com 123-45-6789 4111 1111 1111 1111');
    expect(out(once)).toBe(once);
  });
});

describe('multiple PII values in one message', () => {
  it('redacts every type and counts them', () => {
    const r = redact('Mail a@b.com or c@d.org, card 4111 1111 1111 1111, ssn 123-45-6789, alt 987654321');
    expect(r.text).toBe(`Mail ${EMAIL} or ${EMAIL}, card ${CARD}, ssn ${SSN}, alt ${SSN}`);
    expect(r.counts).toEqual({ EMAIL: 2, CREDIT_CARD: 1, SSN: 2 });
  });

  it('handles an SSN directly followed by a card', () => {
    expect(out('123-45-6789 4111 1111 1111 1111')).toBe(`${SSN} ${CARD}`);
  });

  it('handles a standalone 9-digit SSN directly followed by a card', () => {
    expect(out('123456789 4111 1111 1111 1111')).toBe(`${SSN} ${CARD}`);
    expect(out('4111 1111 1111 1111 123456789')).toBe(`${CARD} ${SSN}`);
  });

  it('redacts repeated occurrences of the same value', () => {
    expect(out('123-45-6789 and again 123-45-6789')).toBe(`${SSN} and again ${SSN}`);
  });
});

describe('text surrounding sensitive values', () => {
  it('preserves punctuation, newlines, tabs and spacing exactly', () => {
    expect(out('Hi,\n\tmy card:  4111-1111-1111-1111!\r\nBye  ')).toBe(`Hi,\n\tmy card:  ${CARD}!\r\nBye  `);
  });

  it('works at the start, middle and end of the string', () => {
    expect(out('123456789 mid a@b.com end 4111111111111111')).toBe(`${SSN} mid ${EMAIL} end ${CARD}`);
  });

  it('returns unrelated text byte-for-byte, including non-ASCII and compatibility characters', () => {
    const text = 'Ünïcode ﬁne ½ ① café ＡＢＣ — 日本語 🔐 12-34 v2.0';
    expect(out(text)).toBe(text);
    expect(out(`${text} 4111111111111111 ${text}`)).toBe(`${text} ${CARD} ${text}`);
  });
});

describe('strings without sensitive information', () => {
  it.each([
    'Hello, how are you?',
    'Call me on 555-1234.',
    'Order #12345 shipped on 2024-05-06.',
    'Price: $1,234,567.89',
    'version 1.2.3 build 4567',
  ])('%s', (text) => {
    const r = redact(text);
    expect(r.text).toBe(text);
    expect(r.counts).toEqual({ EMAIL: 0, CREDIT_CARD: 0, SSN: 0 });
  });
});

describe('empty and degenerate input', () => {
  it('empty string', () => {
    expect(redact('')).toEqual({ text: '', counts: { EMAIL: 0, CREDIT_CARD: 0, SSN: 0 } });
  });
  it.each([' ', '\n', '@', '-', '1', '​'])('%j is returned unchanged', (s) => {
    expect(out(s)).toBe(s);
  });
});

describe('unicode evasion', () => {
  it('catches full-width digits and keeps surrounding full-width text', () => {
    expect(out('ＡＢＣ ４１１１ １１１１ １１１１ １１１１ ｘｙｚ')).toBe(`ＡＢＣ ${CARD} ｘｙｚ`);
    expect(out('１２３４５６７８９')).toBe(SSN);
  });

  it('catches full-width @ in emails', () => {
    expect(out('john＠example.com')).toBe(EMAIL);
  });

  it('catches digits split by zero-width characters, and keeps zero-width chars outside the match', () => {
    expect(out('123​-45‍-6789')).toBe(SSN);
    expect(out('​123456789​')).toBe(`​${SSN}​`);
  });

  it('catches en-dash and NBSP separators', () => {
    expect(out('123–45–6789')).toBe(SSN);
    expect(out('4111 1111 1111 1111')).toBe(CARD);
  });
});

describe('safety', () => {
  it('stays fast on adversarial input', () => {
    const inputs = [
      'a'.repeat(100_000),
      'a.'.repeat(50_000),
      '1 '.repeat(50_000),
      '1111 '.repeat(20_000),
      '1'.repeat(100_000),
      `${'a'.repeat(50_000)}@`,
    ];
    const start = performance.now();
    for (const i of inputs) redact(i);
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it('never leaves the original sensitive values in the output', () => {
    const secrets = ['john@example.com', '4111111111111111', '123-45-6789', '987654321'];
    const text = out(`x ${secrets.join(' | ')} y`);
    for (const s of secrets) expect(text).not.toContain(s);
  });
});

// ---- Security review regressions (findings 1-3) ----

describe('review #1: email forms that used to bypass or be partially redacted', () => {
  it.each([
    ['non-ASCII local part', 'mail josé@example.com now', `mail ${EMAIL} now`],
    ['CJK local part', '联系 王小明@example.com', `联系 ${EMAIL}`],
    ['IDN domain', 'mail john@exämple.com now', `mail ${EMAIL} now`],
    ['punycode TLD', 'john@example.xn--p1ai', EMAIL],
    ['IPv4 literal domain', 'mail john@[192.168.0.1] now', `mail ${EMAIL} now`],
    ['IPv6 literal domain', 'john@[IPv6:2001:db8::1]', EMAIL],
    ['ideographic full stop', 'mail john@example。com now', `mail ${EMAIL} now`],
    ['half-width ideographic full stop', 'john@example｡com', EMAIL],
    ['full-width full stop', 'john@example．com', EMAIL],
    ["apostrophe local part", "mail o'brien@example.com now", `mail ${EMAIL} now`],
    ['special atext characters', 'mail a!b#c$d%e&f*g/h=i?j^k`l{m|n}o~p@example.com now', `mail ${EMAIL} now`],
  ])('%s', (_label, input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('never leaves a prefix of the local part behind', () => {
    for (const local of ["o'brien", 'a!b#c', 'josé', 'x+y', 'a_b-c.d']) {
      const text = out(`hello ${local}@example.com bye`);
      expect(text).toBe(`hello ${EMAIL} bye`);
    }
  });

  it('still leaves non-emails alone', () => {
    const text = 'meet @ noon, user@localhost, foo@bar, @handle, 5@6';
    expect(out(text)).toBe(text);
  });
});

describe('review #2: card and SSN separator bypasses', () => {
  it.each([
    ['4111.1111.1111.1111', CARD],
    ['4111/1111/1111/1111', CARD],
    ['4111\n1111\n1111\n1111', CARD],
    ['4111\t1111\t1111\t1111', CARD],
    ['4111  1111  1111  1111', CARD],
    ['3782.822463.10005', CARD],
    ['123.45.6789', SSN],
    ['123/45/6789', SSN],
    ['123  45  6789', SSN],
    ['123\n45\n6789', SSN],
  ])('%j', (input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('still requires one consistent separator for SSNs', () => {
    for (const text of ['123-45.6789', '123.45 6789', '123-45/6789']) expect(out(text)).toBe(text);
  });

  it('does not over-redact common dotted/slashed non-PII numbers', () => {
    for (const text of ['192.168.100.200', 'version 1.2.3.4', '10/12/2024', '3.14159265', '1.2.3', 'v10.20.30']) {
      expect(out(text)).toBe(text);
    }
  });
});

describe('review #3: non-ASCII decimal digits', () => {
  it.each([
    ['Arabic-Indic SSN', 'ssn ١٢٣-٤٥-٦٧٨٩', `ssn ${SSN}`],
    ['Arabic-Indic 9 digits', 'ssn ١٢٣٤٥٦٧٨٩', `ssn ${SSN}`],
    ['Extended Arabic-Indic', '۱۲۳۴۵۶۷۸۹', SSN],
    ['Devanagari', '१२३-४५-६७८९', SSN],
    ['Thai', '๑๒๓๔๕๖๗๘๙', SSN],
    ['Bengali card', '৪১১১ ১১১১ ১১১১ ১১১১', CARD],
    ['mathematical bold digits', '𝟒𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏𝟏', CARD],
    ['mixed ASCII + Arabic-Indic', '4111 ١١١١ 1111 ١١١١', CARD],
  ])('%s', (_label, input, expected) => {
    expect(out(input)).toBe(expected);
  });

  it('keeps surrounding non-ASCII text untouched', () => {
    expect(out('الرقم ١٢٣٤٥٦٧٨٩ شكرا')).toBe(`الرقم ${SSN} شكرا`);
  });
});

describe('review: performance of the widened patterns on max-size input', () => {
  it('stays fast', () => {
    const inputs = [
      'é'.repeat(4000),
      "a'".repeat(2000),
      '/'.repeat(4000),
      '.'.repeat(4000),
      '1.'.repeat(2000),
      '1/'.repeat(2000),
      `${'a'.repeat(2000)}@${'b.'.repeat(1000)}`,
      '\n'.repeat(4000),
      '١'.repeat(4000),
      ('1111 ' + '\n').repeat(700),
      'a@'.repeat(2000),
    ];
    const start = performance.now();
    for (const i of inputs) redact(i);
    expect(performance.now() - start).toBeLessThan(1500);
  });
});
