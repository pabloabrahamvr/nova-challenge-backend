/**
 * PII redactor. Pure and synchronous: no I/O, no logging.
 *
 * Order matters:
 *   1. EMAIL        - first, so digits inside an address are never read as a card/SSN.
 *   2. CREDIT_CARD  - 13-19 digits; must run before the generic 9-digit rule.
 *   3. SSN          - ddd-dd-dddd (or spaces) and any standalone 9-digit run.
 * Placeholders contain no digits, so later passes cannot re-match earlier output.
 *
 * Design choice: fail safe. We over-redact rather than under-redact, so there is
 * no Luhn check and no SSN area-number validation (see README for known false positives).
 */

export type RedactionType = 'EMAIL' | 'CREDIT_CARD' | 'SSN';

export interface RedactionResult {
  /** Redacted text. Note: this is the NFKC-normalized form of the input. */
  text: string;
  counts: Record<RedactionType, number>;
}

// Dash-like separators seen in the wild: hyphen, U+2010-2015, minus sign. Space covers NBSP after NFKC.
const SEP = '[ \\-\\u2010-\\u2015\\u2212]';

// Lookbehind anchors the match at the start of a character run, which keeps the
// scan linear (no O(n^2) rescans of a long run of local-part characters).
const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g;

// 13-19 digits, optionally separated by single spaces/dashes. Bounded repetition, no nesting.
const CARD_RE = new RegExp(`(?<!\\d)\\d(?:${SEP}?\\d){12,18}(?!\\d)`, 'g');

// ddd-dd-dddd with a consistent separator, or exactly 9 digits not part of a longer run.
const SSN_RE = new RegExp(`(?<!\\d)(?:\\d{3}(${SEP})\\d{2}\\1\\d{4}|\\d{9})(?!\\d)`, 'g');

// Soft hyphen, zero-width space/joiners, word joiner, BOM: invisible chars used to split digits.
const INVISIBLE_RE = /[­​-‍⁠﻿]/g;

const placeholder = (type: RedactionType): string => `<REDACTED: ${type}>`;

export function redact(input: string): RedactionResult {
  const counts: Record<RedactionType, number> = { EMAIL: 0, CREDIT_CARD: 0, SSN: 0 };

  const sub = (text: string, re: RegExp, type: RedactionType): string =>
    text.replace(re, () => {
      counts[type] += 1;
      return placeholder(type);
    });

  // NFKC folds full-width digits/@ and NBSP to ASCII so they cannot dodge the patterns.
  let text = input.normalize('NFKC').replace(INVISIBLE_RE, '');
  text = sub(text, EMAIL_RE, 'EMAIL');
  text = sub(text, CARD_RE, 'CREDIT_CARD');
  text = sub(text, SSN_RE, 'SSN');

  return { text, counts };
}
