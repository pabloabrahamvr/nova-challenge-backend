/**
 * PII redactor. Pure and synchronous: no I/O, no logging.
 *
 * Matching is done on a normalized view of the text (NFKC, invisible characters removed,
 * non-ASCII decimal digits mapped to ASCII, ideographic full stops mapped to '.') so
 * full-width digits, Arabic-Indic digits or zero-width splitters cannot dodge the patterns. Matches are then
 * mapped back to the ORIGINAL string, so only the sensitive spans change and all unrelated
 * content is returned byte-for-byte.
 *
 * Overlap handling: candidates are claimed in priority order, and a lower-priority candidate
 * that touches an already-claimed character is dropped entirely (never partially redacted):
 *   1. EMAIL        - so digits inside an address are never read as a card or SSN.
 *   2. CREDIT_CARD  - 13-19 digits, Luhn-valid; beats the generic 9-digit rule when they overlap.
 *   3. SSN          - ddd-dd-dddd (consistent separator) or a standalone 9-digit run.
 */

export type RedactionType = 'EMAIL' | 'CREDIT_CARD' | 'SSN';

export interface RedactionResult {
  text: string;
  counts: Record<RedactionType, number>;
}

interface Span {
  start: number;
  end: number; // exclusive
}

// Separators between digit groups: any whitespace (incl. newlines, NBSP), '.', '-', '/', and the
// U+2010-2015 dashes / minus sign. Up to two in a row ("4111  1111").
const SEP = '[\\s.\\-/\\u2010-\\u2015\\u2212]';

// Email: RFC 5322 "atext" plus Unicode letters/digits in the local part (RFC 6531), IDN domains and
// IP-literal domains. The lookbehind anchors a match at the start of a local-part run, which keeps
// scanning linear AND guarantees we never redact only the tail of a local part.
const LOCAL = "[\\p{L}\\p{N}._%+\\-!#$&'*/=?^`{|}~]";
const EMAIL_RE = new RegExp(
  `(?<!${LOCAL})${LOCAL}+@(?:(?:[\\p{L}\\p{N}-]+\\.)+[\\p{L}\\p{N}-]{2,}|\\[[A-Za-z0-9:.]{2,}\\])`,
  'gu',
);
// Digit groups joined by 1-2 separators. Unambiguous (separators are never digits), so linear.
const DIGIT_RUN_RE = new RegExp(`\\d+(?:${SEP}{1,2}\\d+)*`, 'g');
// ddd-dd-dddd with one consistent separator, or exactly 9 digits that are not part of a longer run.
const SSN_RE = new RegExp(`(?<!\\d)(?:\\d{3}(${SEP}{1,2})\\d{2}\\1\\d{4}|\\d{9})(?!\\d)`, 'g');

// Soft hyphen, zero-width space/joiners, word joiner, BOM.
const INVISIBLE_RE = /^[­​-‍⁠﻿]$/;

const CARD_MIN_DIGITS = 13;
const CARD_MAX_DIGITS = 19;
const CARD_MIN_GROUP = 4; // every digit group except the last must have at least 4 digits

export function luhnValid(digits: string): boolean {
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

const DECIMAL_DIGIT_RE = /^\p{Nd}$/u;
const isDecimalDigit = (cp: number): boolean => cp >= 0 && DECIMAL_DIGIT_RE.test(String.fromCodePoint(cp));

/** Value of a non-ASCII decimal digit. Unicode lays Nd digits out in aligned runs of ten starting at zero. */
function digitValue(cp: number): number {
  let start = cp;
  while (isDecimalDigit(start - 1)) start--;
  return (cp - start) % 10;
}

/** Fold one character to the form the patterns expect. */
function foldChar(ch: string): string {
  const cp = ch.codePointAt(0)!;
  if (cp < 0x80) return ch;
  if (ch === '\u3002' || ch === '\uFF61') return '.'; // ideographic full stops
  if (isDecimalDigit(cp)) return String(digitValue(cp)); // Arabic-Indic, Devanagari, Thai, math digits...
  return ch.normalize('NFKC');
}

/** Fold per character and remember where each folded unit came from in the original string. */
function normalizeWithMap(input: string): { norm: string; origStart: number[]; origEnd: number[] } {
  let norm = '';
  const origStart: number[] = [];
  const origEnd: number[] = [];
  let pos = 0;
  for (const ch of input) {
    const end = pos + ch.length;
    if (!INVISIBLE_RE.test(ch)) {
      const n = foldChar(ch);
      norm += n;
      for (let k = 0; k < n.length; k++) {
        origStart.push(pos);
        origEnd.push(end);
      }
    }
    pos = end;
  }
  return { norm, origStart, origEnd };
}

function findEmails(norm: string): Span[] {
  return [...norm.matchAll(EMAIL_RE)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
}

/**
 * A card is a window of whole digit groups holding 13-19 digits that passes Luhn.
 * Windows never start or end inside a group, so a number embedded in a longer digit run is left alone.
 * When a window fails Luhn we slide, so a valid card next to unrelated digits is still found.
 *
 * Groups that are part of an SSN-shaped token (ddd-dd-dddd or a standalone 9-digit run) are barriers:
 * a window may not start on, or extend across, one. Without this, "123-45-6789 4111 1111 1111 1111"
 * could produce a Luhn-valid window like "6789 4111 1111 1111", leaving the SSN prefix and the
 * card's last digits exposed. No real card layout contains such a group.
 */
function findCards(norm: string, ssnMask: Uint8Array): Span[] {
  const isBarrier = (g: Span): boolean => {
    for (let k = g.start; k < g.end; k++) if (ssnMask[k]) return true;
    return false;
  };
  const spans: Span[] = [];
  for (const run of norm.matchAll(DIGIT_RUN_RE)) {
    if (run[0].length < CARD_MIN_DIGITS) continue;
    const groups = [...run[0].matchAll(/\d+/g)].map((g) => ({
      start: run.index + g.index,
      end: run.index + g.index + g[0].length,
    }));

    let i = 0;
    while (i < groups.length) {
      if (isBarrier(groups[i]!)) {
        i++;
        continue;
      }
      let digits = '';
      let best = -1;
      for (let j = i; j < groups.length; j++) {
        const g = groups[j]!;
        if (isBarrier(g)) break;
        if (j > i) {
          const prev = groups[j - 1]!;
          if (prev.end - prev.start < CARD_MIN_GROUP) break; // prev is no longer the last group
        }
        digits += norm.slice(g.start, g.end);
        if (digits.length > CARD_MAX_DIGITS) break;
        if (digits.length >= CARD_MIN_DIGITS && luhnValid(digits)) best = j; // keep the longest
      }
      if (best >= 0) {
        spans.push({ start: groups[i]!.start, end: groups[best]!.end });
        i = best + 1;
      } else {
        i++;
      }
    }
  }
  return spans;
}

function findSsns(norm: string): Span[] {
  return [...norm.matchAll(SSN_RE)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
}

export function redact(input: string): RedactionResult {
  const counts: Record<RedactionType, number> = { EMAIL: 0, CREDIT_CARD: 0, SSN: 0 };
  if (input === '') return { text: '', counts };

  const { norm, origStart, origEnd } = normalizeWithMap(input);
  const claimed = new Uint8Array(norm.length);
  const accepted: Array<Span & { type: RedactionType }> = [];

  const claim = (type: RedactionType, spans: Span[]): void => {
    for (const s of spans) {
      let free = true;
      for (let k = s.start; k < s.end; k++) {
        if (claimed[k]) {
          free = false;
          break;
        }
      }
      if (!free) continue; // drop whole candidate: never redact half of an overlap
      claimed.fill(1, s.start, s.end);
      accepted.push({ ...s, type });
    }
  };

  const ssns = findSsns(norm);
  const ssnMask = new Uint8Array(norm.length);
  for (const s of ssns) ssnMask.fill(1, s.start, s.end);

  claim('EMAIL', findEmails(norm));
  claim('CREDIT_CARD', findCards(norm, ssnMask));
  claim('SSN', ssns);

  accepted.sort((a, b) => a.start - b.start);

  let out = '';
  let cursor = 0;
  for (const s of accepted) {
    const from = Math.max(origStart[s.start]!, cursor); // clamp: one char may expand into several
    const to = origEnd[s.end - 1]!;
    if (to <= cursor) continue;
    out += input.slice(cursor, from) + `<REDACTED: ${s.type}>`;
    cursor = to;
    counts[s.type] += 1;
  }
  return { text: out + input.slice(cursor), counts };
}
