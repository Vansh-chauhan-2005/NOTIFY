import type { DedupPreprocessResult } from './types.js';

const ZERO_WIDTH_OR_CONTROL_REGEX = /[\u200B-\u200D\uFEFF\u2060\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;
const ATTACHMENT_MARKER_REGEX = /\[(?:attachment|file|image|video|pdf)\s*:[^\]]*\]/gi;
const TOKEN_REGEX = /[\p{L}\p{N}_./:#@-]+/gu;

/**
 * Normalizes notification text purely in memory:
 * - Unicode NFKC normalization
 * - Strips zero-width and control characters
 * - Strips attachment markers (attachments are never embedded)
 * - Lowercases & collapses whitespace
 * - Supports English, Hindi (Devanagari), and Hinglish tokens capped at `maxTokens`
 */
export function preprocessNotificationText(
  rawText: string,
  maxTokens = 256
): DedupPreprocessResult {
  const input = String(rawText || '');
  const hadZeroWidthOrControl = ZERO_WIDTH_OR_CONTROL_REGEX.test(input);
  ZERO_WIDTH_OR_CONTROL_REGEX.lastIndex = 0;

  const hasLatin = /[a-zA-Z]/.test(input);
  const hasCyrillicOrGreek = /[\u0400-\u04FF\u0370-\u03FF]/.test(input);
  const hadMixedScript = hasLatin && hasCyrillicOrGreek;

  const nfkc = input.normalize('NFKC');
  const stripped = nfkc
    .replace(ZERO_WIDTH_OR_CONTROL_REGEX, '')
    .replace(ATTACHMENT_MARKER_REGEX, ' ');

  const lowerCollapsed = stripped.toLowerCase().replace(/\s+/g, ' ').trim();
  const matchedTokens = lowerCollapsed.match(TOKEN_REGEX) || [];
  const truncated = matchedTokens.length > maxTokens;
  const tokens = matchedTokens.slice(0, maxTokens);
  const normalizedText = tokens.join(' ');

  return {
    normalizedText,
    tokens,
    truncated,
    hadZeroWidthOrControl,
    hadMixedScript,
  };
}
