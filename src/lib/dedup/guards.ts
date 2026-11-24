import { DEFAULT_DEDUP_CONFIG } from './config.js';
import type {
  DedupIncomingMetadataInput,
  DedupProvenanceTrust,
  DedupThreadMetadata,
  ExtractedEntities,
  GuardCheckDetail,
  GuardName,
} from './types.js';

const CURRENCY_NUMBER_REGEX =
  /\b(?:(?:rs\.?|inr|usd|eur|gbp|\$|₹|€|£)\s*\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s*(?:%|percent|ms|s|sec|seconds|min|minutes|hrs|hours|gb|mb|kb))\b/gi;
const STANDALONE_BIG_NUM_REGEX = /\b\d[\d,]{2,}(?:\.\d+)?\b/g;
const GUARDRAIL_NUMBER_REGEX = new RegExp(
  DEFAULT_DEDUP_CONFIG.guardrails?.numberRegex || '\\d+(?:[.,]\\d+)?',
  'g'
);
const CODE_OR_ID_REGEX =
  /(?:#?[A-Z]{2,10}-\d{1,10}\b|\b\d{4,8}\b|\b\d{3}-\d{3}\b|\b(?:id|ord|inv|txn|ref|ticket)[:#=\s-]*[a-z0-9_-]{3,24}\b)/gi;
const URL_REGEX = /\bhttps?:\/\/[^\s/$.?#].[^\s]*|\b(?:[a-z0-9-]+\.)+(?:io|com|org|net|in|dev|app|ai)\b/gi;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi;
const PHONE_REGEX = /\b(?:\+?\d{1,3}[\s-]?)?(?:\d[\s-]?){9,12}\b/g;
const DATE_TIME_REGEX =
  /\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}|\d{1,2}:\d{2}(?::\d{2})?(?:\s*(?:am|pm|utc|ist))?)\b/gi;

const DOWN_OR_FAILURE_WORDS = new Set([
  'down',
  'outage',
  'unreachable',
  'failed',
  'fail',
  'failure',
  'blocked',
  'denied',
  'stopped',
  'crashed',
  'crashloopbackoff',
  'offline',
  'degraded',
  'timeout',
  'band',
  'rejected',
  'expired',
  'cancelled',
]);

const UP_OR_RECOVERED_WORDS = new Set([
  'up',
  'recovered',
  'resolved',
  'restored',
  'healthy',
  'succeeded',
  'success',
  'successful',
  'completed',
  'allowed',
  'resumed',
  'online',
  'chalu',
  'thik',
  'fixed',
  'passed',
  'unblocked',
  'approved',
  'confirmed',
]);

const CRITICAL_SECURITY_REGEX =
  /\b(otp|one[- ]time|verification code|2fa|mfa|password reset|new device|unauthorized|breach|compromised|key rotated|key revoked|provenance failed|pin mismatch)\b/i;

function normalizeTokenSet(matches: string[] | null, stripCommas = false): string[] {
  if (!matches || matches.length === 0) return [];
  const out = new Set<string>();
  for (const m of matches) {
    let clean = m.trim().toLowerCase().replace(/\s+/g, '');
    if (stripCommas) clean = clean.replace(/,/g, '');
    if (clean) out.add(clean);
  }
  return Array.from(out).sort();
}

export function extractEntities(rawText: string): ExtractedEntities {
  const text = String(rawText || '');
  const currencies = normalizeTokenSet(text.match(CURRENCY_NUMBER_REGEX), true);
  const bigNums = normalizeTokenSet(text.match(STANDALONE_BIG_NUM_REGEX), true);
  const guardrailNums = DEFAULT_DEDUP_CONFIG.guardrails?.blockIfNumbersDiffer
    ? normalizeTokenSet(text.match(GUARDRAIL_NUMBER_REGEX), true)
    : [];
  const currenciesAndNumbers = Array.from(
    new Set([...currencies, ...bigNums, ...guardrailNums])
  ).sort();

  const codesAndIds = normalizeTokenSet(text.match(CODE_OR_ID_REGEX), false);
  const urlsAndDomains = normalizeTokenSet(text.match(URL_REGEX), false);
  const emails = normalizeTokenSet(text.match(EMAIL_REGEX), false);
  const phoneMatches: string[] = text.match(PHONE_REGEX) || [];
  const phones = normalizeTokenSet(
    phoneMatches.filter((p: string) => p.replace(/\D/g, '').length >= 9),
    true
  );
  const datesAndTimes = normalizeTokenSet(text.match(DATE_TIME_REGEX), false);

  return {
    currenciesAndNumbers,
    codesAndIds,
    urlsAndDomains,
    emails,
    phones,
    datesAndTimes,
  };
}

function setsOverlapOrEqual(a: string[], b: string[]): boolean {
  if (a.length === 0 && b.length === 0) return true;
  if (a.length === 0 || b.length === 0) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function checkCriticalSecurityGuard(
  incoming: DedupIncomingMetadataInput,
  rawText: string,
  neverMergeCategories: string[]
): GuardCheckDetail {
  const cat = String(incoming.category || '').trim().toLowerCase();
  const isCritical = incoming.priority === 'CRITICAL';
  const isNeverMergeCategory = neverMergeCategories.includes(cat);
  const hasSecurityPattern = CRITICAL_SECURITY_REGEX.test(rawText);

  if (
    isCritical ||
    isNeverMergeCategory ||
    incoming.isOtpOrLoginOrKeyChange ||
    incoming.isPriorityFloorAlert ||
    incoming.provenanceFailed ||
    hasSecurityPattern
  ) {
    const reasons: string[] = [];
    if (isCritical) reasons.push('CRITICAL priority alert');
    if (isNeverMergeCategory) reasons.push(`never-merge category (${cat})`);
    if (incoming.isOtpOrLoginOrKeyChange || hasSecurityPattern) {
      reasons.push('OTP / login / key-change alert');
    }
    if (incoming.isPriorityFloorAlert) reasons.push('priority-engine security floor');
    if (incoming.provenanceFailed) reasons.push('provenance verification failure');

    return {
      guard: 'CRITICAL_SECURITY_EXCLUSION',
      passed: false,
      severity: 'link_only',
      reason: `Never suppressed or merged (${reasons.join(', ')}). May show non-suppressing Related link only.`,
    };
  }

  return {
    guard: 'CRITICAL_SECURITY_EXCLUSION',
    passed: true,
    reason: 'Item is not a CRITICAL/security/OTP/provenance-floor alert.',
  };
}

export function checkEntityGuard(textA: string, textB: string): GuardCheckDetail {
  const entA = extractEntities(textA);
  const entB = extractEntities(textB);

  const conflicts: string[] = [];
  if (!setsOverlapOrEqual(entA.currenciesAndNumbers, entB.currenciesAndNumbers)) {
    conflicts.push(
      `amounts/numbers (${entA.currenciesAndNumbers.join(', ')} vs ${entB.currenciesAndNumbers.join(', ')})`
    );
  }
  if (!setsOverlapOrEqual(entA.codesAndIds, entB.codesAndIds)) {
    conflicts.push(`IDs/codes (${entA.codesAndIds.join(', ')} vs ${entB.codesAndIds.join(', ')})`);
  }
  if (!setsOverlapOrEqual(entA.emails, entB.emails)) {
    conflicts.push(`emails (${entA.emails.join(', ')} vs ${entB.emails.join(', ')})`);
  }
  if (!setsOverlapOrEqual(entA.phones, entB.phones)) {
    conflicts.push('phone numbers differ');
  }
  if (!setsOverlapOrEqual(entA.urlsAndDomains, entB.urlsAndDomains)) {
    conflicts.push(
      `URLs/hosts (${entA.urlsAndDomains.join(', ')} vs ${entB.urlsAndDomains.join(', ')})`
    );
  }
  if (!setsOverlapOrEqual(entA.datesAndTimes, entB.datesAndTimes)) {
    conflicts.push(
      `dates/times (${entA.datesAndTimes.join(', ')} vs ${entB.datesAndTimes.join(', ')})`
    );
  }

  if (conflicts.length > 0) {
    return {
      guard: 'ENTITY_CONFLICT',
      passed: false,
      severity: 'block',
      reason: `Material entity mismatch detected: ${conflicts.join('; ')}.`,
    };
  }

  return {
    guard: 'ENTITY_CONFLICT',
    passed: true,
    reason: 'No conflicting numeric amounts, OTP codes, IDs, hosts, or dates found.',
  };
}

function extractWordSet(text: string): Set<string> {
  const words = String(text || '').toLowerCase().match(/[a-z0-9_]+/g) || [];
  return new Set(words);
}

function detectPolarState(words: Set<string>): { hasDown: boolean; hasUp: boolean } {
  let hasDown = false;
  let hasUp = false;
  for (const w of words) {
    if (DOWN_OR_FAILURE_WORDS.has(w)) hasDown = true;
    if (UP_OR_RECOVERED_WORDS.has(w)) hasUp = true;
  }
  return { hasDown, hasUp };
}

export function checkNegationStateGuard(
  candidateText: string,
  existingText: string
): GuardCheckDetail & { isResolutionUpdate: boolean } {
  const incomingWords = extractWordSet(candidateText);
  const existingWords = extractWordSet(existingText);
  const incomingState = detectPolarState(incomingWords);
  const existingState = detectPolarState(existingWords);

  const downToUp = existingState.hasDown && incomingState.hasUp && !incomingState.hasDown;
  const upToDown = existingState.hasUp && incomingState.hasDown && !incomingState.hasUp;

  // Check explicit opposite_state_pairs imported from dedupConfig.json
  let matchedPair: [string, string] | null = null;
  if (DEFAULT_DEDUP_CONFIG.guardrails?.blockIfOppositeStates !== false) {
    for (const pair of DEFAULT_DEDUP_CONFIG.guardrails?.oppositeStatePairs || []) {
      const a = String(pair[0] || '').toLowerCase();
      const b = String(pair[1] || '').toLowerCase();
      if (!a || !b) continue;
      if (
        (existingWords.has(a) && incomingWords.has(b) && !incomingWords.has(a)) ||
        (existingWords.has(b) && incomingWords.has(a) && !incomingWords.has(b))
      ) {
        matchedPair = [a, b];
        break;
      }
    }
  }

  if (downToUp || upToDown || matchedPair) {
    return {
      guard: 'NEGATION_STATE_CONFLICT',
      passed: false,
      severity: 'link_only',
      isResolutionUpdate: downToUp,
      reason: matchedPair
        ? `Opposite state pair detected (${matchedPair[0]} vs ${matchedPair[1]}). Kept separate.`
        : downToUp
          ? 'Opposite operational state detected (incident -> recovered/resolved). Kept separate and linked as resolution update.'
          : 'Opposite operational state detected (healthy/success -> down/failed). Kept separate.',
    };
  }

  return {
    guard: 'NEGATION_STATE_CONFLICT',
    passed: true,
    isResolutionUpdate: false,
    reason: 'No opposing operational state or resolution negation detected.',
  };
}

const TRUST_RANK: Record<DedupProvenanceTrust, number> = {
  UNVERIFIED: 0,
  GATEWAY_ATTESTED: 1,
  VERIFIED: 2,
};

export function minProvenanceTrust(
  a: DedupProvenanceTrust,
  b: DedupProvenanceTrust
): DedupProvenanceTrust {
  return TRUST_RANK[a] <= TRUST_RANK[b] ? a : b;
}

export function checkProvenanceGuard(
  incoming: DedupIncomingMetadataInput,
  candidateThread: Pick<DedupThreadMetadata, 'senderId' | 'sourceId' | 'lowestTrust'>
): GuardCheckDetail & { combinedLowestTrust: DedupProvenanceTrust } {
  const incomingTrust = incoming.trust;
  const threadTrust = candidateThread.lowestTrust;
  const combinedLowestTrust = minProvenanceTrust(incomingTrust, threadTrust);

  // Never merge VERIFIED and UNVERIFIED messages
  if (
    (incomingTrust === 'VERIFIED' && threadTrust === 'UNVERIFIED') ||
    (incomingTrust === 'UNVERIFIED' && threadTrust === 'VERIFIED')
  ) {
    return {
      guard: 'PROVENANCE_TRUST',
      passed: false,
      severity: 'block',
      combinedLowestTrust,
      reason: 'Provenance mismatch: VERIFIED messages cannot merge with UNVERIFIED messages.',
    };
  }

  // Only merge same verified sender or same attested source
  if (incomingTrust === 'VERIFIED' || threadTrust === 'VERIFIED') {
    const sameSender =
      incoming.senderId.trim().toLowerCase() === candidateThread.senderId.trim().toLowerCase();
    const sameSource =
      incoming.sourceId.trim().toLowerCase() === candidateThread.sourceId.trim().toLowerCase();
    if (!sameSender && !sameSource) {
      return {
        guard: 'PROVENANCE_TRUST',
        passed: false,
        severity: 'block',
        combinedLowestTrust,
        reason: `Verified sender/source mismatch (${incoming.senderId}/${incoming.sourceId} vs ${candidateThread.senderId}/${candidateThread.sourceId}).`,
      };
    }
  } else {
    const sameSource =
      incoming.sourceId.trim().toLowerCase() === candidateThread.sourceId.trim().toLowerCase();
    if (!sameSource) {
      return {
        guard: 'PROVENANCE_TRUST',
        passed: false,
        severity: 'block',
        combinedLowestTrust,
        reason: `Different attested/unverified source (${incoming.sourceId} vs ${candidateThread.sourceId}).`,
      };
    }
  }

  return {
    guard: 'PROVENANCE_TRUST',
    passed: true,
    combinedLowestTrust,
    reason: `Provenance guard passed (trust=${combinedLowestTrust}).`,
  };
}

export function evaluateAllMergeGuards(params: {
  incoming: DedupIncomingMetadataInput;
  incomingText: string;
  candidateThread: DedupThreadMetadata;
  candidateLatestText: string;
  neverMergeCategories: string[];
}): {
  allowedToMerge: boolean;
  blockedByGuard: GuardName | null;
  linkRelatedOnly: boolean;
  isResolutionUpdate: boolean;
  lowestTrust: DedupProvenanceTrust;
  guards: GuardCheckDetail[];
} {
  const critGuard = checkCriticalSecurityGuard(
    params.incoming,
    params.incomingText,
    params.neverMergeCategories
  );
  const entGuard = checkEntityGuard(params.incomingText, params.candidateLatestText);
  const negGuard = checkNegationStateGuard(params.incomingText, params.candidateLatestText);
  const provGuard = checkProvenanceGuard(params.incoming, params.candidateThread);

  const guards: GuardCheckDetail[] = [critGuard, entGuard, negGuard, provGuard];
  const firstFailed = guards.find((g) => !g.passed) || null;

  return {
    allowedToMerge: firstFailed === null,
    blockedByGuard: firstFailed ? firstFailed.guard : null,
    linkRelatedOnly: Boolean(
      firstFailed && (firstFailed.guard === 'CRITICAL_SECURITY_EXCLUSION' || firstFailed.guard === 'NEGATION_STATE_CONFLICT')
    ),
    isResolutionUpdate: negGuard.isResolutionUpdate,
    lowestTrust: firstFailed ? params.incoming.trust : provGuard.combinedLowestTrust,
    guards,
  };
}
