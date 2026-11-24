import { computeCiphertextHash } from './canonical.js';
import { verifyEd25519Browser } from './browserCrypto.js';
import { checkOrPinKeyTofu, getPinnedKey } from './pinning.js';
import type {
  KeyLogEntry,
  ProvenanceEnvelopeV1,
  ProvenanceKeyRecord,
  ProvenanceVerificationReport,
} from './types.js';
import { verifyProvenanceEnvelope } from './verifyPolicy.js';
import { safeReadJson } from '../http/safeJson.js';
import {
  DEFAULT_WEIGHTS,
  DEFAULT_BIAS,
  computeAgeFactor,
  fromLegacyPriority,
  scoreNotification,
} from '../priority/math.js';
import type {
  FeatureVector,
  PriorityScoreBreakdown,
  SigmoidPriorityLabel,
  WeightVector,
} from '../priority/types.js';

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const CACHE_TTL_MS = 15_000;
const userKeysCache = new Map<string, CacheEntry<ProvenanceKeyRecord[]>>();
let keyLogCache: CacheEntry<KeyLogEntry[]> | null = null;
let serverKeyCache: CacheEntry<ProvenanceKeyRecord | null> | null = null;

export function invalidateClientProvenanceCaches(userId?: string): void {
  if (userId) {
    userKeysCache.delete(userId);
  } else {
    userKeysCache.clear();
  }
  keyLogCache = null;
  serverKeyCache = null;
}

async function fetchServerKeyRecord(): Promise<ProvenanceKeyRecord | null> {
  const now = Date.now();
  if (serverKeyCache && serverKeyCache.expiresAt > now) {
    return serverKeyCache.value;
  }
  try {
    const res = await fetch('/api/v1/provenance/server-key');
    const data = await safeReadJson(res);
    if (res.ok && data?.success && data?.data?.kid && data?.data?.publicKey) {
      const rec: ProvenanceKeyRecord = {
        kid: data.data.kid,
        userId: 'aegis-server-gateway',
        publicKey: data.data.publicKey,
        fingerprintHex: data.data.fingerprintHex || '',
        fingerprintWords: Array.isArray(data.data.fingerprintWords) ? data.data.fingerprintWords : [],
        status: 'ACTIVE',
        createdAt: data.data.validFrom || new Date().toISOString(),
      };
      serverKeyCache = { value: rec, expiresAt: now + CACHE_TTL_MS };
      return rec;
    }
  } catch {
    // non-fatal
  }
  return null;
}

async function fetchKeysForUser(userId: string): Promise<ProvenanceKeyRecord[]> {
  if (!userId) return [];
  if (userId === 'aegis-server-gateway') {
    const sk = await fetchServerKeyRecord();
    return sk ? [sk] : [];
  }

  const now = Date.now();
  const cached = userKeysCache.get(userId);
  if (cached && cached.expiresAt > now) {
    return cached.value;
  }

  const token =
    typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
  if (!token) return [];

  try {
    const res = await fetch(`/api/v1/provenance/keys/${encodeURIComponent(userId)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await safeReadJson(res);
    if (res.ok && data?.success && Array.isArray(data?.data?.keys)) {
      const keys = data.data.keys as ProvenanceKeyRecord[];
      userKeysCache.set(userId, { value: keys, expiresAt: now + CACHE_TTL_MS });
      return keys;
    }
  } catch {
    // non-fatal
  }
  return [];
}

async function fetchKeyLogEntries(): Promise<KeyLogEntry[]> {
  const now = Date.now();
  if (keyLogCache && keyLogCache.expiresAt > now) {
    return keyLogCache.value;
  }
  try {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    const res = await fetch('/api/v1/provenance/keylog?limit=200', {
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });
    const data = await safeReadJson(res);
    if (res.ok && data?.success && Array.isArray(data?.data?.entries)) {
      const entries = data.data.entries as KeyLogEntry[];
      keyLogCache = { value: entries, expiresAt: now + CACHE_TTL_MS };
      return entries;
    }
  } catch {
    // non-fatal
  }
  return [];
}

export async function verifyItemProvenanceOnClient(params: {
  envelope?: ProvenanceEnvelopeV1 | null;
  serverReport?: ProvenanceVerificationReport | null;
  expectedRecipientId?: string;
  expectedMessageId?: string;
  expectedCiphertext?: string;
  expectedIv?: string;
  expectedDigestInput?: string;
  itemTimestamp?: string;
}): Promise<ProvenanceVerificationReport> {
  const envelope = params.envelope || params.serverReport?.envelope || null;

  if (!envelope) {
    if (params.serverReport) {
      return params.serverReport;
    }
    return {
      status: 'UNSIGNED',
      verified: false,
      reason: 'Notification carries no Ed25519 provenance envelope.',
      alg: 'NONE',
      badgeVariant: 'unverified',
      chain: [],
    };
  }

  const signerIds = new Set<string>([
    envelope.payload.senderId,
    ...envelope.chain.map((hop) => hop.signerId),
  ]);

  const [keyLogEntries, serverKey, ...userKeyLists] = await Promise.all([
    fetchKeyLogEntries(),
    fetchServerKeyRecord(),
    ...Array.from(signerIds).map((uid) => fetchKeysForUser(uid)),
  ]);

  const byKid = new Map<string, ProvenanceKeyRecord>();
  if (serverKey) {
    byKid.set(serverKey.kid, serverKey);
  }
  for (const list of userKeyLists) {
    for (const k of list) {
      byKid.set(k.kid, k);
    }
  }

  const originSignerId = envelope.chain[0]?.signerId || envelope.payload.senderId;
  const pinnedKey =
    originSignerId && originSignerId !== 'aegis-server-gateway'
      ? await getPinnedKey(originSignerId)
      : null;

  const expectedCiphertextHash =
    typeof params.expectedDigestInput === 'string' && !params.expectedCiphertext
      ? await computeCiphertextHash(params.expectedDigestInput, params.expectedIv || '')
      : undefined;

  // Always check real wall-clock expiration against envelope.payload.expiresAt
  if (envelope.payload.expiresAt) {
    const expMs = Date.parse(envelope.payload.expiresAt);
    if (Number.isNaN(expMs) || Date.now() >= expMs) {
      return {
        status: 'EXPIRED_ENVELOPE',
        verified: false,
        reason: `Provenance envelope expired at ${envelope.payload.expiresAt}.`,
        alg: 'Ed25519',
        kid: envelope.payload.kid,
        signerId: envelope.payload.senderId,
        source: envelope.payload.source,
        badgeVariant: 'rejected',
        createdAt: envelope.payload.createdAt,
        chain: [],
        envelope,
      };
    }
  }

  // For older historical items loaded from storage (already accepted earlier), anchor verification nowMs to itemTimestamp
  // while keeping live items anchored to Date.now().
  let evalNowMs = Date.now();
  if (params.itemTimestamp) {
    const tsMs = Date.parse(params.itemTimestamp);
    if (
      Number.isFinite(tsMs) &&
      Math.abs(evalNowMs - tsMs) > 4.5 * 60 * 1000 &&
      params.serverReport?.verified
    ) {
      evalNowMs = tsMs;
    }
  }

  const report = await verifyProvenanceEnvelope({
    envelope,
    expectedRecipientId: params.expectedRecipientId,
    expectedMessageId: params.expectedMessageId,
    expectedCiphertext: params.expectedCiphertext,
    expectedIv: params.expectedIv,
    expectedCiphertextHash,
    nowMs: evalNowMs,
    enforceReplay: false, // client re-verifies existing messages without consuming server nonce window
    keyLookup: (kid) => byKid.get(kid) || null,
    verifyEd25519: verifyEd25519Browser,
    pinnedKey,
    keyLogEntries,
  });

  if (report.verified && originSignerId && originSignerId !== 'aegis-server-gateway') {
    const primaryKey = byKid.get(envelope.payload.kid);
    if (primaryKey) {
      const tofu = await checkOrPinKeyTofu({
        userId: originSignerId,
        kid: primaryKey.kid,
        publicKey: primaryKey.publicKey,
        fingerprintHex: primaryKey.fingerprintHex,
        keyLogEntries,
      });
      if (!tofu.ok) {
        return {
          ...report,
          status: 'KEY_MISMATCH',
          verified: false,
          badgeVariant: 'rejected',
          reason: tofu.reason || 'TOFU key pin mismatch detected on recipient device.',
        };
      }
    }
  }

  return report;
}

const RECIPIENT_PRIORITY_ORDER: SigmoidPriorityLabel[] = ['LOW', 'NORMAL', 'HIGH', 'CRITICAL'];

/**
 * Re-scores a notification locally on the recipient's device after provenance verification:
 * - Uses ONLY verified signed textScore (when present) or base feature vector
 * - Recomputes only ageFactor and userContext/userAffinity locally
 * - Never trusts unverified priority boosts above signedPriorityCeiling + 1 level
 */
export function rescorePriorityOnRecipientDevice(params: {
  baseFeatures: FeatureVector;
  provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
  provenanceVerified?: boolean;
  elapsedSeconds: number;
  isAcked: boolean;
  userContext?: number;
  userAffinity?: number;
  previousLabel?: SigmoidPriorityLabel;
  weights?: WeightVector;
  bias?: number;
}): PriorityScoreBreakdown {
  const envPayload = params.provenanceEnvelope?.payload;
  const verifiedTextScore =
    params.provenanceVerified && typeof envPayload?.textScore === 'number'
      ? envPayload.textScore
      : params.baseFeatures.textScore;

  const updatedFeatures: FeatureVector = {
    ...params.baseFeatures,
    textScore: verifiedTextScore,
    ageFactor: computeAgeFactor(params.elapsedSeconds, params.isAcked),
    ...(typeof params.userContext === 'number' ? { userContext: params.userContext } : {}),
    ...(typeof params.userAffinity === 'number' ? { userAffinity: params.userAffinity } : {}),
  };

  const breakdown = scoreNotification({
    features: updatedFeatures,
    weights: params.weights ?? DEFAULT_WEIGHTS,
    bias: params.bias ?? DEFAULT_BIAS,
    elapsedSeconds: params.elapsedSeconds,
    isAcked: params.isAcked,
    previousLabel: params.previousLabel,
  });

  if (envPayload?.signedPriorityLabel) {
    const signedLabel = fromLegacyPriority(envPayload.signedPriorityLabel);
    const maxIdx = Math.min(
      RECIPIENT_PRIORITY_ORDER.length - 1,
      RECIPIENT_PRIORITY_ORDER.indexOf(signedLabel) + 1
    );
    const computedIdx = RECIPIENT_PRIORITY_ORDER.indexOf(breakdown.label);
    if (computedIdx > maxIdx) {
      breakdown.label = RECIPIENT_PRIORITY_ORDER[maxIdx];
    }
  }

  return breakdown;
}

