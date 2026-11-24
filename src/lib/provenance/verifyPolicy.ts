import {
  base64ToBytes,
  buildAttestationSigningBytes,
  buildProvenanceSigningBytes,
  computeCiphertextHash,
  computePayloadHash,
  computeSha256Hex,
  constantTimeEqualBytes,
  hexToBytes,
  isKeyValidForTimestamp,
} from './canonical.js';
import type {
  KeyLogEntry,
  PinnedKeyRecord,
  ProvenanceChainHopResult,
  ProvenanceEnvelopeV1,
  ProvenanceKeyRecord,
  ProvenanceStatus,
  ProvenanceVerificationReport,
} from './types.js';

export const PROVENANCE_CLOCK_SKEW_MS = 5 * 60 * 1000; // +-5 minutes
export const PROVENANCE_REPLAY_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

export type Ed25519VerifyFn = (
  messageBytes: Uint8Array,
  signatureBytes: Uint8Array,
  rawPublicKeyBase64: string
) => Promise<boolean> | boolean;

export type KeyLookupFn = (
  kid: string
) => Promise<ProvenanceKeyRecord | null> | ProvenanceKeyRecord | null;

export type ReplayCheckFn = (params: {
  kid: string;
  nonce: string;
  nowMs: number;
}) => Promise<{ replayed: boolean }> | { replayed: boolean };

export interface VerifyEnvelopeOptions {
  envelope?: ProvenanceEnvelopeV1 | null;
  expectedRecipientId?: string;
  expectedCiphertext?: string;
  expectedIv?: string;
  expectedCiphertextHash?: string;
  expectedMessageId?: string;
  priority?: string;
  nowMs?: number;
  enforceReplay?: boolean;
  keyLookup: KeyLookupFn;
  verifyEd25519: Ed25519VerifyFn;
  replayCheck?: ReplayCheckFn;
  pinnedKey?: PinnedKeyRecord | null;
  keyLogEntries?: KeyLogEntry[];
  domainPrefixOverride?: string;
}

/**
 * Verifies whether a new key cleanly connects to a locally TOFU-pinned key
 * via an intact server-signed ROTATE entry in the Key Transparency Log.
 */
export function verifyPinnedKeyContinuity(params: {
  pinnedKey?: PinnedKeyRecord | null;
  signerUserId: string;
  presentedKid: string;
  presentedPublicKey: string;
  keyLogEntries?: KeyLogEntry[];
}): { ok: boolean; reason?: string } {
  const { pinnedKey, signerUserId, presentedKid, presentedPublicKey, keyLogEntries } = params;
  if (!pinnedKey) return { ok: true };
  if (pinnedKey.userId !== signerUserId) return { ok: true };

  if (pinnedKey.kid === presentedKid) {
    if (pinnedKey.publicKey !== presentedPublicKey) {
      return {
        ok: false,
        reason: `Pinned public key bytes do not match registry entry for kid ${presentedKid}.`,
      };
    }
    return { ok: true };
  }

  // Key ID changed after TOFU pin: require an explicit ROTATE chain from pinnedKey.kid -> presentedKid
  if (!keyLogEntries || keyLogEntries.length === 0) {
    return {
      ok: false,
      reason: `Key substitution detected for ${signerUserId}: pinned key ${pinnedKey.kid} changed to ${presentedKid} without a verifiable ROTATE proof in KeyLog.`,
    };
  }

  let currentKid = pinnedKey.kid;
  const visited = new Set<string>([currentKid]);
  let foundTarget = false;

  // Walk forward through ROTATE entries matching userId
  for (const entry of keyLogEntries) {
    if (entry.userId !== signerUserId) continue;
    if (entry.type === 'ROTATE' && entry.previousKid === currentKid && !visited.has(entry.kid)) {
      currentKid = entry.kid;
      visited.add(currentKid);
      if (currentKid === presentedKid && entry.publicKey === presentedPublicKey) {
        foundTarget = true;
        break;
      }
    }
  }

  if (!foundTarget) {
    return {
      ok: false,
      reason: `Key substitution detected for ${signerUserId}: pinned key ${pinnedKey.kid} was replaced by ${presentedKid} without a valid chained ROTATE entry.`,
    };
  }

  return { ok: true };
}

function makeRejectedReport(params: {
  status: ProvenanceStatus;
  reason: string;
  envelope?: ProvenanceEnvelopeV1;
  chain?: ProvenanceChainHopResult[];
  kid?: string;
  signerId?: string;
  source?: string;
  fingerprintHex?: string;
  fingerprintWords?: string[];
  badgeVariant?: 'unverified' | 'rejected';
}): ProvenanceVerificationReport {
  return {
    status: params.status,
    verified: false,
    reason: params.reason,
    alg: params.envelope ? 'Ed25519' : 'NONE',
    kid: params.kid || params.envelope?.payload?.kid,
    signerId: params.signerId || params.envelope?.payload?.senderId,
    source: params.source || params.envelope?.payload?.source,
    badgeVariant:
      params.badgeVariant || (params.status === 'UNSIGNED' ? 'unverified' : 'rejected'),
    fingerprintHex: params.fingerprintHex,
    fingerprintWords: params.fingerprintWords,
    createdAt: params.envelope?.payload?.createdAt,
    chain: params.chain || [],
    envelope: params.envelope,
  };
}

/**
 * Zero-Trust Deny-by-Default Envelope Verification Policy:
 * Verifies every requirement strictly before returning VERIFIED:
 *  1) Envelope presence & structure (UNSIGNED if absent)
 *  2) Target recipient & messageId binding (TARGET_MISMATCH)
 *  3) Ciphertext hash binding if ciphertext/iv supplied (INVALID_SIGNATURE)
 *  4) Expiry & clock skew +-5m (EXPIRED_ENVELOPE, CLOCK_SKEW)
 *  5) Replay cache `(kid, nonce)` within 10 minutes (REPLAY)
 *  6) Chain completeness, parentHash linkage, key existence/revocation/rotation, & TOFU pinning
 *  7) Ed25519 cryptographic verification of origin payload + every hop signature
 */
export async function verifyProvenanceEnvelope(
  options: VerifyEnvelopeOptions
): Promise<ProvenanceVerificationReport> {
  const { envelope } = options;
  const nowMs = options.nowMs ?? Date.now();

  if (!envelope || !envelope.payload || !Array.isArray(envelope.chain)) {
    return makeRejectedReport({
      status: 'UNSIGNED',
      reason: 'Notification carries no Ed25519 provenance envelope.',
      badgeVariant: 'unverified',
    });
  }

  if (envelope.v !== 1 || envelope.payload.v !== 1 || envelope.payload.alg !== 'Ed25519') {
    return makeRejectedReport({
      status: 'BAD_CHAIN',
      reason: 'Unsupported provenance envelope version or signature algorithm.',
      envelope,
    });
  }

  const p = envelope.payload;

  if (
    !p.kid ||
    !p.messageId ||
    !p.senderId ||
    !p.recipientId ||
    !p.createdAt ||
    !p.nonce ||
    !p.ciphertextHash ||
    envelope.chain.length === 0
  ) {
    return makeRejectedReport({
      status: 'BAD_CHAIN',
      reason: 'Provenance envelope is missing mandatory fields or attestation chain hops.',
      envelope,
    });
  }

  // 1. Target binding check (prevent cross-recipient / cross-message envelope transplantation)
  if (options.expectedRecipientId && p.recipientId !== options.expectedRecipientId) {
    return makeRejectedReport({
      status: 'TARGET_MISMATCH',
      reason: `Provenance recipient "${p.recipientId}" does not match expected recipient "${options.expectedRecipientId}".`,
      envelope,
    });
  }

  if (options.expectedMessageId && p.messageId !== options.expectedMessageId) {
    return makeRejectedReport({
      status: 'TARGET_MISMATCH',
      reason: `Provenance messageId "${p.messageId}" does not match item ID "${options.expectedMessageId}".`,
      envelope,
    });
  }

  // 2. Ciphertext digest integrity check
  if (typeof options.expectedCiphertext === 'string') {
    const computedHash = await computeCiphertextHash(
      options.expectedCiphertext,
      options.expectedIv || ''
    );
    try {
      if (!constantTimeEqualBytes(hexToBytes(computedHash), hexToBytes(p.ciphertextHash))) {
        return makeRejectedReport({
          status: 'INVALID_SIGNATURE',
          reason: 'Ciphertext digest mismatch: payload content changed after signing.',
          envelope,
        });
      }
    } catch {
      return makeRejectedReport({
        status: 'INVALID_SIGNATURE',
        reason: 'Malformed ciphertextHash digest in provenance envelope.',
        envelope,
      });
    }
  } else if (options.expectedCiphertextHash) {
    try {
      if (
        !constantTimeEqualBytes(
          hexToBytes(options.expectedCiphertextHash),
          hexToBytes(p.ciphertextHash)
        )
      ) {
        return makeRejectedReport({
          status: 'INVALID_SIGNATURE',
          reason: 'Payload hash mismatch against envelope ciphertextHash.',
          envelope,
        });
      }
    } catch {
      return makeRejectedReport({
        status: 'INVALID_SIGNATURE',
        reason: 'Malformed ciphertextHash digest.',
        envelope,
      });
    }
  }

  // 3. Expiration check (explicit expiresAt or TTL)
  if (p.expiresAt) {
    const expMs = Date.parse(p.expiresAt);
    if (Number.isNaN(expMs) || nowMs >= expMs) {
      return makeRejectedReport({
        status: 'EXPIRED_ENVELOPE',
        reason: `Provenance envelope expired at ${p.expiresAt}.`,
        envelope,
      });
    }
  }

  // 4. Clock skew +-5 minutes check
  const createdAtMs = Date.parse(p.createdAt);
  if (Number.isNaN(createdAtMs)) {
    return makeRejectedReport({
      status: 'CLOCK_SKEW',
      reason: 'Invalid UTC createdAt timestamp in provenance envelope.',
      envelope,
    });
  }

  if (Math.abs(nowMs - createdAtMs) > PROVENANCE_CLOCK_SKEW_MS) {
    const diffSec = Math.round((nowMs - createdAtMs) / 1000);
    return makeRejectedReport({
      status: 'CLOCK_SKEW',
      reason: `Provenance timestamp outside +-5 minute acceptance window (skew=${diffSec}s).`,
      envelope,
    });
  }

  // 5. Chain structure & cryptographic verification across every hop
  const chainResults: ProvenanceChainHopResult[] = [];
  const expectedPayloadHash = await computePayloadHash(p);
  let previousSigDigest = expectedPayloadHash;
  let primaryKeyRecord: ProvenanceKeyRecord | null = null;

  for (let i = 0; i < envelope.chain.length; i += 1) {
    const hop = envelope.chain[i];
    if (!hop || hop.alg !== 'Ed25519' || !hop.kid || !hop.sig || !hop.signerId) {
      return makeRejectedReport({
        status: 'BAD_CHAIN',
        reason: `Attestation hop #${i + 1} is incomplete or uses unsupported algorithm.`,
        envelope,
        chain: chainResults,
      });
    }

    if (i === 0) {
      // Hop 0 signs canonical payload and binds kid & parentHash == expectedPayloadHash
      if (hop.kid !== p.kid) {
        return makeRejectedReport({
          status: 'BAD_CHAIN',
          reason: `First attestation kid (${hop.kid}) does not match envelope payload kid (${p.kid}).`,
          envelope,
          chain: chainResults,
        });
      }
      if (hop.parentHash !== expectedPayloadHash) {
        return makeRejectedReport({
          status: 'BAD_CHAIN',
          reason: `Origin parentHash does not bind cleanly to canonical payload digest.`,
          envelope,
          chain: chainResults,
        });
      }
    } else {
      // Subsequent hops must link parentHash == SHA-256(previous hop signature)
      if (hop.parentHash !== previousSigDigest) {
        return makeRejectedReport({
          status: 'BAD_CHAIN',
          reason: `Attestation chain break at hop #${i + 1} (${hop.role}): parentHash mismatch.`,
          envelope,
          chain: chainResults,
        });
      }
    }

    const keyRecord = await options.keyLookup(hop.kid);
    if (!keyRecord) {
      return makeRejectedReport({
        status: 'UNKNOWN_KEY',
        reason: `Signing key "${hop.kid}" for signer "${hop.signerId}" is not registered.`,
        envelope,
        chain: chainResults,
      });
    }

    if (i === 0) {
      primaryKeyRecord = keyRecord;
    }

    // Check signer identity ownership of the key (gateway allowed when role === GATEWAY)
    if (
      hop.role === 'ORIGIN' &&
      hop.signerId !== keyRecord.userId &&
      keyRecord.userId !== 'aegis-server-gateway'
    ) {
      return makeRejectedReport({
        status: 'KEY_MISMATCH',
        reason: `Origin signer "${hop.signerId}" does not match key owner "${keyRecord.userId}".`,
        envelope,
        chain: chainResults,
      });
    }

    // Key lifecycle validity at signed timestamp (revokedAt / rotatedAt cutoffs)
    const keyTimeValid = isKeyValidForTimestamp(keyRecord, hop.signedAt || p.createdAt);
    if (!keyTimeValid.valid) {
      return makeRejectedReport({
        status: keyTimeValid.status,
        reason: keyTimeValid.reason || 'Key lifecycle state rejects this signature timestamp.',
        envelope,
        chain: chainResults,
        fingerprintHex: keyRecord.fingerprintHex,
        fingerprintWords: keyRecord.fingerprintWords,
      });
    }

    // Verify client-side TOFU key pinning on origin user keys
    if (i === 0 && options.pinnedKey && keyRecord.userId !== 'aegis-server-gateway') {
      const pinCheck = verifyPinnedKeyContinuity({
        pinnedKey: options.pinnedKey,
        signerUserId: keyRecord.userId,
        presentedKid: keyRecord.kid,
        presentedPublicKey: keyRecord.publicKey,
        keyLogEntries: options.keyLogEntries,
      });
      if (!pinCheck.ok) {
        return makeRejectedReport({
          status: 'KEY_MISMATCH',
          reason: pinCheck.reason || 'TOFU key pin mismatch detected.',
          envelope,
          chain: chainResults,
          fingerprintHex: keyRecord.fingerprintHex,
          fingerprintWords: keyRecord.fingerprintWords,
        });
      }
    }

    // Ed25519 signature verification
    let sigBytes: Uint8Array;
    try {
      sigBytes = base64ToBytes(hop.sig);
    } catch {
      return makeRejectedReport({
        status: 'INVALID_SIGNATURE',
        reason: `Malformed base64 signature at hop #${i + 1}.`,
        envelope,
        chain: chainResults,
      });
    }

    const bytesToVerify =
      i === 0
        ? buildProvenanceSigningBytes(p, options.domainPrefixOverride)
        : buildAttestationSigningBytes({
            role: hop.role,
            alg: 'Ed25519',
            kid: hop.kid,
            signerId: hop.signerId,
            signedAt: hop.signedAt,
            parentHash: hop.parentHash,
            messageId: p.messageId,
            ciphertextHash: p.ciphertextHash,
          });

    const sigOk = await options.verifyEd25519(bytesToVerify, sigBytes, keyRecord.publicKey);
    if (!sigOk) {
      return makeRejectedReport({
        status: 'INVALID_SIGNATURE',
        reason: `Ed25519 signature verification failed at hop #${i + 1} (${hop.role}, kid=${hop.kid}).`,
        envelope,
        chain: [
          ...chainResults,
          {
            role: hop.role,
            kid: hop.kid,
            signerId: hop.signerId,
            signedAt: hop.signedAt,
            parentHash: hop.parentHash,
            verified: false,
            status: 'INVALID_SIGNATURE',
            reason: 'Invalid Ed25519 signature',
          },
        ],
        fingerprintHex: keyRecord.fingerprintHex,
        fingerprintWords: keyRecord.fingerprintWords,
      });
    }

    chainResults.push({
      role: hop.role,
      kid: hop.kid,
      signerId: hop.signerId,
      signedAt: hop.signedAt,
      parentHash: hop.parentHash,
      verified: true,
      status: 'VERIFIED',
      reason:
        hop.role === 'GATEWAY'
          ? 'Server gateway Ed25519 attestation verified'
          : 'Origin user Ed25519 signature verified',
    });

    previousSigDigest = await computeSha256Hex(hop.sig);
  }

  // 6. Replay check `(kid, nonce)` ONLY after basic structure/timestamps look legitimate (10m window)
  if (options.enforceReplay && options.replayCheck) {
    const replayOutcome = await options.replayCheck({
      kid: p.kid,
      nonce: p.nonce,
      nowMs,
    });
    if (replayOutcome.replayed) {
      return makeRejectedReport({
        status: 'REPLAY',
        reason: `Replay blocked: nonce "${p.nonce.slice(0, 12)}..." already observed for key "${p.kid}" within 10-minute replay window.`,
        envelope,
        chain: chainResults,
        fingerprintHex: primaryKeyRecord?.fingerprintHex,
        fingerprintWords: primaryKeyRecord?.fingerprintWords,
      });
    }
  }

  const hasGatewayOnly =
    chainResults.length === 1 && chainResults[0]?.role === 'GATEWAY';

  return {
    status: 'VERIFIED',
    verified: true,
    reason: hasGatewayOnly
      ? 'Gateway-attested Ed25519 provenance verified (HMAC webhook validated & server-signed).'
      : 'End-to-end Ed25519 origin provenance verified across all hops.',
    alg: 'Ed25519',
    kid: p.kid,
    signerId: envelope.chain[0]?.signerId || p.senderId,
    source: p.source,
    badgeVariant: hasGatewayOnly ? 'gateway' : 'verified',
    fingerprintHex: primaryKeyRecord?.fingerprintHex,
    fingerprintWords: primaryKeyRecord?.fingerprintWords,
    createdAt: p.createdAt,
    chain: chainResults,
    envelope,
  };
}
