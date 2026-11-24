import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  base64ToBytes,
  buildProvenanceSigningBytes,
  bytesToBase64,
  bytesToHex,
  canonicalizeJson,
  computeCiphertextHash,
  computePayloadHash,
  computePublicKeyFingerprint,
  hexToBytes,
} from '../canonical.js';
import {
  signEd25519Bytes,
  verifyEd25519Browser,
  createEncryptedSigningKeyBundle,
  unlockEncryptedSigningKeyBundle,
} from '../browserCrypto.js';
import {
  createServerAttestedEnvelope,
  getServerProvenanceKey,
  signBytesWithSeedServer,
  verifyEd25519Server,
} from '../serverCrypto.js';
import {
  verifyPinnedKeyContinuity,
  verifyProvenanceEnvelope,
} from '../verifyPolicy.js';
import {
  checkAndRecordReplayNonce,
  deleteDemoProvenanceState,
  getKeyLogPage,
  lookupProvenanceKeyByKid,
  registerUserProvenanceKey,
  revokeUserProvenanceKey,
  rotateUserProvenanceKey,
  verifyEnvelopeOnServer,
  verifyKeyLogChain,
} from '../store.js';
import { checkOrPinKeyTofu, deletePinnedKey } from '../pinning.js';
import type { ProvenanceEnvelopeV1, ProvenanceKeyRecord } from '../types.js';

// Official RFC 8032 Section 7.1 Ed25519 Test Vectors 1, 2, 3
const RFC8032_VECTORS = [
  {
    name: 'RFC 8032 Vector 1 (empty message)',
    seedHex: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    pubHex: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    msgHex: '',
    sigHex:
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' +
      '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    name: 'RFC 8032 Vector 2 (1-byte 0x72)',
    seedHex: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    pubHex: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    msgHex: '72',
    sigHex:
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
      '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
  {
    name: 'RFC 8032 Vector 3 (2-byte 0xaf82)',
    seedHex: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    pubHex: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    msgHex: 'af82',
    sigHex:
      '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' +
      '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },
];

async function makeTestBrowserEnvelope(params: {
  seedHex: string;
  userId: string;
  messageId?: string;
  recipientId?: string;
  ciphertext?: string;
  iv?: string;
  priority?: string;
  createdAt?: string;
  expiresAt?: string;
  nonce?: string;
  domainPrefixOverride?: string;
}): Promise<{
  envelope: ProvenanceEnvelopeV1;
  keyRecord: ProvenanceKeyRecord;
  seed: Uint8Array;
}> {
  const seed = hexToBytes(params.seedHex);
  const pubBytes = ed25519.getPublicKey(seed);
  const publicKey = bytesToBase64(pubBytes);
  const fp = await computePublicKeyFingerprint(publicKey);
  const createdAt = params.createdAt || new Date().toISOString();
  const ciphertext = params.ciphertext ?? 'cipher_payload_abc';
  const iv = params.iv ?? 'iv_123';
  const ciphertextHash = await computeCiphertextHash(ciphertext, iv);

  const payload = {
    v: 1 as const,
    alg: 'Ed25519' as const,
    kid: fp.kid,
    messageId: params.messageId || `msg_${Math.random().toString(36).slice(2, 8)}`,
    senderId: params.userId,
    recipientId: params.recipientId || params.userId,
    source: 'direct',
    priority: params.priority || 'CRITICAL',
    createdAt,
    nonce: params.nonce || bytesToHex(Buffer.from('0123456789abcdef0123456789abcdef', 'hex')),
    ciphertextHash,
    ...(params.expiresAt ? { expiresAt: params.expiresAt } : {}),
  };

  const payloadHash = await computePayloadHash(payload);
  const sigBytes = signEd25519Bytes(
    buildProvenanceSigningBytes(payload, params.domainPrefixOverride),
    seed
  );

  const envelope: ProvenanceEnvelopeV1 = {
    v: 1,
    payload,
    chain: [
      {
        role: 'ORIGIN',
        alg: 'Ed25519',
        kid: fp.kid,
        signerId: params.userId,
        signedAt: createdAt,
        parentHash: payloadHash,
        sig: bytesToBase64(sigBytes),
      },
    ],
  };

  const keyRecord: ProvenanceKeyRecord = {
    kid: fp.kid,
    userId: params.userId,
    publicKey,
    status: 'ACTIVE',
    createdAt: new Date(Date.parse(createdAt) - 60_000).toISOString(),
    fingerprintHex: fp.fingerprintHex,
    fingerprintWords: fp.fingerprintWords,
  };

  return { envelope, keyRecord, seed };
}

describe('Zero-Trust Ed25519 Provenance Engine', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-21T12:00:00.000Z'));
  });

  afterEach(async () => {
    vi.useRealTimers();
    await deleteDemoProvenanceState(['prov_unit_']);
  });

  it('matches official RFC 8032 Ed25519 vectors identically across Node crypto and browser @noble/curves', async () => {
    for (const vec of RFC8032_VECTORS) {
      const seed = hexToBytes(vec.seedHex);
      const msg = hexToBytes(vec.msgHex);

      // Browser (@noble/curves/ed25519)
      const browserPub = ed25519.getPublicKey(seed);
      const browserSig = signEd25519Bytes(msg, seed);
      expect(bytesToHex(browserPub)).toBe(vec.pubHex);
      expect(bytesToHex(browserSig)).toBe(vec.sigHex);

      // Node built-in crypto
      const nodeSig = signBytesWithSeedServer(msg, seed);
      expect(bytesToHex(nodeSig)).toBe(vec.sigHex);

      // Cross-verification: Node verifies browser signature, browser verifies Node signature
      const pubB64 = bytesToBase64(browserPub);
      expect(verifyEd25519Server(msg, browserSig, pubB64)).toBe(true);
      expect(await verifyEd25519Browser(msg, nodeSig, pubB64)).toBe(true);
    }
  });

  it('produces identical canonical JSON digests regardless of object property insertion order', () => {
    const a = {
      z: 1,
      a: { k2: 'val', k1: [3, 1, 2], omitted: undefined },
      m: true,
    };
    const b = {
      m: true,
      a: { k1: [3, 1, 2], k2: 'val' },
      z: 1,
    };
    expect(canonicalizeJson(a)).toBe(canonicalizeJson(b));
    expect(canonicalizeJson(a)).toBe('{"a":{"k1":[3,1,2],"k2":"val"},"m":true,"z":1}');
  });

  it('enforces domain separation (rejects signatures signed under wrong prefix)', async () => {
    const { envelope, keyRecord } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[0].seedHex,
      userId: 'prov_unit_alice',
      domainPrefixOverride: 'AEGIS-OTHER-CONTEXT-v1\0',
    });

    const report = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_alice',
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Server,
    });

    expect(report.verified).toBe(false);
    expect(report.status).toBe('INVALID_SIGNATURE');
  });

  it('rejects tampered ciphertext, unknown keys, target mismatch, broken chains, clock skew, and expiry', async () => {
    const { envelope, keyRecord } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[0].seedHex,
      userId: 'prov_unit_alice',
      recipientId: 'prov_unit_bob',
      ciphertext: 'original_cipher',
      iv: 'iv_orig',
    });

    // 1. Valid baseline passes
    const okReport = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_bob',
      expectedCiphertext: 'original_cipher',
      expectedIv: 'iv_orig',
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(okReport.verified).toBe(true);
    expect(okReport.status).toBe('VERIFIED');

    // 2. Modified ciphertext fails ciphertext hash binding
    const tamperedCipher = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_bob',
      expectedCiphertext: 'tampered_cipher',
      expectedIv: 'iv_orig',
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(tamperedCipher.verified).toBe(false);
    expect(tamperedCipher.status).toBe('INVALID_SIGNATURE');

    // 3. Unknown key rejected
    const unknownKey = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_bob',
      expectedCiphertext: 'original_cipher',
      expectedIv: 'iv_orig',
      keyLookup: () => null,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(unknownKey.verified).toBe(false);
    expect(unknownKey.status).toBe('UNKNOWN_KEY');

    // 4. Target recipient transplant rejected
    const targetMismatch = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_eve',
      expectedCiphertext: 'original_cipher',
      expectedIv: 'iv_orig',
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(targetMismatch.verified).toBe(false);
    expect(targetMismatch.status).toBe('TARGET_MISMATCH');

    // 5. Broken attestation chain parentHash rejected
    const brokenChainEnv: ProvenanceEnvelopeV1 = {
      ...envelope,
      chain: [{ ...envelope.chain[0], parentHash: 'f'.repeat(64) }],
    };
    const badChain = await verifyProvenanceEnvelope({
      envelope: brokenChainEnv,
      expectedRecipientId: 'prov_unit_bob',
      expectedCiphertext: 'original_cipher',
      expectedIv: 'iv_orig',
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(badChain.verified).toBe(false);
    expect(badChain.status).toBe('BAD_CHAIN');

    // 6. Clock skew +-6 minutes rejected
    const skewedReport = await verifyProvenanceEnvelope({
      envelope,
      expectedRecipientId: 'prov_unit_bob',
      expectedCiphertext: 'original_cipher',
      expectedIv: 'iv_orig',
      nowMs: Date.now() + 6 * 60 * 1000,
      keyLookup: () => keyRecord,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(skewedReport.verified).toBe(false);
    expect(skewedReport.status).toBe('CLOCK_SKEW');

    // 7. Expired envelope rejected
    const { envelope: expEnv, keyRecord: expKey } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[0].seedHex,
      userId: 'prov_unit_alice',
      expiresAt: new Date(Date.now() + 30_000).toISOString(),
    });
    vi.advanceTimersByTime(31_000);
    const expiredReport = await verifyProvenanceEnvelope({
      envelope: expEnv,
      expectedRecipientId: 'prov_unit_alice',
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      keyLookup: () => expKey,
      verifyEd25519: verifyEd25519Browser,
    });
    expect(expiredReport.verified).toBe(false);
    expect(expiredReport.status).toBe('EXPIRED_ENVELOPE');
  });

  it('blocks duplicate (kid, nonce) replays inside 10 minutes and clears after expiry', async () => {
    const userId = 'prov_unit_replay_usr';
    const seed = hexToBytes(RFC8032_VECTORS[1].seedHex);
    const pubB64 = bytesToBase64(ed25519.getPublicKey(seed));
    await registerUserProvenanceKey({ userId, publicKey: pubB64, skipTelemetry: true });

    const nonce = bytesToHex(Buffer.from('abcdef0123456789abcdef0123456789', 'hex'));
    const { envelope } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[1].seedHex,
      userId,
      nonce,
    });

    const first = await verifyEnvelopeOnServer({
      envelope,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: true,
      skipTelemetry: true,
    });
    expect(first.verified).toBe(true);

    // Immediate replay with same nonce is blocked
    const replay = await verifyEnvelopeOnServer({
      envelope,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: true,
      skipTelemetry: true,
    });
    expect(replay.verified).toBe(false);
    expect(replay.status).toBe('REPLAY');

    // Advance 10m + 1s and re-sign with same nonce -> allowed because old nonce evicted
    vi.advanceTimersByTime(10 * 60 * 1000 + 1000);
    const { envelope: freshEnv } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[1].seedHex,
      userId,
      nonce,
    });
    const afterWindow = await verifyEnvelopeOnServer({
      envelope: freshEnv,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: true,
      skipTelemetry: true,
    });
    expect(afterWindow.verified).toBe(true);
    expect(await checkAndRecordReplayNonce({ kid: envelope.payload.kid, nonce })).toEqual({
      replayed: true,
    });
  });

  it('enforces key rotation timestamps, revocation cutoff, and TOFU pin key-substitution detection', async () => {
    const userId = 'prov_unit_rot_usr';
    const seed1 = hexToBytes(RFC8032_VECTORS[0].seedHex);
    const seed2 = hexToBytes(RFC8032_VECTORS[1].seedHex);
    const pub1 = bytesToBase64(ed25519.getPublicKey(seed1));
    const pub2 = bytesToBase64(ed25519.getPublicKey(seed2));

    const reg = await registerUserProvenanceKey({ userId, publicKey: pub1, skipTelemetry: true });
    expect(reg.ok).toBe(true);
    const kid1 = reg.key!.kid;

    // Pre-rotation message signed before rotation timestamp
    const preRotTime = new Date(Date.now()).toISOString();
    const { envelope: preRotEnv } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[0].seedHex,
      userId,
      createdAt: preRotTime,
      nonce: '11'.repeat(16),
    });

    // Rotate 10 seconds later
    vi.advanceTimersByTime(10_000);
    const rot = await rotateUserProvenanceKey({
      userId,
      oldKid: kid1,
      newPublicKey: pub2,
      skipTelemetry: true,
    });
    expect(rot.ok).toBe(true);
    const kid2 = rot.newKey!.kid;

    // Pre-rotation message still verifies cleanly
    const verifyPre = await verifyEnvelopeOnServer({
      envelope: preRotEnv,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: false,
      skipTelemetry: true,
    });
    expect(verifyPre.verified).toBe(true);

    // Post-rotation message signed with OLD key fails KEY_MISMATCH
    vi.advanceTimersByTime(2_000);
    const { envelope: postRotOldKeyEnv } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[0].seedHex,
      userId,
      nonce: '22'.repeat(16),
    });
    const verifyPostOld = await verifyEnvelopeOnServer({
      envelope: postRotOldKeyEnv,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: false,
      skipTelemetry: true,
    });
    expect(verifyPostOld.verified).toBe(false);
    expect(verifyPostOld.status).toBe('KEY_MISMATCH');

    // TOFU pin continuity: pin kid1, accept kid2 via ROTATE chain, reject rogue kid3 without ROTATE
    await deletePinnedKey(userId);
    const logPage = await getKeyLogPage({ limit: 200 });
    const pin1 = await checkOrPinKeyTofu({
      userId,
      kid: kid1,
      publicKey: pub1,
      fingerprintHex: reg.key!.fingerprintHex,
      keyLogEntries: logPage.entries,
    });
    expect(pin1.ok).toBe(true);
    expect(pin1.newlyPinned).toBe(true);

    const pin2 = await checkOrPinKeyTofu({
      userId,
      kid: kid2,
      publicKey: pub2,
      fingerprintHex: rot.newKey!.fingerprintHex,
      keyLogEntries: logPage.entries,
    });
    expect(pin2.ok).toBe(true);
    expect(pin2.rotatedPin).toBe(true);

    const roguePub = bytesToBase64(ed25519.getPublicKey(hexToBytes(RFC8032_VECTORS[2].seedHex)));
    const rogueFp = await computePublicKeyFingerprint(roguePub);
    const swapAttempt = verifyPinnedKeyContinuity({
      pinnedKey: pin2.pin,
      signerUserId: userId,
      presentedKid: rogueFp.kid,
      presentedPublicKey: roguePub,
      keyLogEntries: logPage.entries,
    });
    expect(swapAttempt.ok).toBe(false);

    // Revoke kid2 and verify message signed at/after revocation fails REVOKED_KEY
    const rev = await revokeUserProvenanceKey({
      userId,
      kid: kid2,
      reason: 'Compromise test',
      skipTelemetry: true,
    });
    expect(rev.ok).toBe(true);
    const { envelope: revokedEnv } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[1].seedHex,
      userId,
      nonce: '33'.repeat(16),
    });
    const revReport = await verifyEnvelopeOnServer({
      envelope: revokedEnv,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      enforceReplay: false,
      skipTelemetry: true,
    });
    expect(revReport.verified).toBe(false);
    expect(revReport.status).toBe('REVOKED_KEY');
  });

  it('appends server GATEWAY attestation hop and verifies KeyLog hash chain + detects tampering', async () => {
    const userId = 'prov_unit_chain_usr';
    const seed = hexToBytes(RFC8032_VECTORS[2].seedHex);
    const pubB64 = bytesToBase64(ed25519.getPublicKey(seed));
    await registerUserProvenanceKey({ userId, publicKey: pubB64, skipTelemetry: true });

    const { envelope } = await makeTestBrowserEnvelope({
      seedHex: RFC8032_VECTORS[2].seedHex,
      userId,
      nonce: '44'.repeat(16),
    });

    const attested = await createServerAttestedEnvelope({
      messageId: envelope.payload.messageId,
      senderId: userId,
      recipientId: userId,
      source: 'direct',
      priority: 'CRITICAL',
      ciphertextOrDigestInput: 'cipher_payload_abc',
      ivOrSalt: 'iv_123',
      role: 'GATEWAY',
      existingEnvelope: envelope,
    });

    expect(attested.chain.length).toBe(2);
    expect(attested.chain[0].role).toBe('ORIGIN');
    expect(attested.chain[1].role).toBe('GATEWAY');

    const serverInfo = await getServerProvenanceKey();
    const browserVerified = await verifyProvenanceEnvelope({
      envelope: attested,
      expectedRecipientId: userId,
      expectedCiphertext: 'cipher_payload_abc',
      expectedIv: 'iv_123',
      keyLookup: async (kid) => {
        if (kid === serverInfo.kid) {
          return {
            kid: serverInfo.kid,
            userId: 'aegis-server-gateway',
            publicKey: serverInfo.publicKey,
            status: 'ACTIVE',
            createdAt: serverInfo.validFrom,
            fingerprintHex: serverInfo.fingerprintHex,
            fingerprintWords: serverInfo.fingerprintWords,
          };
        }
        return lookupProvenanceKeyByKid(kid);
      },
      verifyEd25519: verifyEd25519Browser,
    });
    expect(browserVerified.verified).toBe(true);
    expect(browserVerified.chain.length).toBe(2);

    // Key Transparency Log integrity + tamper detection
    const page = await getKeyLogPage({ limit: 200 });
    const cleanChain = await verifyKeyLogChain(page.entries, { skipTelemetry: true });
    expect(cleanChain.ok).toBe(true);

    if (page.entries.length > 0) {
      const tampered = structuredClone(page.entries);
      tampered[0].kid = 'deadbeef00000000';
      const broken = await verifyKeyLogChain(tampered, { skipTelemetry: true });
      expect(broken.ok).toBe(false);
      expect(broken.brokenAtIndex).toBe(0);
    }
  });

  it('encrypts browser signing seed with PBKDF2 + AES-GCM and wipes RAM handle on lock', async () => {
    const { bundle, unlocked } = await createEncryptedSigningKeyBundle(
      'prov_unit_pbkdf2',
      'StrongPassphrase!99'
    );
    expect(bundle.kdf).toBe('PBKDF2-HMAC-SHA256');
    expect(bundle.cipher).toBe('AES-256-GCM');
    expect(unlocked.isWiped()).toBe(false);

    // Wrong passphrase throws
    await expect(
      unlockEncryptedSigningKeyBundle(bundle, 'WrongPassphrase!00')
    ).rejects.toThrow();

    // Correct passphrase unlocks matching kid
    const reopened = await unlockEncryptedSigningKeyBundle(bundle, 'StrongPassphrase!99');
    expect(reopened.kid).toBe(bundle.kid);
    reopened.wipe();
    expect(reopened.isWiped()).toBe(true);
    expect(() => reopened.getSecretSeedCopy()).toThrow();
    unlocked.wipe();
  });
});
