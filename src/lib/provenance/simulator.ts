import crypto from 'crypto';
import {
  buildAttestationSigningBytes,
  buildProvenanceSigningBytes,
  bytesToBase64,
  computeCiphertextHash,
  computePayloadHash,
  computePublicKeyFingerprint,
} from './canonical.js';
import {
  extractRawPublicKeyBase64FromKeyObject,
  getServerProvenanceKey,
  signBytesWithServerKey,
} from './serverCrypto.js';
import {
  getKeyLogPage,
  lookupProvenanceKeyByKid,
  registerUserProvenanceKey,
  revokeUserProvenanceKey,
  rotateUserProvenanceKey,
  verifyEnvelopeOnServer,
  verifyKeyLogChain,
} from './store.js';
import { verifyProvenanceEnvelope } from './verifyPolicy.js';
import { verifyEd25519Server } from './serverCrypto.js';
import type {
  PinnedKeyRecord,
  ProvenanceAttestation,
  ProvenanceEnvelopeV1,
  ProvenancePayloadV1,
  ProvenanceStatus,
} from './types.js';

export interface ProvenanceSimulationStep {
  id: string;
  label: string;
  description: string;
  expectedStatus: string;
  actualStatus: string;
  passed: boolean;
  details: string;
}

export interface ProvenanceSimulationReport {
  demoMode: true;
  ranAt: string;
  passedCount: number;
  totalCount: number;
  allPassed: boolean;
  steps: ProvenanceSimulationStep[];
}

function generateTestEd25519Pair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPubB64 = extractRawPublicKeyBase64FromKeyObject(publicKey);
  return { privateKey, rawPubB64 };
}

function signTestPayload(payload: ProvenancePayloadV1, privKey: crypto.KeyObject): string {
  const bytes = buildProvenanceSigningBytes(payload);
  return crypto.sign(null, Buffer.from(bytes), privKey).toString('base64');
}

async function buildSignedEnvelope(params: {
  senderId: string;
  recipientId: string;
  messageId: string;
  kid: string;
  privKey: crypto.KeyObject;
  ciphertext?: string;
  iv?: string;
  priority?: string;
  createdAt?: string;
  expiresAt?: string;
  nonce?: string;
}): Promise<{ envelope: ProvenanceEnvelopeV1; ciphertext: string; iv: string }> {
  const ciphertext = params.ciphertext || 'c2ltdWxhdGVkLWNpcGhlcnRleHQ=';
  const iv = params.iv || 'MTIzNDU2Nzg5MDEy';
  const createdAt = params.createdAt || new Date().toISOString();
  const nonce = params.nonce || crypto.randomBytes(16).toString('hex');
  const ciphertextHash = await computeCiphertextHash(ciphertext, iv);

  const payload: ProvenancePayloadV1 = {
    v: 1,
    alg: 'Ed25519',
    kid: params.kid,
    messageId: params.messageId,
    senderId: params.senderId,
    recipientId: params.recipientId,
    source: 'direct',
    priority: params.priority || 'CRITICAL',
    createdAt,
    nonce,
    ciphertextHash,
    ...(params.expiresAt ? { expiresAt: params.expiresAt } : {}),
  };

  const payloadHash = await computePayloadHash(payload);
  const sig = signTestPayload(payload, params.privKey);

  return {
    ciphertext,
    iv,
    envelope: {
      v: 1,
      payload,
      chain: [
        {
          role: 'ORIGIN',
          alg: 'Ed25519',
          kid: params.kid,
          signerId: params.senderId,
          signedAt: createdAt,
          parentHash: payloadHash,
          sig,
        },
      ],
    },
  };
}

/**
 * Executes the isolated 12-scenario (a–l) Zero-Trust Ed25519 Provenance Attack Simulator.
 * Requires explicit `demoMode: true` flag and admin authorization.
 */
export async function runProvenanceAttackSimulator(
  scenariosFilter?: string[]
): Promise<ProvenanceSimulationReport> {
  const runId = Date.now().toString(36);
  const senderId = `prov_sim_sender_${runId}`;
  const recipientId = `prov_sim_recipient_${runId}`;
  const otherRecipientId = `prov_sim_other_${runId}`;

  const steps: ProvenanceSimulationStep[] = [];
  const shouldRun = (id: string) =>
    !scenariosFilter || scenariosFilter.length === 0 || scenariosFilter.includes(id);

  // Provision isolated sender key A
  const kpA = generateTestEd25519Pair();
  const regA = await registerUserProvenanceKey({
    userId: senderId,
    publicKey: kpA.rawPubB64,
    reason: 'Provenance Attack Simulator isolated demo key A',
    skipTelemetry: true,
  });
  const kidA = regA.key!.kid;

  // a) Unsigned CRITICAL/HIGH message rejected (403)
  if (shouldRun('a')) {
    const res = await verifyEnvelopeOnServer({
      envelope: null,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_a_${runId}`,
      priority: 'CRITICAL',
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    const blockedStatus = res.status === 'UNSIGNED' ? 'UNSIGNED (HTTP 403 Rejected)' : res.status;
    steps.push({
      id: 'a',
      label: 'a) Unsigned CRITICAL/HIGH message',
      description: 'Verify zero-trust policy rejects unsigned CRITICAL/HIGH payloads instead of trusting them.',
      expectedStatus: 'UNSIGNED (HTTP 403 Rejected)',
      actualStatus: blockedStatus,
      passed: res.status === 'UNSIGNED' && !res.verified,
      details: res.reason,
    });
  }

  // b) Tampered message body / ciphertext
  if (shouldRun('b')) {
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_b_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
    });
    const res = await verifyEnvelopeOnServer({
      envelope: built.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_b_${runId}`,
      expectedCiphertext: 'dGFtcGVyZWQtY2lwaGVydGV4dC1ieXRlcw==', // modified ciphertext
      expectedIv: built.iv,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'b',
      label: 'b) Tampered ciphertext body',
      description: 'Modify ciphertext after Ed25519 signing and confirm SHA-256 ciphertextHash mismatch detection.',
      expectedStatus: 'INVALID_SIGNATURE',
      actualStatus: res.status,
      passed: res.status === 'INVALID_SIGNATURE',
      details: res.reason,
    });
  }

  // c) Tampered envelope priority / recipientId
  if (shouldRun('c')) {
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_c_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
      priority: 'LOW',
    });
    // Mutate priority in signed envelope without re-signing
    const tampered: ProvenanceEnvelopeV1 = {
      ...built.envelope,
      payload: { ...built.envelope.payload, priority: 'CRITICAL' },
    };
    const res = await verifyEnvelopeOnServer({
      envelope: tampered,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_c_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      isDemo: true,
      skipTelemetry: true,
    });
    const passed = res.status === 'INVALID_SIGNATURE' || res.status === 'BAD_CHAIN';
    steps.push({
      id: 'c',
      label: 'c) Tampered envelope priority metadata',
      description: 'Mutate priority from LOW to CRITICAL inside signed envelope without re-signing.',
      expectedStatus: 'BAD_CHAIN / INVALID_SIGNATURE',
      actualStatus: res.status,
      passed,
      details: res.reason,
    });
  }

  // d) Forged signature with unregistered attacker Ed25519 key
  if (shouldRun('d')) {
    const attackerKp = generateTestEd25519Pair();
    const attackerFp = await computePublicKeyFingerprint(attackerKp.rawPubB64);
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_d_${runId}`,
      kid: attackerFp.kid,
      privKey: attackerKp.privateKey,
    });
    const res = await verifyEnvelopeOnServer({
      envelope: built.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_d_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'd',
      label: 'd) Forged signature / impersonated sender',
      description: 'Submit payload signed by an unregistered attacker keypair claiming the target senderId.',
      expectedStatus: 'UNKNOWN_KEY',
      actualStatus: res.status,
      passed: res.status === 'UNKNOWN_KEY',
      details: res.reason,
    });
  }

  // e) Replay attack with duplicate nonce
  if (shouldRun('e')) {
    const fixedNonce = crypto.randomBytes(16).toString('hex');
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_e_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
      nonce: fixedNonce,
    });
    const first = await verifyEnvelopeOnServer({
      envelope: built.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_e_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      enforceReplay: true,
      isDemo: true,
      skipTelemetry: true,
    });
    const replay = await verifyEnvelopeOnServer({
      envelope: built.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_e_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      enforceReplay: true,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'e',
      label: 'e) Replay attack (duplicate nonce)',
      description: 'Verify valid envelope succeeds once then exact duplicate (kid, nonce) is blocked.',
      expectedStatus: 'VERIFIED -> REPLAY',
      actualStatus: `${first.status} -> ${replay.status}`,
      passed: first.status === 'VERIFIED' && replay.status === 'REPLAY',
      details: replay.reason,
    });
  }

  // f) Expired envelope & stale timestamp (> +-5m skew)
  if (shouldRun('f')) {
    const staleDate = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const expiredDate = new Date(Date.now() - 60 * 1000).toISOString();
    const builtExpired = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_f1_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
      expiresAt: expiredDate,
    });
    const builtSkew = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_f2_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
      createdAt: staleDate,
    });
    const resExp = await verifyEnvelopeOnServer({
      envelope: builtExpired.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_f1_${runId}`,
      expectedCiphertext: builtExpired.ciphertext,
      expectedIv: builtExpired.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    const resSkew = await verifyEnvelopeOnServer({
      envelope: builtSkew.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_f2_${runId}`,
      expectedCiphertext: builtSkew.ciphertext,
      expectedIv: builtSkew.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'f',
      label: 'f) Expired envelope & stale clock skew',
      description: 'Confirm envelopes past expiresAt (EXPIRED_ENVELOPE) or outside +-5m (CLOCK_SKEW) reject.',
      expectedStatus: 'EXPIRED_ENVELOPE + CLOCK_SKEW',
      actualStatus: `${resExp.status} + ${resSkew.status}`,
      passed: resExp.status === 'EXPIRED_ENVELOPE' && resSkew.status === 'CLOCK_SKEW',
      details: `${resExp.reason} | ${resSkew.reason}`,
    });
  }

  // g) Envelope transplanted to wrong recipient
  if (shouldRun('g')) {
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_g_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
    });
    const res = await verifyEnvelopeOnServer({
      envelope: built.envelope,
      expectedRecipientId: otherRecipientId,
      expectedMessageId: `sim_g_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'g',
      label: 'g) Wrong recipient (envelope transplant)',
      description: 'Verify envelope addressed to User A is blocked when presented to User B.',
      expectedStatus: 'TARGET_MISMATCH',
      actualStatus: res.status,
      passed: res.status === 'TARGET_MISMATCH',
      details: res.reason,
    });
  }

  // h) Key revocation enforcement
  const kpB = generateTestEd25519Pair();
  const regB = await registerUserProvenanceKey({
    userId: `${senderId}_rev`,
    publicKey: kpB.rawPubB64,
    reason: 'Simulator revocable key',
    skipTelemetry: true,
  });
  const kidB = regB.key!.kid;
  if (shouldRun('h')) {
    const revTime = new Date(Date.now() - 5000).toISOString();
    await revokeUserProvenanceKey({
      userId: `${senderId}_rev`,
      kid: kidB,
      reason: 'Simulator compromise drill',
      revokedAtOverride: revTime,
      skipTelemetry: true,
    });
    const builtAfterRevoke = await buildSignedEnvelope({
      senderId: `${senderId}_rev`,
      recipientId,
      messageId: `sim_h_${runId}`,
      kid: kidB,
      privKey: kpB.privateKey,
      createdAt: new Date().toISOString(),
    });
    const res = await verifyEnvelopeOnServer({
      envelope: builtAfterRevoke.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_h_${runId}`,
      expectedCiphertext: builtAfterRevoke.ciphertext,
      expectedIv: builtAfterRevoke.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'h',
      label: 'h) Message signed by REVOKED key',
      description: 'Revoke key and confirm signatures created at/after revokedAt fail with REVOKED_KEY.',
      expectedStatus: 'REVOKED_KEY',
      actualStatus: res.status,
      passed: res.status === 'REVOKED_KEY',
      details: res.reason,
    });
  }

  // i) Key rotation boundary: pre-rotation verifies, post-rotation old key fails
  if (shouldRun('i')) {
    const kpRotOld = generateTestEd25519Pair();
    const kpRotNew = generateTestEd25519Pair();
    const rotUser = `${senderId}_rot`;
    const regOld = await registerUserProvenanceKey({
      userId: rotUser,
      publicKey: kpRotOld.rawPubB64,
      skipTelemetry: true,
    });
    const oldKid = regOld.key!.kid;
    const tPre = new Date(Date.now() - 20_000).toISOString();
    const tRotate = new Date(Date.now() - 10_000).toISOString();
    const tPost = new Date(Date.now() - 2_000).toISOString();

    const preMsg = await buildSignedEnvelope({
      senderId: rotUser,
      recipientId,
      messageId: `sim_i_pre_${runId}`,
      kid: oldKid,
      privKey: kpRotOld.privateKey,
      createdAt: tPre,
    });

    await rotateUserProvenanceKey({
      userId: rotUser,
      newPublicKey: kpRotNew.rawPubB64,
      oldKid,
      rotatedAtOverride: tRotate,
      skipTelemetry: true,
    });

    const postMsgWithOld = await buildSignedEnvelope({
      senderId: rotUser,
      recipientId,
      messageId: `sim_i_post_${runId}`,
      kid: oldKid,
      privKey: kpRotOld.privateKey,
      createdAt: tPost,
    });

    const resPre = await verifyEnvelopeOnServer({
      envelope: preMsg.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_i_pre_${runId}`,
      expectedCiphertext: preMsg.ciphertext,
      expectedIv: preMsg.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    const resPost = await verifyEnvelopeOnServer({
      envelope: postMsgWithOld.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_i_post_${runId}`,
      expectedCiphertext: postMsgWithOld.ciphertext,
      expectedIv: postMsgWithOld.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });

    steps.push({
      id: 'i',
      label: 'i) Rotated old key boundary',
      description: 'Confirm pre-rotation messages with old key verify while post-rotation use is rejected.',
      expectedStatus: 'VERIFIED (pre) + KEY_MISMATCH (post)',
      actualStatus: `${resPre.status} + ${resPost.status}`,
      passed: resPre.status === 'VERIFIED' && resPost.status === 'KEY_MISMATCH',
      details: resPost.reason,
    });
  }

  // j) Server key substitution without KeyLog ROTATE detected by client TOFU pin
  if (shouldRun('j')) {
    const rogueKp = generateTestEd25519Pair();
    const rogueReg = await registerUserProvenanceKey({
      userId: senderId, // registered directly as a fresh REGISTER (no ROTATE entry linking from kidA!)
      publicKey: rogueKp.rawPubB64,
      reason: 'Simulated unchained key substitution',
      skipTelemetry: true,
    });
    const builtSub = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_j_${runId}`,
      kid: rogueReg.key!.kid,
      privKey: rogueKp.privateKey,
    });
    const clientPin: PinnedKeyRecord = {
      userId: senderId,
      kid: kidA,
      publicKey: kpA.rawPubB64,
      fingerprintHex: regA.key!.fingerprintHex,
      pinnedAt: new Date(Date.now() - 60_000).toISOString(),
      lastLogIndex: 0,
    };
    const keyLog = (await getKeyLogPage({ limit: 200 })).entries;
    const resPin = await verifyProvenanceEnvelope({
      envelope: builtSub.envelope,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_j_${runId}`,
      expectedCiphertext: builtSub.ciphertext,
      expectedIv: builtSub.iv,
      keyLookup: lookupProvenanceKeyByKid,
      verifyEd25519: verifyEd25519Server,
      pinnedKey: clientPin,
      keyLogEntries: keyLog,
    });
    steps.push({
      id: 'j',
      label: 'j) Server key substitution vs TOFU pin',
      description: 'Detect a silent key swap lacking a valid ROTATE link in KeyLog against client TOFU pin.',
      expectedStatus: 'KEY_MISMATCH',
      actualStatus: resPin.status,
      passed: resPin.status === 'KEY_MISMATCH',
      details: resPin.reason,
    });
  }

  // k) Forged / broken hop in attestation chain
  if (shouldRun('k')) {
    const built = await buildSignedEnvelope({
      senderId,
      recipientId,
      messageId: `sim_k_${runId}`,
      kid: kidA,
      privKey: kpA.privateKey,
    });
    const serverInfo = await getServerProvenanceKey();
    const forgedHopSig = signBytesWithServerKey(
      buildAttestationSigningBytes({
        role: 'GATEWAY',
        alg: 'Ed25519',
        kid: serverInfo.kid,
        signerId: 'aegis-server-gateway',
        signedAt: new Date().toISOString(),
        parentHash: 'f'.repeat(64), // broken parentHash!
        messageId: built.envelope.payload.messageId,
        ciphertextHash: built.envelope.payload.ciphertextHash,
      })
    );
    const brokenChainEnv: ProvenanceEnvelopeV1 = {
      v: 1,
      payload: built.envelope.payload,
      chain: [
        ...built.envelope.chain,
        {
          role: 'GATEWAY',
          alg: 'Ed25519',
          kid: serverInfo.kid,
          signerId: 'aegis-server-gateway',
          signedAt: new Date().toISOString(),
          parentHash: 'f'.repeat(64),
          sig: forgedHopSig.sig,
        } satisfies ProvenanceAttestation,
      ],
    };
    const res = await verifyEnvelopeOnServer({
      envelope: brokenChainEnv,
      expectedRecipientId: recipientId,
      expectedMessageId: `sim_k_${runId}`,
      expectedCiphertext: built.ciphertext,
      expectedIv: built.iv,
      enforceReplay: false,
      isDemo: true,
      skipTelemetry: true,
    });
    steps.push({
      id: 'k',
      label: 'k) Broken attestation chain hop',
      description: 'Inject a gateway hop whose parentHash does not link to previous attestation digest.',
      expectedStatus: 'BAD_CHAIN',
      actualStatus: res.status,
      passed: res.status === 'BAD_CHAIN',
      details: res.reason,
    });
  }

  // l) Tampered historical KeyLog entry detected by Verify Chain
  if (shouldRun('l')) {
    const page = await getKeyLogPage({ limit: 200 });
    const cloned = page.entries.map((e) => ({ ...e }));
    if (cloned.length > 0) {
      cloned[0].publicKey = bytesToBase64(crypto.randomBytes(32));
    }
    const verifyTampered = await verifyKeyLogChain(cloned, { skipTelemetry: true });
    steps.push({
      id: 'l',
      label: 'l) Tampered historical KeyLog entry',
      description: 'Mutate a historical publicKey inside KeyLog and verify hash-chain detection catches it.',
      expectedStatus: 'CHAIN_BROKEN (FAIL at index 0)',
      actualStatus: verifyTampered.ok
        ? 'UNEXPECTED_PASS'
        : `CHAIN_BROKEN (FAIL at index ${verifyTampered.brokenAtIndex})`,
      passed: !verifyTampered.ok && verifyTampered.brokenAtIndex === 0,
      details: verifyTampered.reason,
    });
  }

  const passedCount = steps.filter((s) => s.passed).length;
  return {
    demoMode: true,
    ranAt: new Date().toISOString(),
    passedCount,
    totalCount: steps.length,
    allPassed: passedCount === steps.length,
    steps,
  };
}
