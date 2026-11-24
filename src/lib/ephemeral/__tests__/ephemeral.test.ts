import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  computeExpiryTimestamps,
  getDefaultEphemeralTtlSeconds,
  MAX_EPHEMERAL_TTL_SECONDS,
  READ_ONCE_GRACE_SECONDS,
  validateAndResolveTtlSeconds,
  buildEphemeralGenericAlertText,
} from '../constants.js';
import {
  encryptAndWrapEphemeralMessage,
  generateEphemeralKeyRing,
  verifyAndDecryptEphemeralMessage,
} from '../crypto.js';
import {
  createEphemeralMessage,
  cryptoShredEphemeralItem,
  getEphemeralTombstones,
  readEphemeralMessage,
  runEphemeralSweep,
  simulateEphemeralServerRestart,
  __getRawIsolatedCountsForTest,
} from '../ephemeralStore.js';
import { createDeliveryJob, getDeliveryJobById } from '../../delivery/deliveryStore.js';
import { getSecurityEvents } from '../../telemetry/securityLogger.js';

describe('Ephemeral Data Isolation (300s TTL & Crypto-Shredding)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-21T12:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    delete process.env.EPHEMERAL_TTL_SECONDS;
  });

  it('calculates TTL accurately and enforces server-side maximum (900s)', () => {
    delete process.env.EPHEMERAL_TTL_SECONDS;
    expect(getDefaultEphemeralTtlSeconds()).toBe(300);

    process.env.EPHEMERAL_TTL_SECONDS = '4500';
    expect(getDefaultEphemeralTtlSeconds()).toBe(MAX_EPHEMERAL_TTL_SECONDS);

    expect(validateAndResolveTtlSeconds(undefined).ttlSeconds).toBe(MAX_EPHEMERAL_TTL_SECONDS);
    expect(validateAndResolveTtlSeconds(60)).toMatchObject({ valid: true, ttlSeconds: 60 });
    expect(validateAndResolveTtlSeconds(300)).toMatchObject({ valid: true, ttlSeconds: 300 });
    expect(validateAndResolveTtlSeconds(900)).toMatchObject({ valid: true, ttlSeconds: 900 });

    const tooLarge = validateAndResolveTtlSeconds(1800);
    expect(tooLarge.valid).toBe(false);
    expect(tooLarge.error).toContain('900s');

    const unsupported = validateAndResolveTtlSeconds(120);
    expect(unsupported.valid).toBe(false);

    const t0 = Date.now();
    const { createdAtMs, expiresAtMs } = computeExpiryTimestamps(t0, 300);
    expect(expiresAtMs - createdAtMs).toBe(300_000);
  });

  it('rejects reads with 410 Gone immediately after mocked clock passes expiresAt', async () => {
    const senderRing = await generateEphemeralKeyRing('test_sender_ttl');
    const recipientRing = await generateEphemeralKeyRing('test_recipient_ttl');
    const id = `unit_eph_clock_${Date.now()}`;
    const plaintext = 'Top-secret mocked-clock payload';

    const encrypted = await encryptAndWrapEphemeralMessage({
      id,
      senderId: 'test_sender_ttl',
      recipientId: 'test_recipient_ttl',
      priority: 'HIGH',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      readOnce: false,
      plaintext,
      senderKeyRing: senderRing,
      recipientEcdhPublicJwk: recipientRing.ecdhPublicJwk,
    });

    const created = await createEphemeralMessage({
      id,
      senderId: 'test_sender_ttl',
      recipientId: 'test_recipient_ttl',
      ciphertext: encrypted.envelope.ciphertext,
      iv: encrypted.envelope.iv,
      signature: encrypted.envelope.signature,
      wrappedDek: encrypted.keyMaterial.wrappedDek,
      wrapIv: encrypted.keyMaterial.wrapIv,
      senderEcdhPubJwk: encrypted.envelope.senderEcdhPubJwk,
      senderEcdsaPubJwk: encrypted.envelope.senderEcdsaPubJwk,
      priority: 'HIGH',
      ttlSeconds: 300,
      readOnce: false,
      isDemo: true,
    });
    expect(created.ok).toBe(true);

    // Advance 299s -> still readable & decryptable
    vi.advanceTimersByTime(299_000);
    const beforeExpiry = await readEphemeralMessage({ id, userId: 'test_recipient_ttl' });
    expect(beforeExpiry.ok).toBe(true);
    expect(beforeExpiry.status).toBe(200);

    const dec = await verifyAndDecryptEphemeralMessage({
      envelope: beforeExpiry.data!.envelope,
      wrappedDek: beforeExpiry.data!.keyMaterial.wrappedDek,
      wrapIv: beforeExpiry.data!.keyMaterial.wrapIv,
      recipientEcdhPrivateKey: recipientRing.ecdhPrivateKey,
    });
    expect(dec.plaintext).toBe(plaintext);
    dec.wipeHandle();

    // Advance past 300s -> server clock returns 410 Gone
    vi.advanceTimersByTime(2_000);
    const afterExpiry = await readEphemeralMessage({ id, userId: 'test_recipient_ttl' });
    expect(afterExpiry.ok).toBe(false);
    expect(afterExpiry.status).toBe(410);
  });

  it('executes crypto-shredding strictly key-first before ciphertext and renders saved copies undecryptable', async () => {
    const senderRing = await generateEphemeralKeyRing('test_sender_shred');
    const recipientRing = await generateEphemeralKeyRing('test_recipient_shred');
    const id = `unit_eph_shred_${Date.now()}`;

    const encrypted = await encryptAndWrapEphemeralMessage({
      id,
      senderId: 'test_sender_shred',
      recipientId: 'test_recipient_shred',
      priority: 'CRITICAL',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      readOnce: false,
      plaintext: 'Crypto-shred proof canary text',
      senderKeyRing: senderRing,
      recipientEcdhPublicJwk: recipientRing.ecdhPublicJwk,
    });

    await createEphemeralMessage({
      id,
      senderId: 'test_sender_shred',
      recipientId: 'test_recipient_shred',
      ciphertext: encrypted.envelope.ciphertext,
      iv: encrypted.envelope.iv,
      signature: encrypted.envelope.signature,
      wrappedDek: encrypted.keyMaterial.wrappedDek,
      wrapIv: encrypted.keyMaterial.wrapIv,
      senderEcdhPubJwk: encrypted.envelope.senderEcdhPubJwk,
      senderEcdsaPubJwk: encrypted.envelope.senderEcdsaPubJwk,
      priority: 'CRITICAL',
      ttlSeconds: 300,
      isDemo: true,
    });

    const savedEnvelopeCopy = structuredClone(encrypted.envelope);
    const steps: string[] = [];

    const tombstone = await cryptoShredEphemeralItem({
      id,
      reason: 'BURNED',
      onStep: (s) => steps.push(s),
    });

    expect(tombstone).not.toBeNull();
    expect(steps).toEqual([
      'OVERWRITE_KEY',
      'DELETE_KEY',
      'OVERWRITE_DOC',
      'DELETE_DOC',
      'WRITE_TOMBSTONE',
    ]);

    const rawState = __getRawIsolatedCountsForTest();
    expect(rawState.hasKey(id)).toBe(false);
    expect(rawState.hasMessage(id)).toBe(false);

    // Even with a saved ciphertext copy, missing wrapped DEK makes decryption impossible
    await expect(
      verifyAndDecryptEphemeralMessage({
        envelope: savedEnvelopeCopy,
        wrappedDek: null,
        wrapIv: null,
        recipientEcdhPrivateKey: recipientRing.ecdhPrivateKey,
      })
    ).rejects.toThrow(/Crypto-shredded/i);
  });

  it('runs idempotent sweeper and startup catch-up sweep without duplicate tombstones or errors', async () => {
    const senderRing = await generateEphemeralKeyRing('test_sender_sweep');
    const recipientRing = await generateEphemeralKeyRing('test_recipient_sweep');
    const id = `unit_eph_sweep_${Date.now()}`;

    const encrypted = await encryptAndWrapEphemeralMessage({
      id,
      senderId: 'test_sender_sweep',
      recipientId: 'test_recipient_sweep',
      priority: 'MEDIUM',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      readOnce: false,
      plaintext: 'Sweeper catch-up test payload',
      senderKeyRing: senderRing,
      recipientEcdhPublicJwk: recipientRing.ecdhPublicJwk,
    });

    await createEphemeralMessage({
      id,
      senderId: 'test_sender_sweep',
      recipientId: 'test_recipient_sweep',
      ciphertext: encrypted.envelope.ciphertext,
      iv: encrypted.envelope.iv,
      signature: encrypted.envelope.signature,
      wrappedDek: encrypted.keyMaterial.wrappedDek,
      wrapIv: encrypted.keyMaterial.wrapIv,
      senderEcdhPubJwk: encrypted.envelope.senderEcdhPubJwk,
      senderEcdsaPubJwk: encrypted.envelope.senderEcdsaPubJwk,
      priority: 'MEDIUM',
      ttlSeconds: 60,
      isDemo: true,
    });

    vi.advanceTimersByTime(65_000);

    // Trigger concurrent sweeps simultaneously
    const [r1, r2] = await Promise.all([runEphemeralSweep(), runEphemeralSweep()]);
    const totalSwept = r1.sweptCount + r2.sweptCount;
    expect(totalSwept).toBeGreaterThanOrEqual(1);
    expect(r1.alreadyInFlight || r2.alreadyInFlight || r2.sweptCount === 0).toBe(true);

    const tombsForId = getEphemeralTombstones({ includeDemo: true, limit: 100 }).filter(
      (t) => t.id === id
    );
    expect(tombsForId.length).toBe(1);
    expect(tombsForId[0].reason).toBe('EXPIRED');

    // Simulate restart sweep on an already-overdue item created earlier
    const id2 = `unit_eph_restart_${Date.now()}`;
    const enc2 = await encryptAndWrapEphemeralMessage({
      id: id2,
      senderId: 'test_sender_sweep',
      recipientId: 'test_recipient_sweep',
      priority: 'LOW',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      readOnce: false,
      plaintext: 'Overdue restart item',
      senderKeyRing: senderRing,
      recipientEcdhPublicJwk: recipientRing.ecdhPublicJwk,
    });
    await createEphemeralMessage({
      id: id2,
      senderId: 'test_sender_sweep',
      recipientId: 'test_recipient_sweep',
      ciphertext: enc2.envelope.ciphertext,
      iv: enc2.envelope.iv,
      signature: enc2.envelope.signature,
      wrappedDek: enc2.keyMaterial.wrappedDek,
      wrapIv: enc2.keyMaterial.wrapIv,
      senderEcdhPubJwk: enc2.envelope.senderEcdhPubJwk,
      senderEcdsaPubJwk: enc2.envelope.senderEcdsaPubJwk,
      ttlSeconds: 60,
      isDemo: true,
    });
    vi.advanceTimersByTime(65_000);
    const restart = await simulateEphemeralServerRestart(Date.now());
    expect(restart.sweptIds).toContain(id2);
  });

  it('enforces read-once policy (allows 1st read + 10s grace, rejects 2nd read with 410) and keeps tombstones/logs leak-free', async () => {
    const senderRing = await generateEphemeralKeyRing('test_sender_ro');
    const recipientRing = await generateEphemeralKeyRing('test_recipient_ro');
    const id = `unit_eph_ro_${Date.now()}`;
    const secretCanary = 'ULTRA_SECRET_READ_ONCE_CANARY_9911';

    const encrypted = await encryptAndWrapEphemeralMessage({
      id,
      senderId: 'test_sender_ro',
      recipientId: 'test_recipient_ro',
      priority: 'CRITICAL',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      readOnce: true,
      plaintext: secretCanary,
      senderKeyRing: senderRing,
      recipientEcdhPublicJwk: recipientRing.ecdhPublicJwk,
    });

    await createEphemeralMessage({
      id,
      senderId: 'test_sender_ro',
      recipientId: 'test_recipient_ro',
      ciphertext: encrypted.envelope.ciphertext,
      iv: encrypted.envelope.iv,
      signature: encrypted.envelope.signature,
      wrappedDek: encrypted.keyMaterial.wrappedDek,
      wrapIv: encrypted.keyMaterial.wrapIv,
      senderEcdhPubJwk: encrypted.envelope.senderEcdhPubJwk,
      senderEcdsaPubJwk: encrypted.envelope.senderEcdsaPubJwk,
      priority: 'CRITICAL',
      ttlSeconds: 300,
      readOnce: true,
      isDemo: true,
    });

    // Attach associated delivery job to verify it cancels/expires upon burn
    const jobCreated = await createDeliveryJob({
      notificationId: id,
      userId: 'test_recipient_ro',
      priority: 'CRITICAL',
      isDemoJob: true,
      isEphemeral: true,
      ephemeralTtlSeconds: 300,
      ephemeralExpiresAt: new Date(Date.now() + 300_000).toISOString(),
    });
    expect(buildEphemeralGenericAlertText(300)).toContain('expires in 5 minutes');
    expect(buildEphemeralGenericAlertText(300)).not.toContain(secretCanary);

    // 1st read succeeds and tightens remaining window to READ_ONCE_GRACE_SECONDS (10s)
    const first = await readEphemeralMessage({ id, userId: 'test_recipient_ro' });
    expect(first.ok).toBe(true);
    expect(first.data?.envelope.remainingSeconds).toBeLessThanOrEqual(READ_ONCE_GRACE_SECONDS);

    // Decryption verifies even though expiresAt was tightened on READ_ONCE
    const dec = await verifyAndDecryptEphemeralMessage({
      envelope: first.data!.envelope,
      wrappedDek: first.data!.keyMaterial.wrappedDek,
      wrapIv: first.data!.keyMaterial.wrapIv,
      recipientEcdhPrivateKey: recipientRing.ecdhPrivateKey,
    });
    expect(dec.plaintext).toBe(secretCanary);
    dec.wipeHandle();

    // 2nd read fails immediately with 410 Gone and shreds item + expires delivery job
    const second = await readEphemeralMessage({ id, userId: 'test_recipient_ro' });
    expect(second.ok).toBe(false);
    expect(second.status).toBe(410);

    const postJob = await getDeliveryJobById(jobCreated.job.id);
    expect(postJob?.state).toBe('EXPIRED');

    // Audit tombstone & telemetry for zero leaks
    const tomb = getEphemeralTombstones({ includeDemo: true, limit: 50 }).find((t) => t.id === id);
    expect(tomb).toBeDefined();
    expect(tomb?.reason).toBe('READ_ONCE');
    expect((tomb as any).ciphertext).toBeUndefined();
    expect((tomb as any).wrappedDek).toBeUndefined();
    expect((tomb as any).plaintext).toBeUndefined();
    expect(JSON.stringify(tomb)).not.toContain(secretCanary);

    const events = getSecurityEvents({ limit: 100 });
    expect(JSON.stringify(events)).not.toContain(secretCanary);
    expect(JSON.stringify(events)).not.toContain('wrappedDek');
  });
});
