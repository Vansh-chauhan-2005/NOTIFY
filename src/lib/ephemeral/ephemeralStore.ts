import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import firebaseConfig from '../../../firebase-applet-config.json' with { type: 'json' };
import {
  computeExpiryTimestamps,
  getDefaultEphemeralTtlSeconds,
  MAX_EPHEMERAL_TTL_SECONDS,
  READ_ONCE_GRACE_SECONDS,
  validateAndResolveTtlSeconds,
  type EphemeralPriority,
  type EphemeralTombstoneReason,
} from './constants.js';
import type { EphemeralPublicBundle } from './crypto.js';
import { expireDeliveryJobsByNotificationId } from '../delivery/deliveryStore.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';
import { verifyEnvelopeOnServer } from '../provenance/store.js';
import type {
  ProvenanceEnvelopeV1,
  ProvenanceStatus,
  ProvenanceVerificationReport,
} from '../provenance/types.js';
import { wipeEphemeralDedupMetadata } from '../dedup/store.js';

const EPH_BASE_DIR = process.env.VITEST ? os.tmpdir() : process.cwd();
const EPH_TAG = process.env.VITEST ? `.vitest.${process.pid}` : '';
const EPHEMERAL_MESSAGES_FILE = path.resolve(EPH_BASE_DIR, `.aegis-ephemeral-messages${EPH_TAG}.json`);
const EPHEMERAL_KEYS_FILE = path.resolve(EPH_BASE_DIR, `.aegis-ephemeral-keys${EPH_TAG}.json`);
const EPHEMERAL_TOMBSTONES_FILE = path.resolve(EPH_BASE_DIR, `.aegis-ephemeral-tombstones${EPH_TAG}.json`);
const EPHEMERAL_PUBKEYS_FILE = path.resolve(EPH_BASE_DIR, `.aegis-ephemeral-pubkeys${EPH_TAG}.json`);

const MAX_TOMBSTONES = 500;
const EPHEMERAL_RATE_LIMIT_MAX = 30;
const EPHEMERAL_RATE_LIMIT_WINDOW_MS = 60_000;

export interface EphemeralMessageRecord {
  id: string;
  senderId: string;
  recipientId: string;
  ciphertext: string;
  iv: string;
  signature: string;
  priority: EphemeralPriority;
  createdAt: string;
  expiresAt: string;
  expireAt: string; // Firestore TTL policy field
  createdAtMs: number;
  expiresAtMs: number;
  ttlSeconds: number;
  status: 'ACTIVE' | 'READ' | 'BURNED' | 'EXPIRED';
  readOnce: boolean;
  readAt?: string | null;
  senderEcdhPubJwk: JsonWebKey;
  senderEcdsaPubJwk: JsonWebKey;
  provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
  provenanceReport?: ProvenanceVerificationReport | null;
  isDemo?: boolean;
}

export interface EphemeralKeyRecord {
  id: string; // matches EphemeralMessageRecord.id
  senderId: string;
  recipientId: string;
  wrappedDek: string;
  wrapIv: string;
  senderEcdhPubJwk: JsonWebKey;
  createdAt: string;
  expiresAt: string;
  expiresAtMs: number;
}

export interface EphemeralTombstoneRecord {
  id: string;
  senderId: string;
  recipientId: string;
  priority: EphemeralPriority;
  createdAt: string;
  expiredAt: string;
  lifetimeSeconds: number;
  reason: EphemeralTombstoneReason;
  provenanceKid?: string;
  provenanceResult?: ProvenanceStatus;
  isDemo?: boolean;
}

export interface EphemeralStatsSnapshot {
  activeCount: number;
  expiredTotalCount: number;
  expiredLast1hCount: number;
  burnedCount: number;
  readOnceBurnedCount: number;
  averageLifetimeSeconds: number;
  aboutToExpire: Array<{
    id: string;
    senderId: string;
    recipientId: string;
    priority: EphemeralPriority;
    status: string;
    readOnce: boolean;
    createdAt: string;
    expiresAt: string;
    remainingSeconds: number;
  }>;
  configuredDefaultTtlSeconds: number;
  serverMaxTtlSeconds: number;
  sweeperIntervalSeconds: number;
  sweeperActive: boolean;
  lastSweepAt: string | null;
  lastSweepCount: number;
}

declare global {
  var __aegisEphemeralMessagesMap: Map<string, EphemeralMessageRecord> | undefined;
  var __aegisEphemeralKeysMap: Map<string, EphemeralKeyRecord> | undefined;
  var __aegisEphemeralTombstonesList: EphemeralTombstoneRecord[] | undefined;
  var __aegisEphemeralPubKeysMap: Map<string, EphemeralPublicBundle> | undefined;
  var __aegisEphemeralHydrated: boolean | undefined;
  var __aegisEphemeralMutexPromise: Promise<void> | undefined;
  var __aegisEphemeralSweeperTimer: ReturnType<typeof setInterval> | undefined;
  var __aegisEphemeralSweepInFlight: boolean | undefined;
  var __aegisEphemeralLastSweepAt: string | null | undefined;
  var __aegisEphemeralLastSweepCount: number | undefined;
  var __aegisEphemeralRateLimiter: Map<string, number[]> | undefined;
}

export async function withEphemeralLock<T>(fn: () => Promise<T> | T): Promise<T> {
  const prev = global.__aegisEphemeralMutexPromise || Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  global.__aegisEphemeralMutexPromise = prev.then(() => next);
  await prev;
  try {
    return await fn();
  } finally {
    release();
  }
}

function safeReadJsonArray<T>(filePath: string): T[] {
  try {
    if (!fs.existsSync(filePath)) return [];
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function safeWriteJsonAtomic(filePath: string, data: unknown): void {
  try {
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, filePath);
  } catch {
    // Non-fatal on read-only environments
  }
}

function hydrateEphemeralStores(): {
  messages: Map<string, EphemeralMessageRecord>;
  keys: Map<string, EphemeralKeyRecord>;
  tombstones: EphemeralTombstoneRecord[];
  pubKeys: Map<string, EphemeralPublicBundle>;
} {
  if (!global.__aegisEphemeralMessagesMap) {
    global.__aegisEphemeralMessagesMap = new Map();
  }
  if (!global.__aegisEphemeralKeysMap) {
    global.__aegisEphemeralKeysMap = new Map();
  }
  if (!global.__aegisEphemeralTombstonesList) {
    global.__aegisEphemeralTombstonesList = [];
  }
  if (!global.__aegisEphemeralPubKeysMap) {
    global.__aegisEphemeralPubKeysMap = new Map();
  }

  if (!global.__aegisEphemeralHydrated) {
    global.__aegisEphemeralHydrated = true;

    const msgList = safeReadJsonArray<EphemeralMessageRecord>(EPHEMERAL_MESSAGES_FILE);
    for (const msg of msgList) {
      if (msg && typeof msg.id === 'string' && msg.ciphertext) {
        global.__aegisEphemeralMessagesMap.set(msg.id, msg);
      }
    }

    const keyList = safeReadJsonArray<EphemeralKeyRecord>(EPHEMERAL_KEYS_FILE);
    for (const keyRec of keyList) {
      if (keyRec && typeof keyRec.id === 'string' && keyRec.wrappedDek) {
        global.__aegisEphemeralKeysMap.set(keyRec.id, keyRec);
      }
    }

    const tombList = safeReadJsonArray<EphemeralTombstoneRecord>(EPHEMERAL_TOMBSTONES_FILE);
    global.__aegisEphemeralTombstonesList.push(...tombList.slice(-MAX_TOMBSTONES));

    const pubList = safeReadJsonArray<EphemeralPublicBundle>(EPHEMERAL_PUBKEYS_FILE);
    for (const pub of pubList) {
      if (pub && typeof pub.userId === 'string') {
        global.__aegisEphemeralPubKeysMap.set(pub.userId, pub);
      }
    }
  }

  return {
    messages: global.__aegisEphemeralMessagesMap,
    keys: global.__aegisEphemeralKeysMap,
    tombstones: global.__aegisEphemeralTombstonesList,
    pubKeys: global.__aegisEphemeralPubKeysMap,
  };
}

function persistMessagesOnly(): void {
  const { messages } = hydrateEphemeralStores();
  safeWriteJsonAtomic(EPHEMERAL_MESSAGES_FILE, Array.from(messages.values()));
}

function persistKeysOnly(): void {
  const { keys } = hydrateEphemeralStores();
  safeWriteJsonAtomic(EPHEMERAL_KEYS_FILE, Array.from(keys.values()));
}

function persistTombstonesOnly(): void {
  const { tombstones } = hydrateEphemeralStores();
  safeWriteJsonAtomic(EPHEMERAL_TOMBSTONES_FILE, tombstones.slice(-MAX_TOMBSTONES));
}

function persistPubKeysOnly(): void {
  const { pubKeys } = hydrateEphemeralStores();
  safeWriteJsonAtomic(EPHEMERAL_PUBKEYS_FILE, Array.from(pubKeys.values()));
}

export function normalizeEphemeralPriority(priority?: string): EphemeralPriority {
  const up = String(priority || 'HIGH').trim().toUpperCase();
  if (up === 'CRITICAL' || up === 'HIGH' || up === 'MEDIUM' || up === 'LOW') {
    return up;
  }
  return 'HIGH';
}

export function checkEphemeralCreateRateLimit(key: string, nowMs: number = Date.now()): {
  allowed: boolean;
  retryAfterSeconds: number;
} {
  if (!global.__aegisEphemeralRateLimiter) {
    global.__aegisEphemeralRateLimiter = new Map();
  }
  const map = global.__aegisEphemeralRateLimiter;
  const recent = (map.get(key) || []).filter((ts) => nowMs - ts < EPHEMERAL_RATE_LIMIT_WINDOW_MS);
  if (recent.length >= EPHEMERAL_RATE_LIMIT_MAX) {
    const oldest = recent[0] || nowMs;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((EPHEMERAL_RATE_LIMIT_WINDOW_MS - (nowMs - oldest)) / 1000)
    );
    map.set(key, recent);
    return { allowed: false, retryAfterSeconds };
  }
  recent.push(nowMs);
  map.set(key, recent);
  return { allowed: true, retryAfterSeconds: 0 };
}

export async function registerEphemeralPublicBundle(
  bundle: Omit<EphemeralPublicBundle, 'updatedAt'>
): Promise<EphemeralPublicBundle> {
  return await withEphemeralLock(() => {
    const { pubKeys } = hydrateEphemeralStores();
    const record: EphemeralPublicBundle = {
      userId: bundle.userId.slice(0, 128),
      ecdhPublicJwk: bundle.ecdhPublicJwk,
      ecdsaPublicJwk: bundle.ecdsaPublicJwk,
      updatedAt: new Date().toISOString(),
    };
    pubKeys.set(record.userId, record);
    persistPubKeysOnly();
    return structuredClone(record);
  });
}

export async function getEphemeralPublicBundle(
  userId: string
): Promise<EphemeralPublicBundle | null> {
  const { pubKeys } = hydrateEphemeralStores();
  const found = pubKeys.get(userId.slice(0, 128));
  return found ? structuredClone(found) : null;
}

/**
 * Best-effort authenticated Firestore REST sync for the isolated `ephemeralMessages` collection.
 * Notice `ephemeralKeys` is NEVER synced to client-writable Firestore collections.
 */
async function syncEphemeralMessageToFirestoreRest(
  record: EphemeralMessageRecord,
  firebaseIdToken?: string
): Promise<boolean> {
  if (!firebaseIdToken || !firebaseConfig?.projectId || !firebaseConfig?.firestoreDatabaseId) {
    return false;
  }
  const cleanId = record.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
  if (!cleanId) return false;

  const docUrl = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${firebaseConfig.firestoreDatabaseId}/documents/ephemeralMessages?documentId=${encodeURIComponent(cleanId)}`;
  try {
    const res = await fetch(docUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${firebaseIdToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        fields: {
          id: { stringValue: cleanId },
          senderId: { stringValue: record.senderId.slice(0, 128) },
          recipientId: { stringValue: record.recipientId.slice(0, 128) },
          ciphertext: { stringValue: record.ciphertext },
          iv: { stringValue: record.iv },
          signature: { stringValue: record.signature },
          priority: { stringValue: record.priority },
          createdAt: { timestampValue: record.createdAt },
          expiresAt: { timestampValue: record.expiresAt },
          expireAt: { timestampValue: record.expireAt },
          status: { stringValue: record.status },
          readOnce: { booleanValue: record.readOnce },
        },
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export interface CreateEphemeralMessageInput {
  id?: string;
  senderId: string;
  recipientId: string;
  ciphertext: string;
  iv: string;
  signature: string;
  wrappedDek: string;
  wrapIv: string;
  senderEcdhPubJwk: JsonWebKey;
  senderEcdsaPubJwk: JsonWebKey;
  provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
  requireEd25519Provenance?: boolean;
  priority?: string;
  ttlSeconds?: unknown;
  readOnce?: boolean;
  isDemo?: boolean;
  nowMs?: number;
  firebaseIdToken?: string;
}

export async function createEphemeralMessage(input: CreateEphemeralMessageInput): Promise<{
  ok: boolean;
  status: number;
  message: string;
  record?: EphemeralMessageRecord;
}> {
  const ttlValidation = validateAndResolveTtlSeconds(input.ttlSeconds, {
    allowDemoShortTtl: Boolean(input.isDemo),
  });

  if (!ttlValidation.valid) {
    return {
      ok: false,
      status: 400,
      message: ttlValidation.error || 'Invalid ephemeral TTL.',
    };
  }

  if (
    !input.ciphertext ||
    !input.iv ||
    !input.signature ||
    !input.wrappedDek ||
    !input.wrapIv ||
    !input.senderEcdhPubJwk ||
    !input.senderEcdsaPubJwk
  ) {
    return {
      ok: false,
      status: 400,
      message: 'Encrypted envelope (ciphertext, iv, signature, wrappedDek, wrapIv, sender public JWKs) is required.',
    };
  }

  // Reject oversized payloads safely
  if (input.ciphertext.length > 64_000 || input.wrappedDek.length > 4_096) {
    return {
      ok: false,
      status: 413,
      message: 'Encrypted payload exceeds maximum permitted size.',
    };
  }

  const nowMs = input.nowMs ?? Date.now();
  const { createdAtMs, createdAtIso, expiresAtMs, expiresAtIso } = computeExpiryTimestamps(
    nowMs,
    ttlValidation.ttlSeconds
  );

  const cleanId = (
    input.id?.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128) ||
    `eph_${nowMs.toString(36)}_${crypto.randomBytes(5).toString('hex')}`
  );
  const cleanPriority = normalizeEphemeralPriority(input.priority);

  let verifiedProvenanceReport: ProvenanceVerificationReport | null = null;
  if (input.provenanceEnvelope) {
    verifiedProvenanceReport = await verifyEnvelopeOnServer({
      envelope: input.provenanceEnvelope,
      expectedRecipientId: input.recipientId.slice(0, 128),
      expectedMessageId: cleanId,
      expectedCiphertext: input.ciphertext,
      expectedIv: input.iv,
      priority: cleanPriority,
      nowMs,
      enforceReplay: true,
      isDemo: Boolean(input.isDemo),
    });

    if (!verifiedProvenanceReport.verified) {
      return {
        ok: false,
        status: 403,
        message: `Ed25519 Provenance rejected [${verifiedProvenanceReport.status}]: ${verifiedProvenanceReport.reason}`,
      };
    }
  } else if (
    input.requireEd25519Provenance &&
    (cleanPriority === 'CRITICAL' || cleanPriority === 'HIGH')
  ) {
    const unsignedReport = await verifyEnvelopeOnServer({
      envelope: null,
      expectedRecipientId: input.recipientId.slice(0, 128),
      expectedMessageId: cleanId,
      priority: cleanPriority,
      nowMs,
      enforceReplay: false,
      isDemo: Boolean(input.isDemo),
    });
    return {
      ok: false,
      status: 403,
      message: `Zero-Trust Provenance [${unsignedReport.status}]: Ed25519 provenance envelope is required for ${cleanPriority} messages.`,
    };
  }

  const record: EphemeralMessageRecord = {
    id: cleanId,
    senderId: input.senderId.slice(0, 128),
    recipientId: input.recipientId.slice(0, 128),
    ciphertext: input.ciphertext,
    iv: input.iv,
    signature: input.signature,
    priority: cleanPriority,
    createdAt: createdAtIso,
    expiresAt: expiresAtIso,
    expireAt: expiresAtIso,
    createdAtMs,
    expiresAtMs,
    ttlSeconds: ttlValidation.ttlSeconds,
    status: 'ACTIVE',
    readOnce: Boolean(input.readOnce),
    readAt: null,
    senderEcdhPubJwk: input.senderEcdhPubJwk,
    senderEcdsaPubJwk: input.senderEcdsaPubJwk,
    ...(input.provenanceEnvelope ? { provenanceEnvelope: input.provenanceEnvelope } : {}),
    ...(verifiedProvenanceReport ? { provenanceReport: verifiedProvenanceReport } : {}),
    ...(input.isDemo ? { isDemo: true } : {}),
  };

  const keyRecord: EphemeralKeyRecord = {
    id: cleanId,
    senderId: record.senderId,
    recipientId: record.recipientId,
    wrappedDek: input.wrappedDek,
    wrapIv: input.wrapIv,
    senderEcdhPubJwk: input.senderEcdhPubJwk,
    createdAt: createdAtIso,
    expiresAt: expiresAtIso,
    expiresAtMs,
  };

  await withEphemeralLock(() => {
    const { messages, keys } = hydrateEphemeralStores();
    messages.set(cleanId, record);
    keys.set(cleanId, keyRecord);
    // Write to isolated storage only — NEVER audit logs or normal notifications
    persistMessagesOnly();
    persistKeysOnly();
  });

  if (input.firebaseIdToken) {
    void syncEphemeralMessageToFirestoreRest(record, input.firebaseIdToken);
  }

  logSecurityEvent({
    eventType: 'EPHEMERAL_CREATED',
    severity: 'info',
    result: 'success',
    userId: record.senderId,
    details: `Ephemeral item ${record.id} created (ttl=${record.ttlSeconds}s, readOnce=${record.readOnce}, priority=${record.priority}${record.isDemo ? ', DEMO' : ''}).`,
  });

  return {
    ok: true,
    status: 201,
    message: `Ephemeral item created (expires in ${record.ttlSeconds}s).`,
    record: structuredClone(record),
  };
}

/**
 * Crypto-shredding core routine executed inside the ephemeral lock.
 * Order of destruction is strict and verified by unit tests:
 *   1) Overwrite key fields in ephemeralKeys & delete key document
 *   2) Overwrite ciphertext/iv/signature in ephemeralMessages & delete document
 *   3) Record metadata-only tombstone (ZERO content, ciphertext, iv, signature, or keys)
 */
async function cryptoShredUnlocked(params: {
  id: string;
  reason: EphemeralTombstoneReason;
  nowMs: number;
  onStep?: (step: 'OVERWRITE_KEY' | 'DELETE_KEY' | 'OVERWRITE_DOC' | 'DELETE_DOC' | 'WRITE_TOMBSTONE') => void;
}): Promise<EphemeralTombstoneRecord | null> {
  const { messages, keys, tombstones } = hydrateEphemeralStores();
  const msg = messages.get(params.id);
  const keyRec = keys.get(params.id);

  if (!msg && !keyRec) {
    return null;
  }

  // Step 1: Overwrite & delete the encryption key FIRST (Crypto-Shredding)
  if (keyRec) {
    keyRec.wrappedDek = '';
    keyRec.wrapIv = '';
    params.onStep?.('OVERWRITE_KEY');
    keys.delete(params.id);
    params.onStep?.('DELETE_KEY');
    persistKeysOnly();
  } else {
    params.onStep?.('OVERWRITE_KEY');
    params.onStep?.('DELETE_KEY');
  }

  // Step 2: Overwrite & delete the ciphertext document SECOND
  let tombstone: EphemeralTombstoneRecord | null = null;
  if (msg) {
    const expiredAtIso = new Date(params.nowMs).toISOString();
    const lifetimeSeconds = Math.max(
      0,
      Math.round((params.nowMs - msg.createdAtMs) / 1000)
    );

    tombstone = {
      id: msg.id,
      senderId: msg.senderId,
      recipientId: msg.recipientId,
      priority: msg.priority,
      createdAt: msg.createdAt,
      expiredAt: expiredAtIso,
      lifetimeSeconds,
      reason: params.reason,
      ...(msg.provenanceEnvelope?.payload?.kid
        ? { provenanceKid: msg.provenanceEnvelope.payload.kid }
        : msg.provenanceReport?.kid
        ? { provenanceKid: msg.provenanceReport.kid }
        : {}),
      ...(msg.provenanceReport?.status
        ? { provenanceResult: msg.provenanceReport.status }
        : {}),
      ...(msg.isDemo ? { isDemo: true } : {}),
    };

    msg.ciphertext = '';
    msg.iv = '';
    msg.signature = '';
    msg.provenanceEnvelope = null;
    msg.provenanceReport = null;
    msg.status = params.reason === 'BURNED' ? 'BURNED' : 'EXPIRED';
    params.onStep?.('OVERWRITE_DOC');
    messages.delete(params.id);
    params.onStep?.('DELETE_DOC');
    persistMessagesOnly();
  } else {
    params.onStep?.('OVERWRITE_DOC');
    params.onStep?.('DELETE_DOC');
  }

  // Step 3: Append metadata-only tombstone
  if (tombstone && !tombstones.some((t) => t.id === tombstone!.id)) {
    tombstones.push(tombstone);
    if (tombstones.length > MAX_TOMBSTONES) {
      tombstones.splice(0, tombstones.length - MAX_TOMBSTONES);
    }
    params.onStep?.('WRITE_TOMBSTONE');
    persistTombstonesOnly();
  }

  return tombstone;
}

export async function cryptoShredEphemeralItem(params: {
  id: string;
  reason: EphemeralTombstoneReason;
  nowMs?: number;
  onStep?: (step: 'OVERWRITE_KEY' | 'DELETE_KEY' | 'OVERWRITE_DOC' | 'DELETE_DOC' | 'WRITE_TOMBSTONE') => void;
}): Promise<EphemeralTombstoneRecord | null> {
  const nowMs = params.nowMs ?? Date.now();
  const tombstone = await withEphemeralLock(() =>
    cryptoShredUnlocked({
      id: params.id,
      reason: params.reason,
      nowMs,
      onStep: params.onStep,
    })
  );

  // Immediately expire any pending multi-channel delivery jobs for this ephemeral item
  await expireDeliveryJobsByNotificationId(
    params.id,
    `Ephemeral item ${params.id} destroyed (${params.reason}); multi-channel fallback halted.`
  ).catch(() => 0);

  // Immediately wipe any ephemeral thread metadata / vector references
  wipeEphemeralDedupMetadata(tombstone?.recipientId, params.id);
  if (tombstone?.senderId && tombstone.senderId !== tombstone.recipientId) {
    wipeEphemeralDedupMetadata(tombstone.senderId, params.id);
  }

  return tombstone;
}

export async function listActiveEphemeralMessages(options: {
  userId: string;
  includeDemo?: boolean;
  nowMs?: number;
}): Promise<
  Array<
    Omit<EphemeralMessageRecord, 'ciphertext' | 'iv' | 'signature'> & {
      remainingSeconds: number;
    }
  >
> {
  const nowMs = options.nowMs ?? Date.now();
  const { messages } = hydrateEphemeralStores();
  const results: Array<
    Omit<EphemeralMessageRecord, 'ciphertext' | 'iv' | 'signature'> & {
      remainingSeconds: number;
    }
  > = [];

  for (const msg of messages.values()) {
    if (msg.status !== 'ACTIVE' && msg.status !== 'READ') continue;
    if (nowMs >= msg.expiresAtMs) continue;
    if (!options.includeDemo && msg.isDemo) continue;
    if (msg.senderId !== options.userId && msg.recipientId !== options.userId) continue;

    const { ciphertext: _c, iv: _i, signature: _s, ...metadata } = msg;
    const remainingSeconds = Math.max(0, Math.ceil((msg.expiresAtMs - nowMs) / 1000));
    results.push({
      ...structuredClone(metadata),
      remainingSeconds,
    });
  }

  results.sort((a, b) => a.expiresAtMs - b.expiresAtMs);
  return results;
}

export async function readEphemeralMessage(params: {
  id: string;
  userId: string;
  nowMs?: number;
}): Promise<{
  ok: boolean;
  status: number;
  message: string;
  data?: {
    envelope: {
      id: string;
      senderId: string;
      recipientId: string;
      priority: EphemeralPriority;
      ciphertext: string;
      iv: string;
      signature: string;
      createdAt: string;
      expiresAt: string;
      readOnce: boolean;
      status: string;
      senderEcdhPubJwk: JsonWebKey;
      senderEcdsaPubJwk: JsonWebKey;
      provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
      provenanceReport?: ProvenanceVerificationReport | null;
      remainingSeconds: number;
    };
    keyMaterial: {
      wrappedDek: string;
      wrapIv: string;
      senderEcdhPubJwk: JsonWebKey;
    };
  };
}> {
  const nowMs = params.nowMs ?? Date.now();

  const outcome = await withEphemeralLock(async () => {
    const { messages, keys } = hydrateEphemeralStores();
    const record = messages.get(params.id);
    const keyRec = keys.get(params.id);

    if (!record || !keyRec) {
      return { kind: 'GONE' as const, reason: 'already expired or burned' };
    }

    if (record.senderId !== params.userId && record.recipientId !== params.userId) {
      return { kind: 'FORBIDDEN' as const };
    }

    // Strict server-clock check (never trust client time)
    if (
      nowMs >= record.expiresAtMs ||
      record.status === 'EXPIRED' ||
      record.status === 'BURNED'
    ) {
      await cryptoShredUnlocked({
        id: record.id,
        reason: record.status === 'BURNED' ? 'BURNED' : 'EXPIRED',
        nowMs,
      });
      return { kind: 'EXPIRED_NOW' as const, recordId: record.id, userId: params.userId };
    }

    // Enforce single-read policy on subsequent fetches
    if (record.readOnce && record.status === 'READ') {
      await cryptoShredUnlocked({
        id: record.id,
        reason: 'READ_ONCE',
        nowMs,
      });
      return { kind: 'READ_ONCE_EXHAUSTED' as const, recordId: record.id, userId: params.userId };
    }

    // Valid authorized read within lifetime
    if (record.readOnce && record.status === 'ACTIVE') {
      record.status = 'READ';
      record.readAt = new Date(nowMs).toISOString();
      const graceExpiresMs = Math.min(
        record.expiresAtMs,
        nowMs + READ_ONCE_GRACE_SECONDS * 1000
      );
      record.expiresAtMs = graceExpiresMs;
      record.expiresAt = new Date(graceExpiresMs).toISOString();
      record.expireAt = record.expiresAt;
      persistMessagesOnly();
    }

    const remainingSeconds = Math.max(0, Math.ceil((record.expiresAtMs - nowMs) / 1000));

    return {
      kind: 'OK' as const,
      envelope: {
        id: record.id,
        senderId: record.senderId,
        recipientId: record.recipientId,
        priority: record.priority,
        ciphertext: record.ciphertext,
        iv: record.iv,
        signature: record.signature,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        readOnce: record.readOnce,
        status: record.status,
        senderEcdhPubJwk: structuredClone(record.senderEcdhPubJwk),
        senderEcdsaPubJwk: structuredClone(record.senderEcdsaPubJwk),
        provenanceEnvelope: record.provenanceEnvelope
          ? structuredClone(record.provenanceEnvelope)
          : null,
        provenanceReport: record.provenanceReport
          ? structuredClone(record.provenanceReport)
          : null,
        remainingSeconds,
      },
      keyMaterial: {
        wrappedDek: keyRec.wrappedDek,
        wrapIv: keyRec.wrapIv,
        senderEcdhPubJwk: structuredClone(keyRec.senderEcdhPubJwk),
      },
      readOnce: record.readOnce,
      isDemo: Boolean(record.isDemo),
    };
  });

  if (outcome.kind === 'FORBIDDEN') {
    return {
      ok: false,
      status: 403,
      message: 'Forbidden: only the sender or recipient may access this ephemeral item.',
    };
  }

  if (outcome.kind === 'GONE') {
    logSecurityEvent({
      eventType: 'EPHEMERAL_ACCESS_DENIED_EXPIRED',
      severity: 'warning',
      result: 'blocked',
      userId: params.userId,
      details: `Rejected access to ephemeral item ${params.id} (410 Gone: ${outcome.reason}).`,
    });
    return {
      ok: false,
      status: 410,
      message: 'Ephemeral item has expired or been crypto-shredded and is permanently unreadable.',
    };
  }

  if (outcome.kind === 'EXPIRED_NOW' || outcome.kind === 'READ_ONCE_EXHAUSTED') {
    await expireDeliveryJobsByNotificationId(
      params.id,
      `Ephemeral item ${params.id} expired/consumed during read; delivery job expired.`
    ).catch(() => 0);

    logSecurityEvent({
      eventType: 'EPHEMERAL_ACCESS_DENIED_EXPIRED',
      severity: 'warning',
      result: 'blocked',
      userId: params.userId,
      details:
        outcome.kind === 'READ_ONCE_EXHAUSTED'
          ? `Blocked second read of read-once ephemeral item ${params.id} (410 Gone).`
          : `Blocked expired read attempt for ephemeral item ${params.id} via server clock (410 Gone).`,
    });
    return {
      ok: false,
      status: 410,
      message:
        outcome.kind === 'READ_ONCE_EXHAUSTED'
          ? 'This read-once ephemeral item has already been viewed and crypto-shredded.'
          : 'Ephemeral item TTL expired (server time) and was crypto-shredded.',
    };
  }

  logSecurityEvent({
    eventType: 'EPHEMERAL_READ',
    severity: 'info',
    result: 'success',
    userId: params.userId,
    details: `Ephemeral item ${outcome.envelope.id} decrypted key material fetched (readOnce=${outcome.readOnce}${outcome.isDemo ? ', DEMO' : ''}).`,
  });

  return {
    ok: true,
    status: 200,
    message: outcome.readOnce
      ? `Ephemeral item loaded (Read-Once active: self-destructs in ${READ_ONCE_GRACE_SECONDS}s).`
      : 'Ephemeral item loaded.',
    data: {
      envelope: outcome.envelope,
      keyMaterial: outcome.keyMaterial,
    },
  };
}

export async function burnEphemeralMessage(params: {
  id: string;
  userId: string;
  nowMs?: number;
}): Promise<{
  ok: boolean;
  status: number;
  message: string;
  tombstone?: EphemeralTombstoneRecord | null;
}> {
  const nowMs = params.nowMs ?? Date.now();
  const { messages } = hydrateEphemeralStores();
  const existing = messages.get(params.id);

  if (!existing) {
    return {
      ok: false,
      status: 410,
      message: 'Ephemeral item is already burned or expired.',
    };
  }

  if (existing.senderId !== params.userId && existing.recipientId !== params.userId) {
    return {
      ok: false,
      status: 403,
      message: 'Forbidden: only the sender or recipient can burn this ephemeral item.',
    };
  }

  const tombstone = await cryptoShredEphemeralItem({
    id: params.id,
    reason: 'BURNED',
    nowMs,
  });

  logSecurityEvent({
    eventType: 'EPHEMERAL_BURNED',
    severity: 'info',
    result: 'success',
    userId: params.userId,
    details: `Ephemeral item ${params.id} manually burned (crypto-shredded before TTL).`,
  });

  return {
    ok: true,
    status: 200,
    message: 'Ephemeral item immediately crypto-shredded and burned.',
    tombstone,
  };
}

/**
 * Idempotent sweeper deleting all expired ephemeral items in ephemeralMessages + ephemeralKeys
 * and writing metadata-only tombstones. Safe under concurrent triggers.
 */
export async function runEphemeralSweep(nowMs: number = Date.now()): Promise<{
  sweptCount: number;
  sweptIds: string[];
  alreadyInFlight: boolean;
}> {
  if (global.__aegisEphemeralSweepInFlight) {
    return { sweptCount: 0, sweptIds: [], alreadyInFlight: true };
  }

  global.__aegisEphemeralSweepInFlight = true;
  try {
    const sweptItems: Array<{ id: string; senderId: string; reason: EphemeralTombstoneReason; isDemo?: boolean }> = [];

    await withEphemeralLock(async () => {
      const { messages, keys } = hydrateEphemeralStores();
      const dueIds = new Set<string>();

      for (const msg of messages.values()) {
        if (nowMs >= msg.expiresAtMs || msg.status === 'EXPIRED' || msg.status === 'BURNED') {
          dueIds.add(msg.id);
        }
      }
      for (const keyRec of keys.values()) {
        if (nowMs >= keyRec.expiresAtMs || !messages.has(keyRec.id)) {
          dueIds.add(keyRec.id);
        }
      }

      for (const id of dueIds) {
        const msg = messages.get(id);
        const reason: EphemeralTombstoneReason =
          msg?.readOnce && msg.status === 'READ' ? 'READ_ONCE' : 'EXPIRED';
        const tombstone = await cryptoShredUnlocked({ id, reason, nowMs });
        if (tombstone) {
          sweptItems.push({
            id: tombstone.id,
            senderId: tombstone.senderId,
            reason: tombstone.reason,
            isDemo: tombstone.isDemo,
          });
        }
      }
    });

    for (const item of sweptItems) {
      await expireDeliveryJobsByNotificationId(
        item.id,
        `Ephemeral sweeper expired item ${item.id} (${item.reason}).`
      ).catch(() => 0);

      logSecurityEvent({
        eventType: 'EPHEMERAL_EXPIRED',
        severity: 'info',
        result: 'success',
        userId: item.senderId,
        details: `Ephemeral item ${item.id} expired and crypto-shredded (${item.reason}${item.isDemo ? ', DEMO' : ''}).`,
      });
    }

    global.__aegisEphemeralLastSweepAt = new Date(nowMs).toISOString();
    global.__aegisEphemeralLastSweepCount = sweptItems.length;

    if (sweptItems.length > 0) {
      logSecurityEvent({
        eventType: 'EPHEMERAL_SWEEP_RUN',
        severity: 'info',
        result: 'success',
        details: `Ephemeral sweeper crypto-shredded ${sweptItems.length} overdue item(s).`,
      });
    }

    return {
      sweptCount: sweptItems.length,
      sweptIds: sweptItems.map((i) => i.id),
      alreadyInFlight: false,
    };
  } finally {
    global.__aegisEphemeralSweepInFlight = false;
  }
}

export function startEphemeralSweeperLoop(intervalMs: number = 5000): void {
  if (global.__aegisEphemeralSweeperTimer) {
    return;
  }
  // Immediate startup catch-up sweep for items that expired while server was offline
  void runEphemeralSweep(Date.now());
  console.log(`[Ephemeral Sweeper] Starting 4-layer TTL sweeper (interval=${intervalMs}ms)`);
  global.__aegisEphemeralSweeperTimer = setInterval(() => {
    void runEphemeralSweep(Date.now());
  }, intervalMs);
}

/**
 * Simulates a server restart by clearing in-memory Maps, re-hydrating from isolated JSON stores,
 * and executing a startup catch-up sweep at `nowMs`.
 */
export async function simulateEphemeralServerRestart(nowMs: number = Date.now()): Promise<{
  reloadedMessagesCount: number;
  reloadedKeysCount: number;
  sweptCount: number;
  sweptIds: string[];
}> {
  global.__aegisEphemeralMessagesMap = undefined;
  global.__aegisEphemeralKeysMap = undefined;
  global.__aegisEphemeralTombstonesList = undefined;
  global.__aegisEphemeralHydrated = false;

  const { messages, keys } = hydrateEphemeralStores();
  const reloadedMessagesCount = messages.size;
  const reloadedKeysCount = keys.size;
  const sweepResult = await runEphemeralSweep(nowMs);

  return {
    reloadedMessagesCount,
    reloadedKeysCount,
    sweptCount: sweepResult.sweptCount,
    sweptIds: sweepResult.sweptIds,
  };
}

export function getEphemeralTombstones(options: {
  includeDemo?: boolean;
  limit?: number;
} = {}): EphemeralTombstoneRecord[] {
  const { tombstones } = hydrateEphemeralStores();
  const limit = Math.min(200, Math.max(1, Number(options.limit) || 100));
  let list = tombstones.slice();
  if (options.includeDemo === false) {
    list = list.filter((t) => !t.isDemo);
  }
  return list
    .sort((a, b) => Date.parse(b.expiredAt) - Date.parse(a.expiredAt))
    .slice(0, limit)
    .map((t) => structuredClone(t));
}

export function getEphemeralStats(nowMs: number = Date.now()): EphemeralStatsSnapshot {
  const { messages, tombstones } = hydrateEphemeralStores();
  const oneHourAgo = nowMs - 3_600_000;

  const activeItems: EphemeralMessageRecord[] = [];
  for (const msg of messages.values()) {
    if ((msg.status === 'ACTIVE' || msg.status === 'READ') && msg.expiresAtMs > nowMs) {
      activeItems.push(msg);
    }
  }

  let expiredLast1hCount = 0;
  let burnedCount = 0;
  let readOnceBurnedCount = 0;
  let lifetimeSum = 0;

  for (const t of tombstones) {
    const expMs = Date.parse(t.expiredAt);
    if (Number.isFinite(expMs) && expMs >= oneHourAgo) {
      expiredLast1hCount += 1;
    }
    if (t.reason === 'BURNED') {
      burnedCount += 1;
    } else if (t.reason === 'READ_ONCE') {
      readOnceBurnedCount += 1;
    }
    lifetimeSum += Math.max(0, Number(t.lifetimeSeconds) || 0);
  }

  const averageLifetimeSeconds =
    tombstones.length > 0 ? Math.round(lifetimeSum / tombstones.length) : 0;

  const aboutToExpire = activeItems
    .slice()
    .sort((a, b) => a.expiresAtMs - b.expiresAtMs)
    .slice(0, 8)
    .map((m) => ({
      id: m.id,
      senderId: m.senderId,
      recipientId: m.recipientId,
      priority: m.priority,
      status: m.status,
      readOnce: m.readOnce,
      createdAt: m.createdAt,
      expiresAt: m.expiresAt,
      remainingSeconds: Math.max(0, Math.ceil((m.expiresAtMs - nowMs) / 1000)),
    }));

  return {
    activeCount: activeItems.length,
    expiredTotalCount: tombstones.length,
    expiredLast1hCount,
    burnedCount,
    readOnceBurnedCount,
    averageLifetimeSeconds,
    aboutToExpire,
    configuredDefaultTtlSeconds: getDefaultEphemeralTtlSeconds(),
    serverMaxTtlSeconds: MAX_EPHEMERAL_TTL_SECONDS,
    sweeperIntervalSeconds: 5,
    sweeperActive: Boolean(global.__aegisEphemeralSweeperTimer),
    lastSweepAt: global.__aegisEphemeralLastSweepAt || null,
    lastSweepCount: global.__aegisEphemeralLastSweepCount || 0,
  };
}

/**
 * Test helper (used only by Ephemeral unit tests / isolated simulator inspection).
 */
export function __getRawIsolatedCountsForTest(): {
  messagesCount: number;
  keysCount: number;
  tombstonesCount: number;
  hasMessage: (id: string) => boolean;
  hasKey: (id: string) => boolean;
} {
  const { messages, keys, tombstones } = hydrateEphemeralStores();
  return {
    messagesCount: messages.size,
    keysCount: keys.size,
    tombstonesCount: tombstones.length,
    hasMessage: (id: string) => messages.has(id),
    hasKey: (id: string) => keys.has(id),
  };
}
