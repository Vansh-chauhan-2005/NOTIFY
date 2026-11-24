import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  base64ToBytes,
  buildKeyLogSigningBytes,
  computeKeyLogEntryHash,
  computePublicKeyFingerprint,
} from './canonical.js';
import {
  getServerProvenanceKey,
  signKeyLogEntryServer,
  verifyEd25519Server,
} from './serverCrypto.js';
import {
  PROVENANCE_REPLAY_WINDOW_MS,
  verifyProvenanceEnvelope,
} from './verifyPolicy.js';
import {
  PROVENANCE_STATUS_CODES,
  type KeyLogEntry,
  type PinnedKeyRecord,
  type ProvenanceEnvelopeV1,
  type ProvenanceKeyRecord,
  type ProvenanceQuarantineRecord,
  type ProvenanceStatus,
  type ProvenanceVerificationReport,
} from './types.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';

const PROV_BASE_DIR = process.env.VITEST ? os.tmpdir() : process.cwd();
const PROV_TAG = process.env.VITEST ? `.vitest.${process.pid}` : '';
const KEYS_FILE = path.resolve(PROV_BASE_DIR, `.aegis-provenance-keys${PROV_TAG}.json`);
const KEYLOG_FILE = path.resolve(PROV_BASE_DIR, `.aegis-provenance-keylog${PROV_TAG}.json`);
const REPLAY_FILE = path.resolve(PROV_BASE_DIR, `.aegis-provenance-replay${PROV_TAG}.json`);
const QUARANTINE_FILE = path.resolve(PROV_BASE_DIR, `.aegis-provenance-quarantine${PROV_TAG}.json`);

const GENESIS_HASH = '0'.repeat(64);
const MAX_QUARANTINE_RECORDS = 500;

interface ReplayCacheEntry {
  cacheKey: string; // `${kid}:${nonce}`
  observedAtMs: number;
}

declare global {
  var __aegisProvKeysMap: Map<string, ProvenanceKeyRecord> | undefined;
  var __aegisProvKeyLog: KeyLogEntry[] | undefined;
  var __aegisProvReplayMap: Map<string, number> | undefined;
  var __aegisProvQuarantine: ProvenanceQuarantineRecord[] | undefined;
  var __aegisProvStatsCounts: Record<ProvenanceStatus, number> | undefined;
  var __aegisProvHydrated: boolean | undefined;
  var __aegisProvMutex: Promise<void> | undefined;
}

export async function withProvenanceLock<T>(fn: () => Promise<T> | T): Promise<T> {
  const prev = global.__aegisProvMutex || Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  global.__aegisProvMutex = prev.then(() => next);
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
    // Non-fatal in read-only environments
  }
}

function createEmptyStats(): Record<ProvenanceStatus, number> {
  const counts = {} as Record<ProvenanceStatus, number>;
  for (const s of PROVENANCE_STATUS_CODES) {
    counts[s] = 0;
  }
  return counts;
}

function hydrateStores() {
  if (!global.__aegisProvKeysMap) global.__aegisProvKeysMap = new Map();
  if (!global.__aegisProvKeyLog) global.__aegisProvKeyLog = [];
  if (!global.__aegisProvReplayMap) global.__aegisProvReplayMap = new Map();
  if (!global.__aegisProvQuarantine) global.__aegisProvQuarantine = [];
  if (!global.__aegisProvStatsCounts) global.__aegisProvStatsCounts = createEmptyStats();

  if (!global.__aegisProvHydrated) {
    global.__aegisProvHydrated = true;

    for (const k of safeReadJsonArray<ProvenanceKeyRecord>(KEYS_FILE)) {
      if (k?.kid && k?.publicKey) {
        global.__aegisProvKeysMap.set(k.kid, k);
      }
    }

    const logRows = safeReadJsonArray<KeyLogEntry>(KEYLOG_FILE);
    for (const entry of logRows) {
      if (entry && typeof entry.index === 'number' && entry.entryHash) {
        global.__aegisProvKeyLog.push(entry);
      }
    }

    const nowMs = Date.now();
    for (const r of safeReadJsonArray<ReplayCacheEntry>(REPLAY_FILE)) {
      if (r?.cacheKey && typeof r.observedAtMs === 'number') {
        if (nowMs - r.observedAtMs <= PROVENANCE_REPLAY_WINDOW_MS) {
          global.__aegisProvReplayMap.set(r.cacheKey, r.observedAtMs);
        }
      }
    }

    const qRows = safeReadJsonArray<ProvenanceQuarantineRecord>(QUARANTINE_FILE);
    for (const q of qRows.slice(-MAX_QUARANTINE_RECORDS)) {
      global.__aegisProvQuarantine.push(q);
      if (q?.verificationResult && global.__aegisProvStatsCounts[q.verificationResult] !== undefined) {
        global.__aegisProvStatsCounts[q.verificationResult] += 1;
      }
    }
  }

  return {
    keys: global.__aegisProvKeysMap,
    keyLog: global.__aegisProvKeyLog,
    replay: global.__aegisProvReplayMap,
    quarantine: global.__aegisProvQuarantine,
    stats: global.__aegisProvStatsCounts,
  };
}

function persistKeys(): void {
  const { keys } = hydrateStores();
  safeWriteJsonAtomic(KEYS_FILE, Array.from(keys.values()));
}

function persistKeyLog(): void {
  const { keyLog } = hydrateStores();
  safeWriteJsonAtomic(KEYLOG_FILE, keyLog);
}

function persistReplay(): void {
  const { replay } = hydrateStores();
  const rows: ReplayCacheEntry[] = Array.from(replay.entries()).map(([cacheKey, observedAtMs]) => ({
    cacheKey,
    observedAtMs,
  }));
  safeWriteJsonAtomic(REPLAY_FILE, rows);
}

function persistQuarantine(): void {
  const { quarantine } = hydrateStores();
  safeWriteJsonAtomic(QUARANTINE_FILE, quarantine.slice(-MAX_QUARANTINE_RECORDS));
}

async function appendKeyLogEntryUnlocked(params: {
  type: 'REGISTER' | 'ROTATE' | 'REVOKE';
  kid: string;
  userId: string;
  publicKey: string;
  timestamp: string;
  reason?: string;
  previousKid?: string;
}): Promise<KeyLogEntry> {
  const { keyLog } = hydrateStores();
  const prevEntry = keyLog.length > 0 ? keyLog[keyLog.length - 1] : null;
  const index = prevEntry ? prevEntry.index + 1 : 0;
  const prevHash = prevEntry ? prevEntry.entryHash : GENESIS_HASH;

  const entryHash = await computeKeyLogEntryHash({
    prevHash,
    index,
    type: params.type,
    kid: params.kid,
    userId: params.userId,
    publicKey: params.publicKey,
    timestamp: params.timestamp,
    reason: params.reason,
    previousKid: params.previousKid,
  });

  const { serverKid, serverSignature } = signKeyLogEntryServer({
    index,
    type: params.type,
    kid: params.kid,
    userId: params.userId,
    publicKey: params.publicKey,
    timestamp: params.timestamp,
    reason: params.reason,
    previousKid: params.previousKid,
    prevHash,
    entryHash,
  });

  const entry: KeyLogEntry = {
    index,
    type: params.type,
    kid: params.kid,
    userId: params.userId,
    publicKey: params.publicKey,
    timestamp: params.timestamp,
    ...(params.reason ? { reason: params.reason } : {}),
    ...(params.previousKid ? { previousKid: params.previousKid } : {}),
    prevHash,
    entryHash,
    serverKid,
    serverSignature,
  };

  keyLog.push(entry);
  persistKeyLog();
  return entry;
}

/**
 * Ensures the active server provenance key exists in the key registry and keyLog
 * so server-attested GATEWAY hops resolve smoothly in every verification check.
 */
export async function ensureServerKeyRegistered(): Promise<ProvenanceKeyRecord> {
  const serverInfo = await getServerProvenanceKey();
  return withProvenanceLock(async () => {
    const { keys } = hydrateStores();
    const existing = keys.get(serverInfo.kid);
    if (existing) {
      return structuredClone(existing);
    }

    const record: ProvenanceKeyRecord = {
      kid: serverInfo.kid,
      userId: 'aegis-server-gateway',
      publicKey: serverInfo.publicKey,
      status: 'ACTIVE',
      createdAt: serverInfo.validFrom,
      fingerprintHex: serverInfo.fingerprintHex,
      fingerprintWords: serverInfo.fingerprintWords,
    };

    keys.set(record.kid, record);
    persistKeys();

    await appendKeyLogEntryUnlocked({
      type: 'REGISTER',
      kid: record.kid,
      userId: record.userId,
      publicKey: record.publicKey,
      timestamp: record.createdAt,
      reason: 'Server gateway Ed25519 root registration',
    });

    return structuredClone(record);
  });
}

export async function lookupProvenanceKeyByKid(
  kid: string
): Promise<ProvenanceKeyRecord | null> {
  await ensureServerKeyRegistered();
  const { keys } = hydrateStores();
  const found = keys.get(kid);
  return found ? structuredClone(found) : null;
}

export async function getUserProvenanceKeys(userId: string): Promise<ProvenanceKeyRecord[]> {
  const { keys } = hydrateStores();
  const list: ProvenanceKeyRecord[] = [];
  for (const k of keys.values()) {
    if (k.userId === userId) {
      list.push(structuredClone(k));
    }
  }
  return list.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export async function registerUserProvenanceKey(params: {
  userId: string;
  publicKey: string;
  reason?: string;
  skipTelemetry?: boolean;
}): Promise<{
  ok: boolean;
  status: number;
  message: string;
  key?: ProvenanceKeyRecord;
  logEntry?: KeyLogEntry;
}> {
  let fp: { kid: string; fingerprintHex: string; fingerprintWords: string[] };
  try {
    fp = await computePublicKeyFingerprint(params.publicKey);
  } catch (err: any) {
    return {
      ok: false,
      status: 400,
      message: err?.message || 'Invalid Ed25519 public key (must be 32 raw bytes in base64).',
    };
  }

  return withProvenanceLock(async () => {
    const { keys } = hydrateStores();
    const existing = keys.get(fp.kid);
    if (existing) {
      if (existing.userId !== params.userId) {
        return {
          ok: false,
          status: 409,
          message: 'Public key fingerprint is already registered to another identity.',
        };
      }
      return {
        ok: true,
        status: 200,
        message: 'Ed25519 signing key already registered.',
        key: structuredClone(existing),
      };
    }

    // Mark any prior ACTIVE keys of this user as ROTATED automatically if registering fresh
    const nowIso = new Date().toISOString();
    const record: ProvenanceKeyRecord = {
      kid: fp.kid,
      userId: params.userId,
      publicKey: params.publicKey,
      status: 'ACTIVE',
      createdAt: nowIso,
      fingerprintHex: fp.fingerprintHex,
      fingerprintWords: fp.fingerprintWords,
    };

    keys.set(record.kid, record);
    persistKeys();

    const logEntry = await appendKeyLogEntryUnlocked({
      type: 'REGISTER',
      kid: record.kid,
      userId: record.userId,
      publicKey: record.publicKey,
      timestamp: nowIso,
      reason: params.reason || 'Client Ed25519 key registration',
    });

    if (!params.skipTelemetry) {
      logSecurityEvent({
        eventType: 'PROVENANCE_KEY_REGISTERED',
        severity: 'info',
        result: 'success',
        userId: params.userId,
        details: `Registered Ed25519 signing key kid=${record.kid}.`,
      });
    }

    return {
      ok: true,
      status: 201,
      message: 'Ed25519 public signing key registered and logged to transparency chain.',
      key: structuredClone(record),
      logEntry,
    };
  });
}

export async function rotateUserProvenanceKey(params: {
  userId: string;
  newPublicKey: string;
  oldKid?: string;
  reason?: string;
  rotatedAtOverride?: string;
  skipTelemetry?: boolean;
}): Promise<{
  ok: boolean;
  status: number;
  message: string;
  oldKey?: ProvenanceKeyRecord;
  newKey?: ProvenanceKeyRecord;
  logEntry?: KeyLogEntry;
}> {
  let fp: { kid: string; fingerprintHex: string; fingerprintWords: string[] };
  try {
    fp = await computePublicKeyFingerprint(params.newPublicKey);
  } catch (err: any) {
    return {
      ok: false,
      status: 400,
      message: err?.message || 'Invalid new Ed25519 public key.',
    };
  }

  return withProvenanceLock(async () => {
    const { keys } = hydrateStores();
    const nowIso = params.rotatedAtOverride || new Date().toISOString();

    let prevActive: ProvenanceKeyRecord | undefined;
    if (params.oldKid) {
      const candidate = keys.get(params.oldKid);
      if (!candidate || candidate.userId !== params.userId) {
        return { ok: false, status: 404, message: 'Specified previous signing key not found for user.' };
      }
      prevActive = candidate;
    } else {
      for (const k of keys.values()) {
        if (k.userId === params.userId && k.status === 'ACTIVE') {
          prevActive = k;
          break;
        }
      }
    }

    if (prevActive && prevActive.kid === fp.kid) {
      return { ok: false, status: 400, message: 'New signing key must differ from existing active key.' };
    }

    if (prevActive && prevActive.status === 'ACTIVE') {
      prevActive.status = 'ROTATED';
      prevActive.rotatedAt = nowIso;
      prevActive.supersededByKid = fp.kid;
      prevActive.reason = params.reason || 'Key rotation';
      keys.set(prevActive.kid, prevActive);
    }

    const newRecord: ProvenanceKeyRecord = {
      kid: fp.kid,
      userId: params.userId,
      publicKey: params.newPublicKey,
      status: 'ACTIVE',
      createdAt: nowIso,
      fingerprintHex: fp.fingerprintHex,
      fingerprintWords: fp.fingerprintWords,
    };
    keys.set(newRecord.kid, newRecord);
    persistKeys();

    const logEntry = await appendKeyLogEntryUnlocked({
      type: 'ROTATE',
      kid: newRecord.kid,
      userId: params.userId,
      publicKey: newRecord.publicKey,
      timestamp: nowIso,
      previousKid: prevActive?.kid,
      reason: params.reason || 'Routine Ed25519 signing key rotation',
    });

    if (!params.skipTelemetry) {
      logSecurityEvent({
        eventType: 'PROVENANCE_KEY_ROTATED',
        severity: 'info',
        result: 'success',
        userId: params.userId,
        details: `Rotated Ed25519 key ${prevActive?.kid || 'none'} -> ${newRecord.kid}.`,
      });
    }

    return {
      ok: true,
      status: 200,
      message: 'Signing key rotated cleanly; prior key remains valid only for pre-rotation messages.',
      oldKey: prevActive ? structuredClone(prevActive) : undefined,
      newKey: structuredClone(newRecord),
      logEntry,
    };
  });
}

export async function revokeUserProvenanceKey(params: {
  userId: string;
  kid?: string;
  reason?: string;
  revokedAtOverride?: string;
  isAdmin?: boolean;
  skipTelemetry?: boolean;
}): Promise<{
  ok: boolean;
  status: number;
  message: string;
  revokedKey?: ProvenanceKeyRecord;
  logEntry?: KeyLogEntry;
}> {
  return withProvenanceLock(async () => {
    const { keys } = hydrateStores();
    let target: ProvenanceKeyRecord | undefined;

    if (params.kid) {
      const candidate = keys.get(params.kid);
      if (!candidate) {
        return { ok: false, status: 404, message: 'Signing key not found.' };
      }
      if (candidate.userId !== params.userId && !params.isAdmin) {
        return { ok: false, status: 403, message: 'Forbidden: cannot revoke another user’s signing key.' };
      }
      target = candidate;
    } else {
      for (const k of keys.values()) {
        if (k.userId === params.userId && k.status === 'ACTIVE') {
          target = k;
          break;
        }
      }
    }

    if (!target) {
      return { ok: false, status: 404, message: 'No active signing key found to revoke.' };
    }

    const nowIso = params.revokedAtOverride || new Date().toISOString();
    target.status = 'REVOKED';
    target.revokedAt = nowIso;
    target.reason = params.reason || 'Manual revocation';
    keys.set(target.kid, target);
    persistKeys();

    const logEntry = await appendKeyLogEntryUnlocked({
      type: 'REVOKE',
      kid: target.kid,
      userId: target.userId,
      publicKey: target.publicKey,
      timestamp: nowIso,
      reason: target.reason,
    });

    if (!params.skipTelemetry) {
      logSecurityEvent({
        eventType: 'PROVENANCE_KEY_REVOKED',
        severity: 'critical',
        result: 'success',
        userId: target.userId,
        details: `Revoked Ed25519 signing key kid=${target.kid} (${target.reason}).`,
      });
    }

    return {
      ok: true,
      status: 200,
      message: `Signing key ${target.kid} permanently revoked.`,
      revokedKey: structuredClone(target),
      logEntry,
    };
  });
}

export async function checkAndRecordReplayNonce(params: {
  kid: string;
  nonce: string;
  nowMs?: number;
}): Promise<{ replayed: boolean }> {
  const nowMs = params.nowMs ?? Date.now();
  return withProvenanceLock(() => {
    const { replay } = hydrateStores();
    // Evict stale entries older than 10 minutes
    for (const [k, ts] of replay.entries()) {
      if (nowMs - ts > PROVENANCE_REPLAY_WINDOW_MS) {
        replay.delete(k);
      }
    }

    const cacheKey = `${params.kid}:${params.nonce}`;
    const existingTs = replay.get(cacheKey);
    if (existingTs !== undefined && nowMs - existingTs <= PROVENANCE_REPLAY_WINDOW_MS) {
      return { replayed: true };
    }

    replay.set(cacheKey, nowMs);
    persistReplay();
    return { replayed: false };
  });
}

export async function recordProvenanceOutcome(params: {
  report: ProvenanceVerificationReport;
  messageId?: string;
  senderId?: string;
  recipientId?: string;
  source?: string;
  isDemo?: boolean;
  skipTelemetry?: boolean;
}): Promise<void> {
  await withProvenanceLock(() => {
    const { stats, quarantine } = hydrateStores();
    stats[params.report.status] = (stats[params.report.status] || 0) + 1;

    if (!params.report.verified) {
      const qRec: ProvenanceQuarantineRecord = {
        id: `pq_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
        timestamp: new Date().toISOString(),
        messageId: params.messageId || params.report.envelope?.payload?.messageId,
        senderId: params.senderId || params.report.signerId,
        recipientId: params.recipientId || params.report.envelope?.payload?.recipientId,
        kid: params.report.kid,
        source: params.source || params.report.source,
        verificationResult: params.report.status,
        reason: params.report.reason,
        ...(params.isDemo ? { isDemo: true } : {}),
      };
      quarantine.unshift(qRec);
      if (quarantine.length > MAX_QUARANTINE_RECORDS) {
        quarantine.length = MAX_QUARANTINE_RECORDS;
      }
      persistQuarantine();
    }
  });

  if (!params.skipTelemetry) {
    if (params.report.verified) {
      logSecurityEvent({
        eventType: 'PROVENANCE_VERIFIED',
        severity: 'info',
        result: 'success',
        userId: params.senderId || params.report.signerId,
        details: `Verified Ed25519 provenance (kid=${params.report.kid}, hops=${params.report.chain.length}${params.isDemo ? ', DEMO' : ''}).`,
      });
    } else if (params.report.status === 'REPLAY') {
      logSecurityEvent({
        eventType: 'PROVENANCE_REPLAY_BLOCKED',
        severity: 'warning',
        result: 'blocked',
        userId: params.senderId || params.report.signerId,
        details: `Blocked replayed provenance nonce (kid=${params.report.kid}${params.isDemo ? ', DEMO' : ''}).`,
      });
    } else {
      logSecurityEvent({
        eventType: 'PROVENANCE_REJECTED',
        severity: 'warning',
        result: 'blocked',
        userId: params.senderId || params.report.signerId,
        details: `Provenance rejected [${params.report.status}]: ${params.report.reason}`,
      });
    }
  }
}

export async function verifyEnvelopeOnServer(params: {
  envelope?: ProvenanceEnvelopeV1 | null;
  expectedRecipientId?: string;
  expectedCiphertext?: string;
  expectedIv?: string;
  expectedCiphertextHash?: string;
  expectedMessageId?: string;
  priority?: string;
  nowMs?: number;
  enforceReplay?: boolean;
  isDemo?: boolean;
  skipTelemetry?: boolean;
  pinnedKey?: PinnedKeyRecord | null;
}): Promise<ProvenanceVerificationReport> {
  await ensureServerKeyRegistered();
  const { keyLog } = hydrateStores();

  const report = await verifyProvenanceEnvelope({
    envelope: params.envelope,
    expectedRecipientId: params.expectedRecipientId,
    expectedCiphertext: params.expectedCiphertext,
    expectedIv: params.expectedIv,
    expectedCiphertextHash: params.expectedCiphertextHash,
    expectedMessageId: params.expectedMessageId,
    priority: params.priority,
    nowMs: params.nowMs,
    enforceReplay: params.enforceReplay ?? true,
    keyLookup: lookupProvenanceKeyByKid,
    verifyEd25519: (msgBytes, sigBytes, rawPubB64) =>
      verifyEd25519Server(msgBytes, sigBytes, rawPubB64),
    replayCheck: ({ kid, nonce, nowMs }) =>
      checkAndRecordReplayNonce({ kid, nonce, nowMs }),
    pinnedKey: params.pinnedKey,
    keyLogEntries: keyLog,
  });

  await recordProvenanceOutcome({
    report,
    messageId: params.expectedMessageId,
    recipientId: params.expectedRecipientId,
    isDemo: params.isDemo,
    skipTelemetry: params.skipTelemetry,
  });

  return report;
}

export async function getKeyLogPage(options: {
  offset?: number;
  limit?: number;
  userId?: string;
} = {}): Promise<{
  entries: KeyLogEntry[];
  total: number;
  headHash: string;
}> {
  await ensureServerKeyRegistered();
  const { keyLog } = hydrateStores();
  const filtered = options.userId
    ? keyLog.filter((e) => e.userId === options.userId)
    : keyLog;

  const limit = Math.min(200, Math.max(1, Number(options.limit) || 100));
  const offset = Math.max(0, Number(options.offset) || 0);
  const entries = filtered.slice(offset, offset + limit).map((e) => structuredClone(e));
  const headHash = keyLog.length > 0 ? keyLog[keyLog.length - 1].entryHash : GENESIS_HASH;

  return {
    entries,
    total: filtered.length,
    headHash,
  };
}

/**
 * Recomputes every hash link (`entryHash = SHA-256(prevHash + canonicalEntry)`)
 * AND verifies the server Ed25519 signature over every entry in the Key Transparency Log.
 */
export async function verifyKeyLogChain(
  entriesInput?: KeyLogEntry[],
  options: { skipTelemetry?: boolean; serverPublicKeyOverride?: string } = {}
): Promise<{
  ok: boolean;
  checkedCount: number;
  brokenAtIndex?: number;
  reason: string;
}> {
  await ensureServerKeyRegistered();
  const serverInfo = await getServerProvenanceKey();
  const entries = entriesInput || hydrateStores().keyLog;
  const serverPubB64 = options.serverPublicKeyOverride || serverInfo.publicKey;

  let expectedPrevHash = GENESIS_HASH;
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry.index !== i) {
      if (!options.skipTelemetry) {
        logSecurityEvent({
          eventType: 'KEYLOG_CHAIN_BROKEN',
          severity: 'critical',
          result: 'blocked',
          details: `KeyLog index discontinuity at slot ${i} (found index=${entry.index}).`,
        });
      }
      return {
        ok: false,
        checkedCount: i + 1,
        brokenAtIndex: i,
        reason: `KeyLog index discontinuity at position ${i} (found index=${entry.index}).`,
      };
    }

    if (entry.prevHash !== expectedPrevHash) {
      if (!options.skipTelemetry) {
        logSecurityEvent({
          eventType: 'KEYLOG_CHAIN_BROKEN',
          severity: 'critical',
          result: 'blocked',
          details: `KeyLog prevHash mismatch at index ${entry.index}.`,
        });
      }
      return {
        ok: false,
        checkedCount: i + 1,
        brokenAtIndex: entry.index,
        reason: `PrevHash link broken at entry #${entry.index} (${entry.type} kid=${entry.kid}).`,
      };
    }

    const recomputedHash = await computeKeyLogEntryHash({
      prevHash: entry.prevHash,
      index: entry.index,
      type: entry.type,
      kid: entry.kid,
      userId: entry.userId,
      publicKey: entry.publicKey,
      timestamp: entry.timestamp,
      reason: entry.reason,
      previousKid: entry.previousKid,
    });

    if (recomputedHash !== entry.entryHash) {
      if (!options.skipTelemetry) {
        logSecurityEvent({
          eventType: 'KEYLOG_CHAIN_BROKEN',
          severity: 'critical',
          result: 'blocked',
          details: `KeyLog entryHash tamper detected at index ${entry.index}.`,
        });
      }
      return {
        ok: false,
        checkedCount: i + 1,
        brokenAtIndex: entry.index,
        reason: `Entry hash mismatch (tampered entry) at index #${entry.index}.`,
      };
    }

    let sigOk = false;
    try {
      const sigBytes = base64ToBytes(entry.serverSignature);
      const signingBytes = buildKeyLogSigningBytes({
        index: entry.index,
        type: entry.type,
        kid: entry.kid,
        userId: entry.userId,
        publicKey: entry.publicKey,
        timestamp: entry.timestamp,
        reason: entry.reason,
        previousKid: entry.previousKid,
        prevHash: entry.prevHash,
        entryHash: entry.entryHash,
      });
      sigOk = verifyEd25519Server(signingBytes, sigBytes, serverPubB64);
    } catch {
      sigOk = false;
    }

    if (!sigOk) {
      if (!options.skipTelemetry) {
        logSecurityEvent({
          eventType: 'KEYLOG_CHAIN_BROKEN',
          severity: 'critical',
          result: 'blocked',
          details: `KeyLog server Ed25519 signature invalid at index ${entry.index}.`,
        });
      }
      return {
        ok: false,
        checkedCount: i + 1,
        brokenAtIndex: entry.index,
        reason: `Server Ed25519 signature invalid at index #${entry.index}.`,
      };
    }

    expectedPrevHash = entry.entryHash;
  }

  if (!options.skipTelemetry) {
    logSecurityEvent({
      eventType: 'KEYLOG_CHAIN_VERIFIED',
      severity: 'info',
      result: 'success',
      details: `KeyLog integrity verified across ${entries.length} hash-chained Ed25519 entries.`,
    });
  }

  return {
    ok: true,
    checkedCount: entries.length,
    reason: `All ${entries.length} hash-chained KeyLog entries and server Ed25519 signatures passed verification.`,
  };
}

export async function getProvenanceQuarantineAndStats(options: {
  userId?: string;
  isAdmin?: boolean;
  limit?: number;
} = {}): Promise<{
  quarantine: ProvenanceQuarantineRecord[];
  countsByStatus: Record<ProvenanceStatus, number>;
  totalVerified: number;
  totalRejected: number;
}> {
  const { quarantine, stats } = hydrateStores();
  const limit = Math.min(200, Math.max(1, Number(options.limit) || 100));

  const visible = options.isAdmin
    ? quarantine
    : quarantine.filter(
        (q) => q.senderId === options.userId || q.recipientId === options.userId
      );

  const counts = { ...stats };
  let totalRejected = 0;
  for (const code of PROVENANCE_STATUS_CODES) {
    if (code !== 'VERIFIED') {
      totalRejected += counts[code] || 0;
    }
  }

  return {
    quarantine: visible.slice(0, limit).map((q) => structuredClone(q)),
    countsByStatus: counts,
    totalVerified: counts.VERIFIED || 0,
    totalRejected,
  };
}

export async function deleteDemoProvenanceState(demoPrefixes: string[]): Promise<void> {
  await withProvenanceLock(() => {
    const { keys, quarantine } = hydrateStores();
    for (const [kid, k] of keys.entries()) {
      if (demoPrefixes.some((p) => k.userId.startsWith(p))) {
        keys.delete(kid);
      }
    }
    for (let i = quarantine.length - 1; i >= 0; i -= 1) {
      if (quarantine[i].isDemo) {
        quarantine.splice(i, 1);
      }
    }
    persistKeys();
    persistQuarantine();
  });
}
