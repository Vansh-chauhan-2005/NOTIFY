import type { KeyLogEntry, PinnedKeyRecord } from './types.js';
import { verifyPinnedKeyContinuity } from './verifyPolicy.js';

const DB_NAME = 'aegis_provenance_pins';
const STORE_NAME = 'pins';
const DB_VERSION = 1;

// Fallback in-memory pin map for SSR or restricted environments without IndexedDB
const memoryPinsFallback = new Map<string, PinnedKeyRecord>();

function openPinsDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: 'userId' });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function getPinnedKey(userId: string): Promise<PinnedKeyRecord | null> {
  const db = await openPinsDb();
  if (!db) {
    return memoryPinsFallback.get(userId) || null;
  }
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(userId);
      req.onsuccess = () => {
        resolve((req.result as PinnedKeyRecord) || null);
      };
      req.onerror = () => resolve(memoryPinsFallback.get(userId) || null);
    } catch {
      resolve(memoryPinsFallback.get(userId) || null);
    }
  });
}

export async function listAllPinnedKeys(): Promise<PinnedKeyRecord[]> {
  const db = await openPinsDb();
  if (!db) {
    return Array.from(memoryPinsFallback.values());
  }
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => resolve((req.result as PinnedKeyRecord[]) || []);
      req.onerror = () => resolve(Array.from(memoryPinsFallback.values()));
    } catch {
      resolve(Array.from(memoryPinsFallback.values()));
    }
  });
}

export async function savePinnedKey(record: PinnedKeyRecord): Promise<void> {
  memoryPinsFallback.set(record.userId, record);
  const db = await openPinsDb();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

export async function deletePinnedKey(userId: string): Promise<void> {
  memoryPinsFallback.delete(userId);
  const db = await openPinsDb();
  if (!db) return;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(userId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

/**
 * Trust-On-First-Use (TOFU) pin verification against Key Transparency Log (`keyLog`).
 * - If no pin exists for `userId`, pins the key on first observation and returns `pinned: true`.
 * - If pin exists and matches OR connects cleanly through a server-signed `ROTATE` entry, updates pin and returns ok.
 * - If registry serves a different key WITHOUT valid chained `ROTATE` proof, blocks with `KEY_MISMATCH`!
 */
export async function checkOrPinKeyTofu(params: {
  userId: string;
  kid: string;
  publicKey: string;
  fingerprintHex: string;
  keyLogEntries: KeyLogEntry[];
}): Promise<{
  ok: boolean;
  newlyPinned: boolean;
  rotatedPin: boolean;
  reason?: string;
  pin?: PinnedKeyRecord;
}> {
  if (!params.userId || params.userId === 'aegis-server-gateway') {
    return { ok: true, newlyPinned: false, rotatedPin: false };
  }

  const latestIndex =
    params.keyLogEntries.length > 0
      ? params.keyLogEntries[params.keyLogEntries.length - 1].index
      : 0;

  const existing = await getPinnedKey(params.userId);
  if (!existing) {
    const pin: PinnedKeyRecord = {
      userId: params.userId,
      kid: params.kid,
      publicKey: params.publicKey,
      fingerprintHex: params.fingerprintHex,
      pinnedAt: new Date().toISOString(),
      lastLogIndex: latestIndex,
    };
    await savePinnedKey(pin);
    return { ok: true, newlyPinned: true, rotatedPin: false, pin };
  }

  const continuity = verifyPinnedKeyContinuity({
    pinnedKey: existing,
    signerUserId: params.userId,
    presentedKid: params.kid,
    presentedPublicKey: params.publicKey,
    keyLogEntries: params.keyLogEntries,
  });

  if (!continuity.ok) {
    return {
      ok: false,
      newlyPinned: false,
      rotatedPin: false,
      reason: continuity.reason,
      pin: existing,
    };
  }

  const rotated = existing.kid !== params.kid;
  if (rotated || existing.lastLogIndex < latestIndex) {
    const updated: PinnedKeyRecord = {
      userId: params.userId,
      kid: params.kid,
      publicKey: params.publicKey,
      fingerprintHex: params.fingerprintHex,
      pinnedAt: rotated ? new Date().toISOString() : existing.pinnedAt,
      lastLogIndex: latestIndex,
    };
    await savePinnedKey(updated);
    return { ok: true, newlyPinned: false, rotatedPin: rotated, pin: updated };
  }

  return { ok: true, newlyPinned: false, rotatedPin: false, pin: existing };
}

/**
 * Explicit user override after out-of-band fingerprint verification.
 */
export async function acceptNewKeyPinAfterOverride(params: {
  userId: string;
  kid: string;
  publicKey: string;
  fingerprintHex: string;
  lastLogIndex?: number;
}): Promise<PinnedKeyRecord> {
  const record: PinnedKeyRecord = {
    userId: params.userId,
    kid: params.kid,
    publicKey: params.publicKey,
    fingerprintHex: params.fingerprintHex,
    pinnedAt: new Date().toISOString(),
    lastLogIndex: params.lastLogIndex ?? 0,
  };
  await savePinnedKey(record);
  return record;
}
