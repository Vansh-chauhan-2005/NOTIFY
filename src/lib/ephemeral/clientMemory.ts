import {
  generateEphemeralKeyRing,
  type EphemeralSessionKeyRing,
} from './crypto.js';
import { safeReadJson } from '../http/safeJson.js';

interface DecryptedMemoryEntry {
  plaintext: string;
  wipeHandle: () => void;
  expiresAtMs: number;
}

// Volatile in-memory storage ONLY — never persisted to localStorage, sessionStorage,
// IndexedDB, cookies, URL params, or console logs.
let activeKeyRing: EphemeralSessionKeyRing | null = null;
const decryptedMemoryMap = new Map<string, DecryptedMemoryEntry>();

export async function ensureClientEphemeralKeyRing(
  userId: string,
  authToken: string | null
): Promise<EphemeralSessionKeyRing> {
  if (!activeKeyRing || activeKeyRing.userId !== userId) {
    activeKeyRing = await generateEphemeralKeyRing(userId);
    if (authToken) {
      await fetch('/api/v1/ephemeral/public-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          ecdhPublicJwk: activeKeyRing.ecdhPublicJwk,
          ecdsaPublicJwk: activeKeyRing.ecdsaPublicJwk,
        }),
      }).catch(() => {});
    }
  }
  return activeKeyRing;
}

export function getActiveClientKeyRing(): EphemeralSessionKeyRing | null {
  return activeKeyRing;
}

export function setActiveClientKeyRing(ring: EphemeralSessionKeyRing | null): void {
  activeKeyRing = ring;
}

export async function resolveRecipientEcdhPublicJwk(
  recipientId: string,
  senderId: string,
  ownKeyRing: EphemeralSessionKeyRing,
  authToken: string | null
): Promise<JsonWebKey> {
  if (!recipientId || recipientId === senderId) {
    return ownKeyRing.ecdhPublicJwk;
  }

  const res = await fetch(
    `/api/v1/ephemeral/public-key/${encodeURIComponent(recipientId)}`,
    {
      method: 'GET',
      headers: {
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
    }
  );
  const data = await safeReadJson(res);
  if (res.ok && data?.success && data?.data?.bundle?.ecdhPublicJwk) {
    return data.data.bundle.ecdhPublicJwk as JsonWebKey;
  }

  throw new Error(
    data?.message ||
      `Recipient "${recipientId}" does not have an active ephemeral session public key registered yet.`
  );
}

export function storeDecryptedEphemeralEntry(
  id: string,
  plaintext: string,
  wipeHandle: () => void,
  expiresAtMs: number
): void {
  const prev = decryptedMemoryMap.get(id);
  if (prev) {
    try {
      prev.wipeHandle();
    } catch {
      // ignore
    }
  }
  decryptedMemoryMap.set(id, { plaintext, wipeHandle, expiresAtMs });
}

export function getDecryptedEphemeralPlaintext(id: string): string | null {
  const entry = decryptedMemoryMap.get(id);
  if (!entry) return null;
  if (Date.now() >= entry.expiresAtMs) {
    wipeDecryptedEphemeralEntry(id);
    return null;
  }
  return entry.plaintext;
}

export function wipeDecryptedEphemeralEntry(id: string): void {
  const entry = decryptedMemoryMap.get(id);
  if (entry) {
    try {
      entry.wipeHandle();
    } catch {
      // ignore
    }
    entry.plaintext = '';
    decryptedMemoryMap.delete(id);
  }
}

export function wipeAllDecryptedPlaintextOnly(): void {
  for (const id of Array.from(decryptedMemoryMap.keys())) {
    wipeDecryptedEphemeralEntry(id);
  }
}

export function wipeAllEphemeralMemory(): void {
  wipeAllDecryptedPlaintextOnly();
  activeKeyRing = null;
}
