/**
 * Ephemeral End-to-End Crypto-Shredding Module (WebCrypto ECDH + AES-256-GCM + ECDSA)
 *
 * Works identically in modern browsers and Node 20+ via globalThis.crypto.subtle.
 * Keys and decrypted plaintext stay strictly in volatile JS memory — NEVER persisted
 * to localStorage, sessionStorage, IndexedDB, cookies, URLs, or logs.
 */

export interface EphemeralPublicBundle {
  userId: string;
  ecdhPublicJwk: JsonWebKey;
  ecdsaPublicJwk: JsonWebKey;
  updatedAt: string;
}

export interface EphemeralSessionKeyRing {
  userId: string;
  ecdhPrivateKey: CryptoKey;
  ecdhPublicJwk: JsonWebKey;
  ecdsaPrivateKey: CryptoKey;
  ecdsaPublicJwk: JsonWebKey;
}

export interface EphemeralEncryptedEnvelope {
  id: string;
  senderId: string;
  recipientId: string;
  priority: string;
  ciphertext: string;
  iv: string;
  signature: string;
  expiresAt: string;
  readOnce: boolean;
  senderEcdhPubJwk: JsonWebKey;
  senderEcdsaPubJwk: JsonWebKey;
}

export interface EphemeralWrappedKeyMaterial {
  wrappedDek: string;
  wrapIv: string;
  senderEcdhPubJwk: JsonWebKey;
}

function getSubtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('WebCrypto SubtleCrypto API is unavailable in this environment.');
  }
  return c.subtle;
}

function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(b64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Overwrite sensitive byte buffers in place with zeros before releasing references.
 */
export function zeroUint8Array(buf?: Uint8Array | null): void {
  if (!buf || typeof buf.fill !== 'function') return;
  try {
    buf.fill(0);
  } catch {
    // ignore read-only views
  }
}

export function canonicalSignaturePayload(params: {
  id: string;
  senderId: string;
  recipientId: string;
  ciphertext: string;
  iv: string;
  priority: string;
  readOnce: boolean;
}): Uint8Array {
  const ordered = JSON.stringify({
    ciphertext: params.ciphertext,
    id: params.id,
    iv: params.iv,
    priority: params.priority,
    readOnce: Boolean(params.readOnce),
    recipientId: params.recipientId,
    senderId: params.senderId,
  });
  return new TextEncoder().encode(ordered);
}

/**
 * Generates volatile in-memory ECDH (P-256) + ECDSA (P-256) keypairs for a user.
 * Never persisted to browser disk storage.
 */
export async function generateEphemeralKeyRing(userId: string): Promise<EphemeralSessionKeyRing> {
  const subtle = getSubtle();

  const ecdhPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const ecdsaPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const [ecdhPublicJwk, ecdsaPublicJwk] = await Promise.all([
    subtle.exportKey('jwk', ecdhPair.publicKey),
    subtle.exportKey('jwk', ecdsaPair.publicKey),
  ]);

  return {
    userId,
    ecdhPrivateKey: ecdhPair.privateKey,
    ecdhPublicJwk,
    ecdsaPrivateKey: ecdsaPair.privateKey,
    ecdsaPublicJwk,
  };
}

async function deriveSharedWrapKey(
  ownEcdhPrivateKey: CryptoKey,
  peerEcdhPublicJwk: JsonWebKey
): Promise<CryptoKey> {
  const subtle = getSubtle();
  const peerPubKey = await subtle.importKey(
    'jwk',
    peerEcdhPublicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: peerPubKey },
    ownEcdhPrivateKey,
    256
  );

  const hashedKekBytes = new Uint8Array(await subtle.digest('SHA-256', sharedBits));
  try {
    return await subtle.importKey(
      'raw',
      toArrayBuffer(hashedKekBytes),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    zeroUint8Array(hashedKekBytes);
  }
}

/**
 * Encrypts plaintext with a fresh random 256-bit DEK (AES-256-GCM),
 * wraps the DEK using an ECDH P-256 derived shared KEK, and signs the
 * canonical envelope with ECDSA P-256.
 *
 * The server receives ONLY ciphertext + wrappedDek (never plaintext or raw DEK).
 */
export async function encryptAndWrapEphemeralMessage(params: {
  id: string;
  senderId: string;
  recipientId: string;
  priority: string;
  expiresAt: string;
  readOnce: boolean;
  plaintext: string;
  senderKeyRing: EphemeralSessionKeyRing;
  recipientEcdhPublicJwk: JsonWebKey;
}): Promise<{
  envelope: EphemeralEncryptedEnvelope;
  keyMaterial: EphemeralWrappedKeyMaterial;
}> {
  const subtle = getSubtle();

  // 1. Fresh 256-bit random DEK + 96-bit IV
  const rawDek = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const contentIv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const wrapIv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(params.plaintext);

  try {
    const dekKey = await subtle.importKey(
      'raw',
      toArrayBuffer(rawDek),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const encryptedContent = new Uint8Array(
      await subtle.encrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(contentIv) },
        dekKey,
        toArrayBuffer(plaintextBytes)
      )
    );

    // 2. Wrap DEK via ECDH-derived shared AES-256-GCM key
    const wrapKek = await deriveSharedWrapKey(
      params.senderKeyRing.ecdhPrivateKey,
      params.recipientEcdhPublicJwk
    );

    const wrappedDekBytes = new Uint8Array(
      await subtle.encrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(wrapIv) },
        wrapKek,
        toArrayBuffer(rawDek)
      )
    );

    const ciphertext = toBase64(encryptedContent);
    const iv = toBase64(contentIv);

    // 3. Sign ciphertext + immutable envelope metadata using sender's ECDSA private key
    const sigPayload = canonicalSignaturePayload({
      id: params.id,
      senderId: params.senderId,
      recipientId: params.recipientId,
      ciphertext,
      iv,
      priority: params.priority,
      readOnce: params.readOnce,
    });

    const sigBytes = new Uint8Array(
      await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        params.senderKeyRing.ecdsaPrivateKey,
        toArrayBuffer(sigPayload)
      )
    );

    return {
      envelope: {
        id: params.id,
        senderId: params.senderId,
        recipientId: params.recipientId,
        priority: params.priority,
        ciphertext,
        iv,
        signature: toBase64(sigBytes),
        expiresAt: params.expiresAt,
        readOnce: Boolean(params.readOnce),
        senderEcdhPubJwk: params.senderKeyRing.ecdhPublicJwk,
        senderEcdsaPubJwk: params.senderKeyRing.ecdsaPublicJwk,
      },
      keyMaterial: {
        wrappedDek: toBase64(wrappedDekBytes),
        wrapIv: toBase64(wrapIv),
        senderEcdhPubJwk: params.senderKeyRing.ecdhPublicJwk,
      },
    };
  } finally {
    zeroUint8Array(rawDek);
    zeroUint8Array(plaintextBytes);
  }
}

/**
 * Verifies the ECDSA signature, unwraps the per-message DEK using ECDH shared KEK,
 * and decrypts AES-256-GCM ciphertext strictly in volatile memory.
 *
 * Fails explicitly if the wrapped key has been crypto-shredded / deleted or tampered.
 */
export async function verifyAndDecryptEphemeralMessage(params: {
  envelope: {
    id: string;
    senderId: string;
    recipientId: string;
    priority: string;
    ciphertext: string;
    iv: string;
    signature: string;
    expiresAt: string;
    readOnce: boolean;
    senderEcdhPubJwk: JsonWebKey;
    senderEcdsaPubJwk: JsonWebKey;
  };
  wrappedDek?: string | null;
  wrapIv?: string | null;
  recipientEcdhPrivateKey: CryptoKey;
}): Promise<{
  plaintext: string;
  verified: boolean;
  wipeHandle: () => void;
}> {
  if (!params.wrappedDek || !params.wrapIv) {
    throw new Error('Crypto-shredded: wrapped DEK is missing or destroyed; ciphertext is permanently unreadable.');
  }
  if (!params.envelope.ciphertext || !params.envelope.iv) {
    throw new Error('Ciphertext payload has already been destroyed.');
  }

  const subtle = getSubtle();

  // 1. Verify ECDSA signature first
  const ecdsaPubKey = await subtle.importKey(
    'jwk',
    params.envelope.senderEcdsaPubJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );

  const sigPayload = canonicalSignaturePayload({
    id: params.envelope.id,
    senderId: params.envelope.senderId,
    recipientId: params.envelope.recipientId,
    ciphertext: params.envelope.ciphertext,
    iv: params.envelope.iv,
    priority: params.envelope.priority,
    readOnce: params.envelope.readOnce,
  });

  const sigBytes = fromBase64(params.envelope.signature);
  const verified = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    ecdsaPubKey,
    toArrayBuffer(sigBytes),
    toArrayBuffer(sigPayload)
  );

  if (!verified) {
    throw new Error('ECDSA signature verification failed for ephemeral payload.');
  }

  // 2. Unwrap DEK via ECDH-derived shared KEK
  const wrapKek = await deriveSharedWrapKey(
    params.recipientEcdhPrivateKey,
    params.envelope.senderEcdhPubJwk
  );

  const wrappedDekBytes = fromBase64(params.wrappedDek);
  const wrapIvBytes = fromBase64(params.wrapIv);

  let rawDekBytes: Uint8Array;
  try {
    rawDekBytes = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(wrapIvBytes) },
        wrapKek,
        toArrayBuffer(wrappedDekBytes)
      )
    );
  } catch {
    throw new Error('Unable to unwrap per-message DEK (destroyed or mismatched ECDH keypair).');
  }

  let decryptedBytes: Uint8Array | null = null;
  try {
    const dekKey = await subtle.importKey(
      'raw',
      toArrayBuffer(rawDekBytes),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const ivBytes = fromBase64(params.envelope.iv);
    const cipherBytes = fromBase64(params.envelope.ciphertext);

    decryptedBytes = new Uint8Array(
      await subtle.decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(ivBytes) },
        dekKey,
        toArrayBuffer(cipherBytes)
      )
    );

    const plaintext = new TextDecoder().decode(decryptedBytes);
    const bufRef = decryptedBytes;

    return {
      plaintext,
      verified: true,
      wipeHandle: () => {
        zeroUint8Array(bufRef);
      },
    };
  } finally {
    zeroUint8Array(rawDekBytes);
    if (decryptedBytes) {
      zeroUint8Array(decryptedBytes);
    }
  }
}
