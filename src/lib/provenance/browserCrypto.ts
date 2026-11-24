import { ed25519 } from '@noble/curves/ed25519.js';
import {
  base64ToBytes,
  buildAttestationSigningBytes,
  buildProvenanceSigningBytes,
  bytesToBase64,
  bytesToHex,
  computeCiphertextHash,
  computeKeyIdFromRawPublicKey,
  computePayloadHash,
  computePublicKeyFingerprint,
  toArrayBuffer,
} from './canonical.js';
import type {
  ProvenanceAttestation,
  ProvenanceEnvelopeV1,
  ProvenancePayloadV1,
} from './types.js';

export interface EncryptedSigningKeyBundle {
  v: 1;
  alg: 'Ed25519';
  kdf: 'PBKDF2-HMAC-SHA256';
  iterations: number;
  cipher: 'AES-256-GCM';
  userId: string;
  kid: string;
  publicKey: string; // base64 raw 32-byte Ed25519 public key
  fingerprintHex: string;
  fingerprintWords: string[];
  salt: string; // base64
  iv: string; // base64
  encryptedPrivateKey: string; // base64
  createdAt: string;
}

export interface UnlockedSigningKey {
  userId: string;
  kid: string;
  publicKey: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  getSecretSeedCopy: () => Uint8Array;
  wipe: () => void;
  isWiped: () => boolean;
}

const PBKDF2_ITERATIONS = 150_000;
const LOCAL_BUNDLE_PREFIX = 'aegis_provenance_enc_key_';

let webCryptoEd25519SupportedCache: boolean | null = null;

function getCrypto(): Crypto {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('WebCrypto API is unavailable in this environment.');
  }
  return globalThis.crypto;
}

export function zeroBuffer(buf?: Uint8Array | null): void {
  if (!buf || typeof buf.fill !== 'function') return;
  try {
    buf.fill(0);
  } catch {
    // ignore
  }
}

/**
 * Feature-detects native Web Crypto Ed25519 support safely.
 * Always falls back to @noble/curves/ed25519 when unsupported.
 */
export async function supportsWebCryptoEd25519(): Promise<boolean> {
  if (webCryptoEd25519SupportedCache !== null) {
    return webCryptoEd25519SupportedCache;
  }
  try {
    const subtle = getCrypto().subtle;
    const dummyPub = new Uint8Array(32);
    dummyPub[0] = 1;
    // Feature-detect subtle.importKey('raw', ..., { name: 'Ed25519' })
    await subtle.importKey('raw', toArrayBuffer(dummyPub), 'Ed25519', false, ['verify']);
    webCryptoEd25519SupportedCache = true;
  } catch {
    webCryptoEd25519SupportedCache = false;
  }
  return webCryptoEd25519SupportedCache;
}

/**
 * Generates a fresh Ed25519 keypair from CSPRNG in browser/client memory.
 */
export async function generateRawEd25519KeyPair(): Promise<{
  secretSeed: Uint8Array;
  publicKeyBytes: Uint8Array;
  publicKey: string;
  kid: string;
  fingerprintHex: string;
  fingerprintWords: string[];
}> {
  const randomSeed = new Uint8Array(32);
  getCrypto().getRandomValues(randomSeed);
  const { secretKey, publicKey } = ed25519.keygen(randomSeed);
  const publicKeyB64 = bytesToBase64(publicKey);
  const fp = await computePublicKeyFingerprint(publicKeyB64);
  return {
    secretSeed: secretKey,
    publicKeyBytes: publicKey,
    publicKey: publicKeyB64,
    kid: fp.kid,
    fingerprintHex: fp.fingerprintHex,
    fingerprintWords: fp.fingerprintWords,
  };
}

/**
 * Signs raw bytes with a 32-byte Ed25519 secret seed (RFC 8032 / @noble/curves).
 */
export function signEd25519Bytes(messageBytes: Uint8Array, secretSeed: Uint8Array): Uint8Array {
  if (secretSeed.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 secret seed, got ${secretSeed.length} bytes.`);
  }
  return ed25519.sign(messageBytes, secretSeed);
}

/**
 * Verifies an Ed25519 signature against a 32-byte raw public key.
 * Uses native Web Crypto Ed25519 when feature-detected, otherwise @noble/curves/ed25519 (RFC 8032 strict).
 */
export async function verifyEd25519Browser(
  messageBytes: Uint8Array,
  signatureBytes: Uint8Array,
  rawPublicKeyBase64: string
): Promise<boolean> {
  try {
    if (signatureBytes.length !== 64) return false;
    const pubBytes = base64ToBytes(rawPublicKeyBase64);
    if (pubBytes.length !== 32) return false;

    const hasWebCrypto = await supportsWebCryptoEd25519();
    if (hasWebCrypto) {
      try {
        const subtle = getCrypto().subtle;
        const pubKey = await subtle.importKey(
          'raw',
          toArrayBuffer(pubBytes),
          'Ed25519',
          false,
          ['verify']
        );
        return await subtle.verify(
          'Ed25519',
          pubKey,
          toArrayBuffer(signatureBytes),
          toArrayBuffer(messageBytes)
        );
      } catch {
        // Fallback smoothly to @noble/curves if WebCrypto runtime rejects curve edge input
      }
    }

    return ed25519.verify(signatureBytes, messageBytes, pubBytes, { zip215: false });
  } catch {
    return false;
  }
}

async function derivePassphraseAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const subtle = getCrypto().subtle;
  const passBytes = new TextEncoder().encode(passphrase);
  try {
    const baseKey = await subtle.importKey(
      'raw',
      toArrayBuffer(passBytes),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return await subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: toArrayBuffer(salt),
        iterations,
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      usage
    );
  } finally {
    zeroBuffer(passBytes);
  }
}

/**
 * Creates a new browser Ed25519 keypair, encrypts the private seed with PBKDF2 + AES-256-GCM,
 * and returns both the encrypted backup bundle and a volatile RAM signing handle.
 * The private seed is NEVER sent to the server or stored in plaintext.
 */
export async function createEncryptedSigningKeyBundle(
  userId: string,
  passphrase: string
): Promise<{
  bundle: EncryptedSigningKeyBundle;
  unlocked: UnlockedSigningKey;
}> {
  if (!passphrase || passphrase.length < 8) {
    throw new Error('Passphrase must be at least 8 characters to protect your Ed25519 private key.');
  }

  const kp = await generateRawEd25519KeyPair();
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  getCrypto().getRandomValues(salt);
  getCrypto().getRandomValues(iv);

  const aesKey = await derivePassphraseAesKey(passphrase, salt, PBKDF2_ITERATIONS, ['encrypt']);
  const encrypted = new Uint8Array(
    await getCrypto().subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(kp.secretSeed)
    )
  );

  const bundle: EncryptedSigningKeyBundle = {
    v: 1,
    alg: 'Ed25519',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: PBKDF2_ITERATIONS,
    cipher: 'AES-256-GCM',
    userId,
    kid: kp.kid,
    publicKey: kp.publicKey,
    fingerprintHex: kp.fingerprintHex,
    fingerprintWords: kp.fingerprintWords,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    encryptedPrivateKey: bytesToBase64(encrypted),
    createdAt: new Date().toISOString(),
  };

  let wiped = false;
  const seedHolder = new Uint8Array(kp.secretSeed);
  zeroBuffer(kp.secretSeed);

  return {
    bundle,
    unlocked: {
      userId,
      kid: kp.kid,
      publicKey: kp.publicKey,
      fingerprintHex: kp.fingerprintHex,
      fingerprintWords: kp.fingerprintWords,
      getSecretSeedCopy: () => {
        if (wiped) {
          throw new Error('Signing key has been locked/wiped from memory.');
        }
        return new Uint8Array(seedHolder);
      },
      wipe: () => {
        wiped = true;
        zeroBuffer(seedHolder);
      },
      isWiped: () => wiped,
    },
  };
}

/**
 * Unlocks a passphrase-protected Ed25519 signing key bundle strictly into volatile memory.
 */
export async function unlockEncryptedSigningKeyBundle(
  bundle: EncryptedSigningKeyBundle,
  passphrase: string
): Promise<UnlockedSigningKey> {
  const salt = base64ToBytes(bundle.salt);
  const iv = base64ToBytes(bundle.iv);
  const cipher = base64ToBytes(bundle.encryptedPrivateKey);

  const aesKey = await derivePassphraseAesKey(
    passphrase,
    salt,
    bundle.iterations || PBKDF2_ITERATIONS,
    ['decrypt']
  );

  let rawSeed: Uint8Array;
  try {
    rawSeed = new Uint8Array(
      await getCrypto().subtle.decrypt(
        { name: 'AES-GCM', iv: toArrayBuffer(iv) },
        aesKey,
        toArrayBuffer(cipher)
      )
    );
  } catch {
    throw new Error('Incorrect passphrase or corrupted signing key backup.');
  }

  const derivedPub = ed25519.getPublicKey(rawSeed);
  const derivedKid = await computeKeyIdFromRawPublicKey(derivedPub);
  if (derivedKid !== bundle.kid) {
    zeroBuffer(rawSeed);
    throw new Error('Decrypted key ID does not match bundle metadata.');
  }

  let wiped = false;
  return {
    userId: bundle.userId,
    kid: bundle.kid,
    publicKey: bundle.publicKey,
    fingerprintHex: bundle.fingerprintHex,
    fingerprintWords: bundle.fingerprintWords,
    getSecretSeedCopy: () => {
      if (wiped) {
        throw new Error('Signing key has been locked/wiped from memory.');
      }
      return new Uint8Array(rawSeed);
    },
    wipe: () => {
      wiped = true;
      zeroBuffer(rawSeed);
    },
    isWiped: () => wiped,
  };
}

export function saveEncryptedKeyBundleLocally(bundle: EncryptedSigningKeyBundle): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  window.localStorage.setItem(`${LOCAL_BUNDLE_PREFIX}${bundle.userId}`, JSON.stringify(bundle));
}

export function loadEncryptedKeyBundleLocally(userId: string): EncryptedSigningKeyBundle | null {
  if (typeof window === 'undefined' || !window.localStorage) return null;
  try {
    const raw = window.localStorage.getItem(`${LOCAL_BUNDLE_PREFIX}${userId}`);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed?.v === 1 && parsed?.alg === 'Ed25519' && parsed?.encryptedPrivateKey) {
      return parsed as EncryptedSigningKeyBundle;
    }
    return null;
  } catch {
    return null;
  }
}

export function clearEncryptedKeyBundleLocally(userId: string): void {
  if (typeof window === 'undefined' || !window.localStorage) return;
  window.localStorage.removeItem(`${LOCAL_BUNDLE_PREFIX}${userId}`);
}

export function generateRandomNonceHex(): string {
  const bytes = new Uint8Array(16);
  getCrypto().getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Signs a message/notification provenance envelope on the client using the unlocked Ed25519 key.
 */
export async function createSignedProvenanceEnvelopeBrowser(params: {
  unlockedKey: UnlockedSigningKey;
  messageId: string;
  recipientId: string;
  source?: string;
  priority: string;
  ciphertext: string;
  iv: string;
  ttlSeconds?: number;
  expiresAt?: string;
  createdAt?: string;
  textScore?: number;
  signedPriorityLabel?: string;
}): Promise<ProvenanceEnvelopeV1> {
  const createdAt = params.createdAt || new Date().toISOString();
  const nonce = generateRandomNonceHex();
  const ciphertextHash = await computeCiphertextHash(params.ciphertext, params.iv);

  const payload: ProvenancePayloadV1 = {
    v: 1,
    alg: 'Ed25519',
    kid: params.unlockedKey.kid,
    messageId: params.messageId,
    senderId: params.unlockedKey.userId,
    recipientId: params.recipientId,
    source: params.source || 'direct',
    priority: params.priority,
    createdAt,
    nonce,
    ciphertextHash,
    ...(typeof params.ttlSeconds === 'number' ? { ttlSeconds: params.ttlSeconds } : {}),
    ...(params.expiresAt ? { expiresAt: params.expiresAt } : {}),
    ...(typeof params.textScore === 'number' && Number.isFinite(params.textScore)
      ? { textScore: Number(Math.max(0, Math.min(1, params.textScore)).toFixed(4)) }
      : {}),
    ...(params.signedPriorityLabel ? { signedPriorityLabel: params.signedPriorityLabel } : {}),
  };

  const payloadHash = await computePayloadHash(payload);
  const seed = params.unlockedKey.getSecretSeedCopy();
  try {
    const payloadSig = signEd25519Bytes(buildProvenanceSigningBytes(payload), seed);
    const attestationSig = signEd25519Bytes(
      buildAttestationSigningBytes({
        role: 'ORIGIN',
        alg: 'Ed25519',
        kid: params.unlockedKey.kid,
        signerId: params.unlockedKey.userId,
        signedAt: createdAt,
        parentHash: payloadHash,
        messageId: params.messageId,
        ciphertextHash,
      }),
      seed
    );

    const originAttestation: ProvenanceAttestation = {
      role: 'ORIGIN',
      alg: 'Ed25519',
      kid: params.unlockedKey.kid,
      signerId: params.unlockedKey.userId,
      signedAt: createdAt,
      parentHash: payloadHash,
      sig: bytesToBase64(payloadSig),
    };

    // Embed attestation chain signature cleanly:
    // First hop signs canonical provenance payload directly; attestation itself carries payloadHash as parentHash
    // and we verify both origin attestation.sig against payload bytes AND chained hops against attestation signing bytes!
    void attestationSig;

    return {
      v: 1,
      payload,
      chain: [originAttestation],
    };
  } finally {
    zeroBuffer(seed);
  }
}
