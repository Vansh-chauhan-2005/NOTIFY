import { ed25519 } from '@noble/curves/ed25519.js';
import {
  base64ToBytes,
  bytesToBase64,
  computePublicKeyFingerprint,
  toArrayBuffer,
} from '../provenance/canonical.js';
import {
  generateRawEd25519KeyPair,
  saveEncryptedKeyBundleLocally,
  type EncryptedSigningKeyBundle,
  type UnlockedSigningKey,
  zeroBuffer,
} from '../provenance/browserCrypto.js';
import {
  generateEphemeralKeyRing,
  type EphemeralSessionKeyRing,
} from '../ephemeral/crypto.js';

export const KEY_VAULT_PBKDF2_ITERATIONS = 150_000;
export const MAX_UNLOCK_ATTEMPTS = 5;

export interface EncryptedCombinedKeyBackup {
  v: 1;
  userId: string;
  kdf: 'PBKDF2-HMAC-SHA256';
  iterations: number;
  cipher: 'AES-256-GCM';
  salt: string; // base64
  iv: string; // base64
  encryptedPrivateKeysBundle: string; // base64 AES-GCM ciphertext of JSON private bundle
  ed25519PublicKey: string;
  ed25519Kid: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  ecdhPublicJwk: JsonWebKey;
  ecdsaPublicJwk: JsonWebKey;
  createdAt: string;
  updatedAt: string;
}

interface PlaintextPrivateKeysPayload {
  v: 1;
  ed25519SeedB64: string;
  ecdhPrivateJwk: JsonWebKey;
  ecdsaPrivateJwk: JsonWebKey;
}

function getWebCrypto(): Crypto {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('WebCrypto API is unavailable in this browser.');
  }
  return globalThis.crypto;
}

async function deriveVaultAesKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const subtle = getWebCrypto().subtle;
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

function makeUnlockedSigningKeyFromSeed(params: {
  userId: string;
  kid: string;
  publicKey: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  secretSeed: Uint8Array;
}): UnlockedSigningKey {
  let wiped = false;
  const seed = new Uint8Array(params.secretSeed);
  return {
    userId: params.userId,
    kid: params.kid,
    publicKey: params.publicKey,
    fingerprintHex: params.fingerprintHex,
    fingerprintWords: params.fingerprintWords,
    getSecretSeedCopy: () => {
      if (wiped) {
        throw new Error('Signing key has been locked or wiped from memory.');
      }
      return new Uint8Array(seed);
    },
    wipe: () => {
      if (!wiped) {
        zeroBuffer(seed);
        wiped = true;
      }
    },
    isWiped: () => wiped,
  };
}

/**
 * Generate a fresh Ed25519 + ECDH P-256 + ECDSA P-256 key bundle in browser RAM,
 * encrypt private material using PBKDF2-HMAC-SHA256 (150k) + AES-256-GCM, and
 * return both the uploadable encrypted backup and the unlocked in-memory handles.
 */
export async function createEncryptedCombinedKeyBackup(
  userId: string,
  passphrase: string
): Promise<{
  backup: EncryptedCombinedKeyBackup;
  unlockedSigningKey: UnlockedSigningKey;
  ephemeralKeyRing: EphemeralSessionKeyRing;
}> {
  const cleanPass = String(passphrase || '');
  if (cleanPass.length < 10) {
    throw new Error('Encryption passphrase must be at least 10 characters long.');
  }

  const cryptoApi = getWebCrypto();
  const subtle = cryptoApi.subtle;

  const [edPair, ephRing] = await Promise.all([
    generateRawEd25519KeyPair(),
    generateEphemeralKeyRing(userId),
  ]);

  const [ecdhPrivateJwk, ecdsaPrivateJwk] = await Promise.all([
    subtle.exportKey('jwk', ephRing.ecdhPrivateKey),
    subtle.exportKey('jwk', ephRing.ecdsaPrivateKey),
  ]);

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  cryptoApi.getRandomValues(salt);
  cryptoApi.getRandomValues(iv);

  const combinedSecretPayload: PlaintextPrivateKeysPayload = {
    v: 1,
    ed25519SeedB64: bytesToBase64(edPair.secretSeed),
    ecdhPrivateJwk,
    ecdsaPrivateJwk,
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(combinedSecretPayload));

  // Also create the compatible local Ed25519 bundle for SigningKeysSettingsSection
  const edSalt = new Uint8Array(16);
  const edIv = new Uint8Array(12);
  cryptoApi.getRandomValues(edSalt);
  cryptoApi.getRandomValues(edIv);

  try {
    const aesKey = await deriveVaultAesKey(
      cleanPass,
      salt,
      KEY_VAULT_PBKDF2_ITERATIONS,
      ['encrypt']
    );
    const cipherBuf = await subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(payloadBytes)
    );

    const edAesKey = await deriveVaultAesKey(
      cleanPass,
      edSalt,
      KEY_VAULT_PBKDF2_ITERATIONS,
      ['encrypt']
    );
    const edCipherBuf = await subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(edIv) },
      edAesKey,
      toArrayBuffer(edPair.secretSeed)
    );

    const nowIso = new Date().toISOString();
    const localEdBundle: EncryptedSigningKeyBundle = {
      v: 1,
      alg: 'Ed25519',
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: KEY_VAULT_PBKDF2_ITERATIONS,
      cipher: 'AES-256-GCM',
      userId,
      kid: edPair.kid,
      publicKey: edPair.publicKey,
      fingerprintHex: edPair.fingerprintHex,
      fingerprintWords: edPair.fingerprintWords,
      salt: bytesToBase64(edSalt),
      iv: bytesToBase64(edIv),
      encryptedPrivateKey: bytesToBase64(new Uint8Array(edCipherBuf)),
      createdAt: nowIso,
    };
    saveEncryptedKeyBundleLocally(localEdBundle);

    const backup: EncryptedCombinedKeyBackup = {
      v: 1,
      userId,
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: KEY_VAULT_PBKDF2_ITERATIONS,
      cipher: 'AES-256-GCM',
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      encryptedPrivateKeysBundle: bytesToBase64(new Uint8Array(cipherBuf)),
      ed25519PublicKey: edPair.publicKey,
      ed25519Kid: edPair.kid,
      fingerprintHex: edPair.fingerprintHex,
      fingerprintWords: edPair.fingerprintWords,
      ecdhPublicJwk: ephRing.ecdhPublicJwk,
      ecdsaPublicJwk: ephRing.ecdsaPublicJwk,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    const unlockedSigningKey = makeUnlockedSigningKeyFromSeed({
      userId,
      kid: edPair.kid,
      publicKey: edPair.publicKey,
      fingerprintHex: edPair.fingerprintHex,
      fingerprintWords: edPair.fingerprintWords,
      secretSeed: edPair.secretSeed,
    });

    return {
      backup,
      unlockedSigningKey,
      ephemeralKeyRing: ephRing,
    };
  } finally {
    zeroBuffer(edPair.secretSeed);
    zeroBuffer(payloadBytes);
  }
}

/**
 * Decrypt an encrypted key backup strictly inside browser RAM and return
 * live CryptoKey + Ed25519 signing handles.
 */
export async function unlockCombinedKeyBackup(
  backup: EncryptedCombinedKeyBackup,
  passphrase: string,
  expectedUserId?: string
): Promise<{
  unlockedSigningKey: UnlockedSigningKey;
  ephemeralKeyRing: EphemeralSessionKeyRing;
}> {
  if (!backup || backup.v !== 1 || !backup.encryptedPrivateKeysBundle) {
    throw new Error('Encrypted key backup is missing or malformed.');
  }

  const subtle = getWebCrypto().subtle;
  const salt = base64ToBytes(backup.salt);
  const iv = base64ToBytes(backup.iv);
  const cipherBytes = base64ToBytes(backup.encryptedPrivateKeysBundle);

  const aesKey = await deriveVaultAesKey(
    passphrase,
    salt,
    backup.iterations || KEY_VAULT_PBKDF2_ITERATIONS,
    ['decrypt']
  );

  let decryptedBytes: Uint8Array | null = null;
  let secretSeed: Uint8Array | null = null;

  try {
    const plainBuf = await subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(cipherBytes)
    );
    decryptedBytes = new Uint8Array(plainBuf);
    const parsed = JSON.parse(new TextDecoder().decode(decryptedBytes)) as PlaintextPrivateKeysPayload;

    if (
      !parsed ||
      parsed.v !== 1 ||
      !parsed.ed25519SeedB64 ||
      !parsed.ecdhPrivateJwk ||
      !parsed.ecdsaPrivateJwk
    ) {
      throw new Error('Decrypted key payload structure is invalid.');
    }

    secretSeed = base64ToBytes(parsed.ed25519SeedB64);
    const derivedPub = ed25519.getPublicKey(secretSeed);
    if (bytesToBase64(derivedPub) !== backup.ed25519PublicKey) {
      throw new Error('Key backup verification mismatch.');
    }

    const [ecdhPrivateKey, ecdsaPrivateKey, fp] = await Promise.all([
      subtle.importKey(
        'jwk',
        parsed.ecdhPrivateJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey', 'deriveBits']
      ),
      subtle.importKey(
        'jwk',
        parsed.ecdsaPrivateJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      ),
      computePublicKeyFingerprint(backup.ed25519PublicKey),
    ]);

    const resolvedUserId = expectedUserId || backup.userId;

    // Also refresh local Ed25519 encrypted bundle so Provenance Settings works directly
    const edSalt = new Uint8Array(16);
    const edIv = new Uint8Array(12);
    getWebCrypto().getRandomValues(edSalt);
    getWebCrypto().getRandomValues(edIv);
    const edAesKey = await deriveVaultAesKey(passphrase, edSalt, KEY_VAULT_PBKDF2_ITERATIONS, ['encrypt']);
    const edCipher = await subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(edIv) },
      edAesKey,
      toArrayBuffer(secretSeed)
    );
    saveEncryptedKeyBundleLocally({
      v: 1,
      alg: 'Ed25519',
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: KEY_VAULT_PBKDF2_ITERATIONS,
      cipher: 'AES-256-GCM',
      userId: resolvedUserId,
      kid: backup.ed25519Kid || fp.kid,
      publicKey: backup.ed25519PublicKey,
      fingerprintHex: backup.fingerprintHex || fp.fingerprintHex,
      fingerprintWords: backup.fingerprintWords || fp.fingerprintWords,
      salt: bytesToBase64(edSalt),
      iv: bytesToBase64(edIv),
      encryptedPrivateKey: bytesToBase64(new Uint8Array(edCipher)),
      createdAt: backup.createdAt,
    });

    const unlockedSigningKey = makeUnlockedSigningKeyFromSeed({
      userId: resolvedUserId,
      kid: backup.ed25519Kid || fp.kid,
      publicKey: backup.ed25519PublicKey,
      fingerprintHex: backup.fingerprintHex || fp.fingerprintHex,
      fingerprintWords: backup.fingerprintWords || fp.fingerprintWords,
      secretSeed,
    });

    const ephemeralKeyRing: EphemeralSessionKeyRing = {
      userId: resolvedUserId,
      ecdhPrivateKey,
      ecdhPublicJwk: backup.ecdhPublicJwk,
      ecdsaPrivateKey,
      ecdsaPublicJwk: backup.ecdsaPublicJwk,
    };

    return {
      unlockedSigningKey,
      ephemeralKeyRing,
    };
  } catch {
    throw new Error('Incorrect encryption passphrase. Unable to unlock keys.');
  } finally {
    zeroBuffer(decryptedBytes);
    zeroBuffer(secretSeed);
  }
}
