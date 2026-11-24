import crypto from 'crypto';
import { redis } from '../db/redis.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';

export interface Ed25519KeyPair {
  publicKey: string;
  privateKey: string;
}

let serverKeyPair: Ed25519KeyPair | null = null;

declare global {
  var __aegisServerEd25519KeyPair: Ed25519KeyPair | undefined;
  var __aegisInvalidEd25519Warned: boolean | undefined;
}

function normalizePemInput(raw: string | undefined): string {
  return String(raw || '')
    .trim()
    .replace(/\\n/g, '\n');
}

function isValidEd25519KeyPair(publicKeyPem: string, privateKeyPem: string): boolean {
  if (!publicKeyPem || !privateKeyPem) return false;
  try {
    const pubObj = crypto.createPublicKey(publicKeyPem);
    const privObj = crypto.createPrivateKey(privateKeyPem);
    return pubObj.asymmetricKeyType === 'ed25519' && privObj.asymmetricKeyType === 'ed25519';
  } catch {
    return false;
  }
}

/**
 * Generates an Ed25519 asymmetric cryptographic keypair
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

/**
 * Get or lazily initialize the platform's root Ed25519 authority keypair
 */
export function getServerKeyPair(): Ed25519KeyPair {
  if (serverKeyPair) {
    return serverKeyPair;
  }
  if (global.__aegisServerEd25519KeyPair) {
    serverKeyPair = global.__aegisServerEd25519KeyPair;
    return serverKeyPair;
  }

  const envPub = normalizePemInput(process.env.AEGIS_PUBLIC_KEY);
  const envPriv = normalizePemInput(process.env.AEGIS_PRIVATE_KEY);

  if (envPub && envPriv && isValidEd25519KeyPair(envPub, envPriv)) {
    serverKeyPair = { publicKey: envPub, privateKey: envPriv };
  } else {
    if ((envPub || envPriv) && !global.__aegisInvalidEd25519Warned) {
      global.__aegisInvalidEd25519Warned = true;
      console.warn(
        '[Crypto] Configured AEGIS_PUBLIC_KEY/AEGIS_PRIVATE_KEY is not valid Ed25519 PEM; generating ephemeral Ed25519 PEM keypair.'
      );
    }
    serverKeyPair = generateEd25519KeyPair();
  }

  global.__aegisServerEd25519KeyPair = serverKeyPair;
  return serverKeyPair;
}

/**
 * Deterministically canonicalize JSON payload before signing
 */
export function canonicalizePayload(payload: object): Buffer {
  const sortedKeys = Object.keys(payload).sort();
  const canonicalObj: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    canonicalObj[key] = (payload as Record<string, unknown>)[key];
  }
  return Buffer.from(JSON.stringify(canonicalObj), 'utf-8');
}

/**
 * Sign payload using Ed25519 private key
 * Uses crypto.sign(null, payloadBuffer, privateKey) as required by Ed25519 in Node.js
 */
export function signPayload(payload: object, privateKey: string): string {
  const payloadBuffer = canonicalizePayload(payload);
  const signature = crypto.sign(null, payloadBuffer, privateKey);
  return signature.toString('base64');
}

/**
 * Verify payload signature using Ed25519 public key.
 * Works seamlessly in Node.js server and checks validity.
 */
export function verifyPayload(payload: object, signature: string, publicKey: string): boolean {
  try {
    const payloadBuffer = canonicalizePayload(payload);
    const signatureBuffer = Buffer.from(signature, 'base64');
    const isValid = crypto.verify(null, payloadBuffer, publicKey, signatureBuffer);
    if (!isValid) {
      logSecurityEvent({
        eventType: 'SIGNATURE_INVALID',
        severity: 'critical',
        result: 'blocked',
        ipAddress: 'internal',
        userAgent: 'ed25519-verifier',
        details: 'Ed25519 cryptographic signature verification failed for payload.',
      });
    }
    return isValid;
  } catch (err) {
    console.warn('[Crypto] Ed25519 verification failed:', err);
    logSecurityEvent({
      eventType: 'SIGNATURE_INVALID',
      severity: 'critical',
      result: 'blocked',
      ipAddress: 'internal',
      userAgent: 'ed25519-verifier',
      details: 'Ed25519 verification threw due to malformed signature or key.',
    });
    return false;
  }
}

/**
 * Sanitizes notification payloads:
 * Ephemeral fields (e.g. OTP codes, 2FA tokens, session nonces) are stored in Redis
 * with a strict 300-second TTL and permanently stripped from database logs.
 */
export async function processEphemeralSecurityData(
  notificationId: string,
  rawPayload: Record<string, any>
): Promise<{ sanitizedPayload: Record<string, any>; ephemeralExtracted: boolean }> {
  const sanitized = { ...rawPayload };
  const ephemeralKeys = ['otp', 'otpCode', 'verificationCode', 'ephemeralSecret', 'pin'];
  let ephemeralExtracted = false;

  for (const key of ephemeralKeys) {
    if (sanitized[key] !== undefined) {
      const ephemeralValue = String(sanitized[key]);
      // Save in Redis with 300-second (5 minute) TTL
      await redis.setex(`ephemeral:${notificationId}:${key}`, 300, ephemeralValue);
      // Strictly redact from permanent logs
      sanitized[key] = '[REDACTED_EPHEMERAL_300S_TTL]';
      ephemeralExtracted = true;
    }
  }

  return {
    sanitizedPayload: sanitized,
    ephemeralExtracted,
  };
}
