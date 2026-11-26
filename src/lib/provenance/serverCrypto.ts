import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  base64ToBytes,
  buildAttestationSigningBytes,
  buildKeyLogSigningBytes,
  buildProvenanceSigningBytes,
  bytesToBase64,
  computeCiphertextHash,
  computePayloadHash,
  computePublicKeyFingerprint,
} from './canonical.js';
import type {
  ProvenanceAttestation,
  ProvenanceEnvelopeV1,
  ProvenancePayloadV1,
} from './types.js';

// ASN.1 DER prefixes for RFC 8410 Ed25519 SPKI & PKCS8
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export interface ServerProvenanceKeyInfo {
  kid: string;
  publicKey: string; // base64 raw 32-byte Ed25519 public key
  spkiPem: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  validFrom: string;
  validUntil: string;
  source: 'env' | 'local-persisted' | 'ephemeral-dev';
}

interface InternalServerKeyHolder {
  privateKey: crypto.KeyObject;
  publicKeyObj: crypto.KeyObject;
  info: ServerProvenanceKeyInfo;
}

declare global {
  var __aegisProvenanceServerKey: InternalServerKeyHolder | undefined;
}

export function rawPublicKeyBase64ToKeyObject(rawPublicKeyBase64: string): crypto.KeyObject {
  const raw = Buffer.from(base64ToBytes(rawPublicKeyBase64));
  if (raw.length !== 32) {
    throw new Error(`Invalid Ed25519 raw public key length: expected 32 bytes, got ${raw.length}`);
  }
  const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
}

export function extractRawPublicKeyBase64FromKeyObject(pubKey: crypto.KeyObject): string {
  const spkiDer = pubKey.export({ type: 'spki', format: 'der' }) as Buffer;
  if (spkiDer.length < 44) {
    throw new Error('Unexpected Ed25519 SPKI DER length.');
  }
  const raw32 = spkiDer.subarray(spkiDer.length - 32);
  return raw32.toString('base64');
}

export function rawSeedToPrivateKeyObject(seedBytes: Uint8Array): crypto.KeyObject {
  if (seedBytes.length !== 32) {
    throw new Error(`Expected 32-byte Ed25519 seed, got ${seedBytes.length}`);
  }
  const pkcs8Der = Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seedBytes)]);
  return crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
}

function getLocalServerKeyFilePath(): string {
  return path.resolve(process.cwd(), '.aegis-provenance-server-key.json');
}

function loadOrCreateLocalServerKey(): {
  privateKey: crypto.KeyObject;
  source: 'local-persisted' | 'ephemeral-dev';
  createdAtMs?: number;
} {
  if (process.env.VITEST) {
    return {
      privateKey: crypto.generateKeyPairSync('ed25519').privateKey,
      source: 'ephemeral-dev',
    };
  }

  const keyFile = getLocalServerKeyFilePath();
  try {
    if (fs.existsSync(keyFile)) {
      const parsed = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      const pem = typeof parsed?.pkcs8Pem === 'string' ? parsed.pkcs8Pem : '';
      if (pem.includes('BEGIN PRIVATE KEY')) {
        const priv = crypto.createPrivateKey(pem);
        if (priv.asymmetricKeyType === 'ed25519') {
          const createdAtMs =
            typeof parsed?.createdAt === 'string' && !Number.isNaN(Date.parse(parsed.createdAt))
              ? Date.parse(parsed.createdAt)
              : undefined;
          return { privateKey: priv, source: 'local-persisted', createdAtMs };
        }
      }
    }
  } catch {
    // Regenerate below if local key file is corrupt/unreadable
  }

  const generated = crypto.generateKeyPairSync('ed25519').privateKey;
  const createdAtIso = new Date().toISOString();
  try {
    const pkcs8Pem = generated.export({ type: 'pkcs8', format: 'pem' }).toString();
    const pubDer = crypto.createPublicKey(generated).export({ type: 'spki', format: 'der' }) as Buffer;
    const kid = crypto.createHash('sha256').update(pubDer.subarray(pubDer.length - 32)).digest('hex').slice(0, 16);
    const tmpFile = `${keyFile}.tmp`;
    fs.writeFileSync(
      tmpFile,
      JSON.stringify({ v: 1, kid, pkcs8Pem, createdAt: createdAtIso }, null, 2),
      { encoding: 'utf8', mode: 0o600 }
    );
    fs.renameSync(tmpFile, keyFile);
    return {
      privateKey: generated,
      source: 'local-persisted',
      createdAtMs: Date.parse(createdAtIso),
    };
  } catch {
    return { privateKey: generated, source: 'ephemeral-dev' };
  }
}

function loadServerKeyFromEnvOrGenerate(): InternalServerKeyHolder {
  if (global.__aegisProvenanceServerKey) {
    return global.__aegisProvenanceServerKey;
  }

  const rawEnv = process.env.PROVENANCE_SERVER_SIGNING_KEY?.trim();
  let privateKey: crypto.KeyObject;
  let source: 'env' | 'local-persisted' | 'ephemeral-dev' = 'ephemeral-dev';
  let persistedCreatedAtMs: number | undefined;

  if (rawEnv) {
    try {
      if (rawEnv.includes('BEGIN PRIVATE KEY')) {
        privateKey = crypto.createPrivateKey(rawEnv.replace(/\\n/g, '\n'));
      } else if (/^[0-9a-fA-F]{64}$/.test(rawEnv)) {
        privateKey = rawSeedToPrivateKeyObject(Buffer.from(rawEnv, 'hex'));
      } else {
        const derOrRaw = Buffer.from(rawEnv, 'base64');
        if (derOrRaw.length === 32) {
          privateKey = rawSeedToPrivateKeyObject(derOrRaw);
        } else {
          privateKey = crypto.createPrivateKey({ key: derOrRaw, format: 'der', type: 'pkcs8' });
        }
      }
      if (privateKey.asymmetricKeyType !== 'ed25519') {
        throw new Error(`Expected ed25519 private key, got ${privateKey.asymmetricKeyType}`);
      }
      source = 'env';
    } catch (err: any) {
      console.warn(
        '[Provenance] Invalid PROVENANCE_SERVER_SIGNING_KEY env value, falling back to local persisted/ephemeral Ed25519 key:',
        err?.message
      );
      const loaded = loadOrCreateLocalServerKey();
      privateKey = loaded.privateKey;
      source = loaded.source;
      persistedCreatedAtMs = loaded.createdAtMs;
    }
  } else {
    const loaded = loadOrCreateLocalServerKey();
    privateKey = loaded.privateKey;
    source = loaded.source;
    persistedCreatedAtMs = loaded.createdAtMs;
  }

  const publicKeyObj = crypto.createPublicKey(privateKey);
  const rawPubB64 = extractRawPublicKeyBase64FromKeyObject(publicKeyObj);
  const rawPubBytes = Buffer.from(rawPubB64, 'base64');
  const shaHex = crypto.createHash('sha256').update(rawPubBytes).digest('hex');
  const kid = shaHex.slice(0, 16);
  const spkiPem = publicKeyObj.export({ type: 'spki', format: 'pem' }).toString();

  // Compute deterministic hex & word fingerprint synchronously on server startup
  const first32 = shaHex.slice(0, 32).toUpperCase();
  const fingerprintHex = [0, 4, 8, 12, 16, 20, 24, 28]
    .map((idx) => first32.slice(idx, idx + 4))
    .join('-');

  const baseMs = persistedCreatedAtMs ?? Date.now();
  const holder: InternalServerKeyHolder = {
    privateKey,
    publicKeyObj,
    info: {
      kid,
      publicKey: rawPubB64,
      spkiPem,
      fingerprintHex,
      fingerprintWords: [],
      validFrom: new Date(baseMs - 60_000).toISOString(),
      validUntil: new Date(baseMs + 90 * 24 * 60 * 60 * 1000).toISOString(),
      source,
    },
  };

  // Enrich word fingerprint async-safely via canonical helper on boot
  void computePublicKeyFingerprint(rawPubB64)
    .then((fp) => {
      holder.info.fingerprintWords = fp.fingerprintWords;
    })
    .catch(() => {});

  global.__aegisProvenanceServerKey = holder;
  return holder;
}

export async function getServerProvenanceKey(): Promise<ServerProvenanceKeyInfo> {
  const holder = loadServerKeyFromEnvOrGenerate();
  if (holder.info.fingerprintWords.length === 0) {
    const fp = await computePublicKeyFingerprint(holder.info.publicKey);
    holder.info.fingerprintWords = fp.fingerprintWords;
  }
  return { ...holder.info };
}

export function signBytesWithServerKey(messageBytes: Uint8Array): {
  kid: string;
  publicKey: string;
  sig: string;
} {
  const holder = loadServerKeyFromEnvOrGenerate();
  const sigBuf = crypto.sign(null, Buffer.from(messageBytes), holder.privateKey);
  return {
    kid: holder.info.kid,
    publicKey: holder.info.publicKey,
    sig: sigBuf.toString('base64'),
  };
}

export function signBytesWithSeedServer(messageBytes: Uint8Array, seedBytes: Uint8Array): Uint8Array {
  const priv = rawSeedToPrivateKeyObject(seedBytes);
  return new Uint8Array(crypto.sign(null, Buffer.from(messageBytes), priv));
}

export function verifyEd25519Server(
  messageBytes: Uint8Array,
  signatureBytes: Uint8Array,
  rawPublicKeyBase64: string
): boolean {
  try {
    if (signatureBytes.length !== 64) return false;
    const pubKeyObj = rawPublicKeyBase64ToKeyObject(rawPublicKeyBase64);
    return crypto.verify(null, Buffer.from(messageBytes), pubKeyObj, Buffer.from(signatureBytes));
  } catch {
    return false;
  }
}

export function timingSafeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(String(a || ''), 'utf8');
  const bufB = Buffer.from(String(b || ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Signs a gateway-attested provenance envelope (e.g., webhook ingress after HMAC check
 * or server-originated direct notification when client key is absent).
 */
export async function createServerAttestedEnvelope(params: {
  messageId: string;
  senderId: string;
  recipientId: string;
  source: string;
  priority: string;
  ciphertextOrDigestInput: string;
  ivOrSalt?: string;
  role?: 'ORIGIN' | 'GATEWAY';
  existingEnvelope?: ProvenanceEnvelopeV1;
  textScore?: number;
  signedPriorityLabel?: string;
}): Promise<ProvenanceEnvelopeV1> {
  const serverInfo = await getServerProvenanceKey();
  const nowIso = new Date().toISOString();

  if (params.existingEnvelope) {
    const prevLast = params.existingEnvelope.chain[params.existingEnvelope.chain.length - 1];
    const parentHash = prevLast
      ? crypto.createHash('sha256').update(prevLast.sig).digest('hex')
      : await computePayloadHash(params.existingEnvelope.payload);

    const attestationUnsigned = {
      role: (params.role || 'GATEWAY') as ProvenanceAttestation['role'],
      alg: 'Ed25519' as const,
      kid: serverInfo.kid,
      signerId: 'aegis-server-gateway',
      signedAt: nowIso,
      parentHash,
      messageId: params.existingEnvelope.payload.messageId,
      ciphertextHash: params.existingEnvelope.payload.ciphertextHash,
    };

    const sigRes = signBytesWithServerKey(buildAttestationSigningBytes(attestationUnsigned));
    const hop: ProvenanceAttestation = {
      role: attestationUnsigned.role,
      alg: 'Ed25519',
      kid: sigRes.kid,
      signerId: attestationUnsigned.signerId,
      signedAt: nowIso,
      parentHash,
      sig: sigRes.sig,
    };

    return {
      v: 1,
      payload: params.existingEnvelope.payload,
      chain: [...params.existingEnvelope.chain, hop],
    };
  }

  const ciphertextHash = await computeCiphertextHash(
    params.ciphertextOrDigestInput,
    params.ivOrSalt || ''
  );
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload: ProvenancePayloadV1 = {
    v: 1,
    alg: 'Ed25519',
    kid: serverInfo.kid,
    messageId: params.messageId,
    senderId: params.senderId,
    recipientId: params.recipientId,
    source: params.source,
    priority: params.priority,
    createdAt: nowIso,
    nonce,
    ciphertextHash,
    ...(typeof params.textScore === 'number' && Number.isFinite(params.textScore)
      ? { textScore: Number(Math.max(0, Math.min(1, params.textScore)).toFixed(4)) }
      : {}),
    ...(params.signedPriorityLabel ? { signedPriorityLabel: params.signedPriorityLabel } : {}),
  };

  const payloadHash = await computePayloadHash(payload);
  const sigRes = signBytesWithServerKey(buildProvenanceSigningBytes(payload));

  const hop: ProvenanceAttestation = {
    role: params.role || 'GATEWAY',
    alg: 'Ed25519',
    kid: sigRes.kid,
    signerId: params.role === 'ORIGIN' ? params.senderId : 'aegis-server-gateway',
    signedAt: nowIso,
    parentHash: payloadHash,
    sig: sigRes.sig,
  };

  return {
    v: 1,
    payload,
    chain: [hop],
  };
}

export function signKeyLogEntryServer(entryUnsigned: {
  index: number;
  type: 'REGISTER' | 'ROTATE' | 'REVOKE';
  kid: string;
  userId: string;
  publicKey: string;
  timestamp: string;
  reason?: string;
  previousKid?: string;
  prevHash: string;
  entryHash: string;
}): { serverKid: string; serverSignature: string } {
  const res = signBytesWithServerKey(buildKeyLogSigningBytes(entryUnsigned));
  return { serverKid: res.kid, serverSignature: res.sig };
}

export function bytesBase64Encode(bytes: Uint8Array): string {
  return bytesToBase64(bytes);
}
