export const PROVENANCE_STATUS_CODES = [
  'VERIFIED',
  'UNSIGNED',
  'INVALID_SIGNATURE',
  'UNKNOWN_KEY',
  'REVOKED_KEY',
  'KEY_MISMATCH',
  'EXPIRED_ENVELOPE',
  'REPLAY',
  'CLOCK_SKEW',
  'BAD_CHAIN',
  'TARGET_MISMATCH',
] as const;

export type ProvenanceStatus = (typeof PROVENANCE_STATUS_CODES)[number];

export type ProvenanceRole = 'ORIGIN' | 'GATEWAY' | 'FORWARDER';

export type ProvenanceKeyStatus = 'ACTIVE' | 'ROTATED' | 'REVOKED';

export interface ProvenancePayloadV1 {
  v: 1;
  alg: 'Ed25519';
  kid: string;
  messageId: string;
  senderId: string;
  recipientId: string;
  source: string;
  priority: string;
  createdAt: string;
  nonce: string;
  ciphertextHash: string;
  parentHash?: string;
  ttlSeconds?: number;
  expiresAt?: string;
  textScore?: number;
  signedPriorityLabel?: string;
}

export interface ProvenanceAttestation {
  role: ProvenanceRole;
  alg: 'Ed25519';
  kid: string;
  signerId: string;
  signedAt: string;
  parentHash: string;
  sig: string; // base64 raw 64-byte Ed25519 signature
}

export interface ProvenanceEnvelopeV1 {
  v: 1;
  payload: ProvenancePayloadV1;
  chain: ProvenanceAttestation[];
}

export interface ProvenanceChainHopResult {
  role: ProvenanceRole;
  kid: string;
  signerId: string;
  signedAt: string;
  parentHash: string;
  verified: boolean;
  status: ProvenanceStatus;
  reason: string;
}

export interface ProvenanceVerificationReport {
  status: ProvenanceStatus;
  verified: boolean;
  reason: string;
  alg: 'Ed25519' | 'ECDSA' | 'NONE';
  kid?: string;
  signerId?: string;
  source?: string;
  badgeVariant: 'verified' | 'gateway' | 'unverified' | 'rejected';
  fingerprintHex?: string;
  fingerprintWords?: string[];
  createdAt?: string;
  chain: ProvenanceChainHopResult[];
  envelope?: ProvenanceEnvelopeV1;
}

export interface ProvenanceKeyRecord {
  kid: string;
  userId: string;
  publicKey: string; // base64 raw 32-byte Ed25519 public key
  status: ProvenanceKeyStatus;
  createdAt: string;
  rotatedAt?: string;
  revokedAt?: string;
  reason?: string;
  supersededByKid?: string;
  fingerprintHex: string;
  fingerprintWords: string[];
}

export type KeyLogEntryType = 'REGISTER' | 'ROTATE' | 'REVOKE';

export interface KeyLogEntry {
  index: number;
  type: KeyLogEntryType;
  kid: string;
  userId: string;
  publicKey: string;
  timestamp: string;
  reason?: string;
  previousKid?: string;
  prevHash: string;
  entryHash: string;
  serverKid: string;
  serverSignature: string;
}

export interface ProvenanceQuarantineRecord {
  id: string;
  timestamp: string;
  messageId?: string;
  senderId?: string;
  recipientId?: string;
  kid?: string;
  source?: string;
  verificationResult: ProvenanceStatus;
  reason: string;
  isDemo?: boolean;
}

export interface PinnedKeyRecord {
  userId: string;
  kid: string;
  publicKey: string;
  fingerprintHex: string;
  pinnedAt: string;
  lastLogIndex: number;
}
