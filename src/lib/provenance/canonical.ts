import type {
  ProvenanceAttestation,
  ProvenanceKeyRecord,
  ProvenancePayloadV1,
} from './types.js';

export const PROVENANCE_DOMAIN_PREFIX = 'AEGIS-PROVENANCE-v1\0';
export const ATTESTATION_DOMAIN_PREFIX = 'AEGIS-ATTESTATION-v1\0';
export const KEYLOG_DOMAIN_PREFIX = 'AEGIS-KEYLOG-v1\0';

const WORD_LIST_256 = [
  'amber', 'anchor', 'anvil', 'apex', 'arch', 'arrow', 'ash', 'atlas',
  'atom', 'aurora', 'badge', 'balsa', 'bamboo', 'banner', 'bark', 'basalt',
  'basin', 'beacon', 'beam', 'berry', 'birch', 'blade', 'blaze', 'bloom',
  'bolt', 'bond', 'bonsai', 'border', 'boulder', 'brace', 'branch', 'brass',
  'breeze', 'brick', 'bridge', 'brim', 'brook', 'brush', 'buckler', 'bulb',
  'cairn', 'calm', 'canal', 'candle', 'canon', 'canyon', 'cape', 'carbon',
  'card', 'cargo', 'carve', 'castle', 'cedar', 'cell', 'chain', 'chalk',
  'champ', 'chant', 'charm', 'chart', 'chase', 'chess', 'chime', 'chord',
  'cinder', 'cipher', 'citadel', 'clay', 'clear', 'cliff', 'cloak', 'clock',
  'cloud', 'clover', 'cobalt', 'cobra', 'coil', 'coin', 'comet', 'compass',
  'conduit', 'coral', 'cord', 'core', 'cork', 'corner', 'corona', 'cosmo',
  'cotton', 'cover', 'craft', 'crane', 'crate', 'creek', 'crest', 'crisp',
  'crown', 'crux', 'crystal', 'cube', 'current', 'curve', 'cycle', 'cypress',
  'dagger', 'daisy', 'dawn', 'delta', 'depth', 'desert', 'dial', 'diamond',
  'diode', 'disk', 'dock', 'dome', 'dove', 'draft', 'dragon', 'drift',
  'drum', 'dune', 'dusk', 'dust', 'eagle', 'earth', 'echo', 'edge',
  'elder', 'ember', 'emerald', 'engine', 'epoch', 'equinox', 'etch', 'ether',
  'falcon', 'fable', 'facet', 'fern', 'ferry', 'fiber', 'field', 'finch',
  'fjord', 'flame', 'flare', 'flint', 'float', 'flora', 'flute', 'focus',
  'forge', 'fort', 'fossil', 'fountain', 'fox', 'frame', 'frost', 'fuel',
  'gable', 'galaxy', 'gale', 'garden', 'garnet', 'gate', 'gauge', 'gavel',
  'gear', 'gem', 'geyser', 'glacier', 'glade', 'glass', 'gleam', 'glide',
  'globe', 'glow', 'glyph', 'gold', 'gorge', 'grain', 'granite', 'graph',
  'gravel', 'grid', 'griffin', 'grove', 'guard', 'guide', 'gulf', 'gust',
  'harbor', 'harp', 'haven', 'hawk', 'hazel', 'hearth', 'helix', 'helm',
  'herald', 'heron', 'hex', 'horizon', 'horn', 'hound', 'hue', 'hull',
  'hymn', 'ibis', 'ice', 'icon', 'index', 'indigo', 'ingot', 'ink',
  'inlet', 'iris', 'iron', 'island', 'ivory', 'jade', 'jasper', 'javelin',
  'jet', 'jewel', 'jolt', 'journal', 'juniper', 'kaolin', 'keel', 'keeper',
  'kelp', 'kestrel', 'key', 'kiln', 'kinetic', 'kite', 'knight', 'knot',
];

function getSubtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('WebCrypto SubtleCrypto is unavailable in this runtime.');
  }
  return c.subtle;
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Invalid hex string.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
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

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Deterministic JCS-style canonical JSON serialization:
 * - Object keys sorted recursively in deterministic UTF-16 code unit order
 * - Undefined object properties omitted
 * - Arrays preserve index order
 * - Zero whitespace
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Non-finite number cannot be canonically serialized.');
    }
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (t === 'string') {
    return JSON.stringify(value);
  }
  if (t === 'undefined') {
    return 'null';
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => (item === undefined ? 'null' : canonicalizeJson(item)));
    return `[${items.join(',')}]`;
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(`${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`Unsupported value type in canonical JSON: ${t}`);
}

export function buildProvenanceSigningBytes(
  payload: ProvenancePayloadV1,
  domainPrefix: string = PROVENANCE_DOMAIN_PREFIX
): Uint8Array {
  return utf8ToBytes(`${domainPrefix}${canonicalizeJson(payload)}`);
}

export function buildAttestationSigningBytes(attestationData: {
  role: ProvenanceAttestation['role'];
  alg: 'Ed25519';
  kid: string;
  signerId: string;
  signedAt: string;
  parentHash: string;
  messageId: string;
  ciphertextHash: string;
}): Uint8Array {
  return utf8ToBytes(`${ATTESTATION_DOMAIN_PREFIX}${canonicalizeJson(attestationData)}`);
}

export function buildKeyLogSigningBytes(entryUnsigned: {
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
}): Uint8Array {
  return utf8ToBytes(`${KEYLOG_DOMAIN_PREFIX}${canonicalizeJson(entryUnsigned)}`);
}

export async function computeSha256Hex(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  const digest = await getSubtle().digest('SHA-256', toArrayBuffer(bytes));
  return bytesToHex(new Uint8Array(digest));
}

export async function computeCiphertextHash(ciphertext: string, iv: string): Promise<string> {
  return computeSha256Hex(`${ciphertext}:${iv}`);
}

export async function computePayloadHash(payload: ProvenancePayloadV1): Promise<string> {
  return computeSha256Hex(buildProvenanceSigningBytes(payload));
}

export async function computeKeyIdFromRawPublicKey(rawPubBytes: Uint8Array): Promise<string> {
  if (rawPubBytes.length !== 32) {
    throw new Error(`Expected 32-byte raw Ed25519 public key, received ${rawPubBytes.length} bytes.`);
  }
  const hex = await computeSha256Hex(rawPubBytes);
  return hex.slice(0, 16);
}

export function formatFingerprintFromSha256(shaHex: string): {
  fingerprintHex: string;
  fingerprintWords: string[];
} {
  const clean = shaHex.toLowerCase().replace(/[^0-9a-f]/g, '').padEnd(64, '0');
  const first32 = clean.slice(0, 32).toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < first32.length; i += 4) {
    groups.push(first32.slice(i, i + 4));
  }
  const words: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    const byteVal = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    words.push(WORD_LIST_256[byteVal % WORD_LIST_256.length]);
  }
  return {
    fingerprintHex: groups.join('-'),
    fingerprintWords: words,
  };
}

export async function computePublicKeyFingerprint(rawPublicKeyBase64: string): Promise<{
  kid: string;
  fingerprintHex: string;
  fingerprintWords: string[];
}> {
  const raw = base64ToBytes(rawPublicKeyBase64);
  if (raw.length !== 32) {
    throw new Error('Invalid Ed25519 public key length (must be 32 raw bytes).');
  }
  const digest = await computeSha256Hex(raw);
  const { fingerprintHex, fingerprintWords } = formatFingerprintFromSha256(digest);
  return {
    kid: digest.slice(0, 16),
    fingerprintHex,
    fingerprintWords,
  };
}

export async function computeKeyLogEntryHash(params: {
  prevHash: string;
  index: number;
  type: 'REGISTER' | 'ROTATE' | 'REVOKE';
  kid: string;
  userId: string;
  publicKey: string;
  timestamp: string;
  reason?: string;
  previousKid?: string;
}): Promise<string> {
  const canonicalEntry = canonicalizeJson({
    index: params.index,
    type: params.type,
    kid: params.kid,
    userId: params.userId,
    publicKey: params.publicKey,
    timestamp: params.timestamp,
    reason: params.reason,
    previousKid: params.previousKid,
  });
  return computeSha256Hex(`${params.prevHash}${canonicalEntry}`);
}

export function isKeyValidForTimestamp(
  keyRecord: ProvenanceKeyRecord,
  signedAtIso: string
): { valid: boolean; status: 'VERIFIED' | 'REVOKED_KEY' | 'KEY_MISMATCH'; reason?: string } {
  const signedAtMs = Date.parse(signedAtIso);
  if (Number.isNaN(signedAtMs)) {
    return { valid: false, status: 'KEY_MISMATCH', reason: 'Invalid envelope timestamp.' };
  }

  if (keyRecord.status === 'REVOKED' && keyRecord.revokedAt) {
    const revokedMs = Date.parse(keyRecord.revokedAt);
    if (!Number.isNaN(revokedMs) && signedAtMs >= revokedMs) {
      return {
        valid: false,
        status: 'REVOKED_KEY',
        reason: `Signing key ${keyRecord.kid} was revoked at ${keyRecord.revokedAt}${
          keyRecord.reason ? ` (${keyRecord.reason})` : ''
        }.`,
      };
    }
  }

  if (keyRecord.status === 'ROTATED' && keyRecord.rotatedAt) {
    const rotatedMs = Date.parse(keyRecord.rotatedAt);
    if (!Number.isNaN(rotatedMs) && signedAtMs > rotatedMs) {
      return {
        valid: false,
        status: 'KEY_MISMATCH',
        reason: `Signing key ${keyRecord.kid} was rotated at ${keyRecord.rotatedAt}; post-rotation signatures require the successor key${
          keyRecord.supersededByKid ? ` (${keyRecord.supersededByKid})` : ''
        }.`,
      };
    }
  }

  return { valid: true, status: 'VERIFIED' };
}
