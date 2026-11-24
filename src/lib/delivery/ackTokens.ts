import crypto from 'crypto';

export interface AckTokenPayload {
  j: string; // jobId
  u: string; // userId
  n: string; // single-use nonce
  exp: number; // expiry epoch ms
}

const ACK_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes
const ACK_IP_RATE_LIMIT = 30; // max 30 verification attempts per IP per minute
const ACK_IP_WINDOW_MS = 60 * 1000;

declare global {
  var __aegisEphemeralAckSecret: string | undefined;
  var __aegisUsedAckNonces: Map<string, number> | undefined;
  var __aegisAckIpWindow: Map<string, number[]> | undefined;
}

function getAckSecret(): string {
  const envSecret = process.env.DELIVERY_ACK_SECRET?.trim();
  if (envSecret && envSecret.length >= 16) {
    return envSecret;
  }
  if (!global.__aegisEphemeralAckSecret) {
    global.__aegisEphemeralAckSecret = crypto.randomBytes(32).toString('hex');
  }
  return global.__aegisEphemeralAckSecret;
}

function getUsedNonceMap(): Map<string, number> {
  if (!global.__aegisUsedAckNonces) {
    global.__aegisUsedAckNonces = new Map();
  }
  return global.__aegisUsedAckNonces;
}

function getIpWindowMap(): Map<string, number[]> {
  if (!global.__aegisAckIpWindow) {
    global.__aegisAckIpWindow = new Map();
  }
  return global.__aegisAckIpWindow;
}

function pruneUsedNonces(now: number) {
  const map = getUsedNonceMap();
  for (const [nonce, exp] of Array.from(map.entries())) {
    if (exp <= now) {
      map.delete(nonce);
    }
  }
}

export function checkAckRateLimit(ipAddress: string, now: number = Date.now()): boolean {
  const map = getIpWindowMap();
  const key = ipAddress || 'local';
  const cutoff = now - ACK_IP_WINDOW_MS;
  const arr = (map.get(key) || []).filter((ts) => ts > cutoff);
  arr.push(now);
  map.set(key, arr);
  return arr.length <= ACK_IP_RATE_LIMIT;
}

export function createSignedAckToken(
  jobId: string,
  userId: string,
  ttlMs: number = ACK_TOKEN_TTL_MS
): { token: string; expiresAt: string } {
  const now = Date.now();
  const exp = now + ttlMs;
  const payload: AckTokenPayload = {
    j: jobId,
    u: userId,
    n: crypto.randomBytes(12).toString('hex'),
    exp,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getAckSecret())
    .update(encodedPayload, 'utf8')
    .digest('base64url');

  return {
    token: `${encodedPayload}.${sig}`,
    expiresAt: new Date(exp).toISOString(),
  };
}

export function buildSignedAckUrl(params: {
  baseUrl?: string;
  jobId: string;
  userId: string;
}): { url: string; token: string; expiresAt: string } {
  const { token, expiresAt } = createSignedAckToken(params.jobId, params.userId);
  const rawBase =
    params.baseUrl?.trim() ||
    process.env.APP_URL?.trim() ||
    'http://localhost:3000';
  const cleanBase = rawBase.replace(/\/+$/, '');
  return {
    url: `${cleanBase}/api/v1/delivery/${encodeURIComponent(params.jobId)}/ack?token=${encodeURIComponent(token)}`,
    token,
    expiresAt,
  };
}

export function verifyAndConsumeAckToken(
  token: string,
  expectedJobId?: string,
  now: number = Date.now()
): { valid: boolean; reason?: string; payload?: AckTokenPayload } {
  const clean = String(token || '').trim();
  const dotIdx = clean.indexOf('.');
  if (dotIdx <= 0 || dotIdx === clean.length - 1) {
    return { valid: false, reason: 'Malformed acknowledgement token format.' };
  }

  const encodedPayload = clean.slice(0, dotIdx);
  const providedSig = clean.slice(dotIdx + 1);
  const expectedSig = crypto
    .createHmac('sha256', getAckSecret())
    .update(encodedPayload, 'utf8')
    .digest('base64url');

  const a = Buffer.from(expectedSig, 'utf8');
  const b = Buffer.from(providedSig, 'utf8');
  if (a.length !== b.length || a.length === 0) {
    const dummy = Buffer.alloc(Math.max(1, a.length), 0);
    crypto.timingSafeEqual(dummy, dummy);
    return { valid: false, reason: 'Invalid acknowledgement signature.' };
  }

  if (!crypto.timingSafeEqual(a, b)) {
    return { valid: false, reason: 'Invalid acknowledgement signature.' };
  }

  let parsed: AckTokenPayload;
  try {
    parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'Corrupt acknowledgement token payload.' };
  }

  if (!parsed?.j || !parsed?.u || !parsed?.n || typeof parsed.exp !== 'number') {
    return { valid: false, reason: 'Incomplete acknowledgement token fields.' };
  }

  if (expectedJobId && parsed.j !== expectedJobId) {
    return { valid: false, reason: 'Acknowledgement token does not match target delivery job.' };
  }

  if (now > parsed.exp) {
    return { valid: false, reason: 'Acknowledgement link has expired (15-minute limit).' };
  }

  pruneUsedNonces(now);
  const used = getUsedNonceMap();
  if (used.has(parsed.n)) {
    return { valid: false, reason: 'Acknowledgement link has already been used.' };
  }

  used.set(parsed.n, parsed.exp);
  return { valid: true, payload: parsed };
}
