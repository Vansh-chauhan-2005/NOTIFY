export const ALLOWED_EPHEMERAL_TTL_PRESETS = [60, 300, 900] as const;
export type AllowedEphemeralTtlPreset = (typeof ALLOWED_EPHEMERAL_TTL_PRESETS)[number];

export const MIN_EPHEMERAL_TTL_SECONDS = 60;
export const MAX_EPHEMERAL_TTL_SECONDS = 900;
export const FALLBACK_EPHEMERAL_TTL_SECONDS = 300;
export const READ_ONCE_GRACE_SECONDS = 10;

export type EphemeralMessageStatus = 'ACTIVE' | 'READ' | 'BURNED' | 'EXPIRED';
export type EphemeralTombstoneReason = 'EXPIRED' | 'BURNED' | 'READ_ONCE';
export type EphemeralPriority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Resolves configured default TTL from server env EPHEMERAL_TTL_SECONDS (default 300s).
 * Clamped safely within [60, 900]. Safe to evaluate in browser too (falls back to 300).
 */
export function getDefaultEphemeralTtlSeconds(): number {
  const raw =
    typeof process !== 'undefined' && process?.env?.EPHEMERAL_TTL_SECONDS
      ? Number(process.env.EPHEMERAL_TTL_SECONDS)
      : FALLBACK_EPHEMERAL_TTL_SECONDS;
  if (!Number.isFinite(raw) || raw < MIN_EPHEMERAL_TTL_SECONDS) {
    return FALLBACK_EPHEMERAL_TTL_SECONDS;
  }
  return Math.min(MAX_EPHEMERAL_TTL_SECONDS, Math.round(raw));
}

export interface TtlValidationResult {
  valid: boolean;
  ttlSeconds: number;
  clamped?: boolean;
  error?: string;
}

/**
 * Server-authoritative TTL enforcement.
 * Standard mode permits ONLY presets [60, 300, 900] (never > 900s).
 * Isolated Demo Simulator mode permits short TTLs [2..30]s for fast automated verification.
 */
export function validateAndResolveTtlSeconds(
  requestedTtl?: unknown,
  options: { allowDemoShortTtl?: boolean } = {}
): TtlValidationResult {
  const defaultTtl = getDefaultEphemeralTtlSeconds();

  if (requestedTtl === undefined || requestedTtl === null || requestedTtl === '') {
    return { valid: true, ttlSeconds: defaultTtl };
  }

  const num = Number(requestedTtl);
  if (!Number.isFinite(num) || !Number.isInteger(num)) {
    return {
      valid: false,
      ttlSeconds: defaultTtl,
      error: 'TTL must be an integer number of seconds.',
    };
  }

  if (options.allowDemoShortTtl) {
    if (
      (num >= 1 && num <= 30) ||
      ALLOWED_EPHEMERAL_TTL_PRESETS.includes(num as AllowedEphemeralTtlPreset)
    ) {
      return { valid: true, ttlSeconds: num };
    }
    return {
      valid: false,
      ttlSeconds: 10,
      error: 'Demo simulator TTL must be 1–30s or a standard preset (60, 300, 900s).',
    };
  }

  if (num > MAX_EPHEMERAL_TTL_SECONDS) {
    return {
      valid: false,
      ttlSeconds: MAX_EPHEMERAL_TTL_SECONDS,
      error: `Requested TTL (${num}s) exceeds the server maximum of ${MAX_EPHEMERAL_TTL_SECONDS}s (15 minutes).`,
    };
  }

  if (!ALLOWED_EPHEMERAL_TTL_PRESETS.includes(num as AllowedEphemeralTtlPreset)) {
    return {
      valid: false,
      ttlSeconds: defaultTtl,
      error: `Unsupported TTL (${num}s). Allowed presets are ${ALLOWED_EPHEMERAL_TTL_PRESETS.join(', ')} seconds.`,
    };
  }

  return { valid: true, ttlSeconds: num };
}

export function computeExpiryTimestamps(
  nowMs: number,
  ttlSeconds: number
): {
  createdAtMs: number;
  createdAtIso: string;
  expiresAtMs: number;
  expiresAtIso: string;
} {
  const safeNow = Math.floor(nowMs);
  const safeTtlMs = Math.max(1000, Math.floor(ttlSeconds * 1000));
  const expiresAtMs = safeNow + safeTtlMs;
  return {
    createdAtMs: safeNow,
    createdAtIso: new Date(safeNow).toISOString(),
    expiresAtMs,
    expiresAtIso: new Date(expiresAtMs).toISOString(),
  };
}

export function formatCountdownMmSs(remainingSeconds: number): string {
  const clamped = Math.max(0, Math.floor(remainingSeconds));
  const mins = Math.floor(clamped / 60);
  const secs = clamped % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function buildEphemeralGenericAlertText(ttlSeconds: number): string {
  const mins = Math.max(1, Math.round(ttlSeconds / 60));
  return `You have a new self-destructing message. Open AegisNotify to read it. It expires in ${mins} minute${mins === 1 ? '' : 's'}.`;
}

/**
 * Honesty-first documentation of the 4-layer ephemeral destruction architecture.
 */
export const EPHEMERAL_DELETION_LAYERS = [
  {
    layer: '1. Access Denied at Expiry',
    description:
      'Both server API routes (HTTP 410 Gone via server clock) and Firestore security rules (request.time < expiresAt) immediately block reads the millisecond expiry passes.',
  },
  {
    layer: '2. Key Destruction (Crypto-Shredding)',
    description:
      'Each message uses a unique 256-bit DEK wrapped for the recipient. At burn or expiry, the wrapped key in ephemeralKeys is overwritten and deleted FIRST, making ciphertext permanently undecryptable.',
  },
  {
    layer: '3. Server Sweeper Deletion',
    description:
      'An idempotent Express background worker sweeps every 5 seconds (and catches up immediately on server startup), overwriting and deleting expired ciphertext documents and writing metadata-only tombstones.',
  },
  {
    layer: '4. Firestore TTL Policy (Safety Net — Not Instant)',
    description:
      'An optional Google Cloud Firestore TTL policy on the expireAt field acts as an asynchronous storage cleanup net. Firestore TTL background deletion is NOT instant and can lag by minutes or hours; layers 1–3 enforce immediate unreadability.',
  },
] as const;

export const SCREENSHOT_HONESTY_NOTE =
  'Honesty notice: A web application cannot prevent the recipient from taking a screenshot, photographing the screen, or manually copying displayed text while an item is open.';
