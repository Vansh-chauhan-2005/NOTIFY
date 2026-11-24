import crypto from 'crypto';

declare global {
  var __aegisJwtSecret: string | undefined;
}

/**
 * Returns the configured JWT signing/verification secret or a per-process
 * cryptographically random 256-bit fallback secret (never a hardcoded string).
 */
export function getJwtSecret(): string {
  const configured = (process.env.JWT_SECRET || '').trim();
  if (configured.length >= 16) {
    return configured;
  }

  if (!global.__aegisJwtSecret) {
    global.__aegisJwtSecret = crypto.randomBytes(32).toString('hex');
  }

  return global.__aegisJwtSecret;
}
