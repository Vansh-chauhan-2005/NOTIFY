import crypto from 'crypto';

declare global {
  var __aegisInternalWebhookToken: string | undefined;
}

/**
 * Process-local CSPRNG secret authenticating internal webhook-to-ingest dispatch.
 * Prevents external callers from forging X-Aegis-Gateway-Webhook headers.
 */
export function getInternalWebhookToken(): string {
  if (!global.__aegisInternalWebhookToken) {
    global.__aegisInternalWebhookToken = crypto.randomBytes(32).toString('hex');
  }
  return global.__aegisInternalWebhookToken;
}

export function isValidInternalWebhookToken(candidate: string | null | undefined): boolean {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    return false;
  }
  const expected = getInternalWebhookToken();
  const bufA = Buffer.from(candidate, 'utf8');
  const bufB = Buffer.from(expected, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
