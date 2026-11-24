import { parseTrustedClientIp } from '../gateway/identity.js';

const dedupRateBuckets = new Map<string, { count: number; resetAt: number }>();

function checkBucket(key: string, limit: number, windowMs: number) {
  const now = Date.now();
  const entry = dedupRateBuckets.get(key);
  if (!entry || now >= entry.resetAt) {
    const resetAt = now + windowMs;
    dedupRateBuckets.set(key, { count: 1, resetAt });
    return { allowed: true, resetAt };
  }
  entry.count += 1;
  return { allowed: entry.count <= limit, resetAt: entry.resetAt };
}

export function getDedupClientIp(request: Request): string {
  return parseTrustedClientIp({
    socketRemoteAddress: request.headers.get('x-real-ip') || '127.0.0.1',
    xForwardedFor: request.headers.get('x-forwarded-for'),
  });
}

export function enforceDedupRateLimit(
  request: Request,
  scope: string,
  limit = 90,
  windowMs = 60_000
): Response | null {
  const ip = getDedupClientIp(request);
  const res = checkBucket(`dedup:${scope}:${ip}`, limit, windowMs);
  if (!res.allowed) {
    return Response.json(
      {
        success: false,
        message: 'Too many deduplication requests. Please wait briefly.',
        data: { retryAfterMs: Math.max(0, res.resetAt - Date.now()) },
      },
      { status: 429 }
    );
  }
  return null;
}

export function dedupError(status: number, message: string, data: unknown = null): Response {
  return Response.json(
    {
      success: false,
      message,
      data,
    },
    { status }
  );
}

export function dedupSuccess<T>(message: string, data: T, status = 200): Response {
  return Response.json(
    {
      success: true,
      message,
      data,
    },
    { status }
  );
}
