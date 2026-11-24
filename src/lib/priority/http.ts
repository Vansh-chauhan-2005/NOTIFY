import { parseTrustedClientIp } from '../gateway/identity.js';

const rateBuckets = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(
  key: string,
  limit: number,
  windowMs: number
): { allowed: boolean; resetAt: number } {
  const now = Date.now();
  const existing = rateBuckets.get(key);
  if (!existing || now >= existing.resetAt) {
    const resetAt = now + windowMs;
    rateBuckets.set(key, { count: 1, resetAt });
    return { allowed: true, resetAt };
  }
  existing.count += 1;
  return { allowed: existing.count <= limit, resetAt: existing.resetAt };
}

export function getClientIpFromRequest(request: Request): string {
  return parseTrustedClientIp({
    socketRemoteAddress: request.headers.get('x-real-ip') || '127.0.0.1',
    xForwardedFor: request.headers.get('x-forwarded-for'),
  });
}

export function enforcePriorityRateLimit(
  request: Request,
  scope: string,
  limit = 90,
  windowMs = 60_000
): Response | null {
  const ip = getClientIpFromRequest(request);
  const res = checkRateLimit(`priority:${scope}:${ip}`, limit, windowMs);
  if (!res.allowed) {
    return Response.json(
      {
        success: false,
        message: 'Too many priority engine requests. Please slow down briefly.',
        data: { retryAfterMs: Math.max(0, res.resetAt - Date.now()) },
      },
      { status: 429 }
    );
  }
  return null;
}

export function priorityError(status: number, message: string, data: unknown = null): Response {
  return Response.json(
    {
      success: false,
      message,
      data,
    },
    { status }
  );
}

export function prioritySuccess<T>(message: string, data: T, status = 200): Response {
  return Response.json(
    {
      success: true,
      message,
      data,
    },
    { status }
  );
}
