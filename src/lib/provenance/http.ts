export function provenanceJson(
  payload: {
    success: boolean;
    message: string;
    data?: unknown;
  },
  status: number = 200
): Response {
  return Response.json(payload, {
    status,
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      Pragma: 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

const slidingWindowMap = new Map<string, number[]>();

export function checkProvenanceRouteRateLimit(
  bucketKey: string,
  maxRequests: number = 60,
  windowMs: number = 60_000
): { allowed: boolean; retryAfterSeconds: number } {
  const nowMs = Date.now();
  const timestamps = (slidingWindowMap.get(bucketKey) || []).filter(
    (ts) => nowMs - ts < windowMs
  );
  if (timestamps.length >= maxRequests) {
    const oldest = timestamps[0] || nowMs;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((windowMs - (nowMs - oldest)) / 1000)
    );
    slidingWindowMap.set(bucketKey, timestamps);
    return { allowed: false, retryAfterSeconds };
  }
  timestamps.push(nowMs);
  slidingWindowMap.set(bucketKey, timestamps);
  return { allowed: true, retryAfterSeconds: 0 };
}
