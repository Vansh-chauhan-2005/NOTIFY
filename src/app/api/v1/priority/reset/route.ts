import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { enforcePriorityRateLimit, prioritySuccess } from '../../../../../lib/priority/http.js';
import { resetUserPriorityModel } from '../../../../../lib/priority/store.js';
import { extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

export async function POST(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'reset', 20, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const ctx = extractRequestContext(request);
  const reset = resetUserPriorityModel(auth.user.userId, {
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
    reason: typeof body?.reason === 'string' ? body.reason.slice(0, 140) : undefined,
  });

  return prioritySuccess('Personalized priority weights reset to calibrated defaults.', {
    model: reset,
    activeMode: 'GLOBAL_DEFAULT',
  });
}
