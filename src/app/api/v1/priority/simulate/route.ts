import { enforcePriorityRateLimit, priorityError, prioritySuccess } from '../../../../../lib/priority/http.js';
import { runPrioritySimulationSuite } from '../../../../../lib/priority/simulator.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

export async function POST(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'simulate', 30, 60_000);
  if (limited) return limited;

  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return priorityError(400, 'Invalid JSON body.');
  }

  if (body?.demoMode !== true) {
    return priorityError(
      403,
      'Demo Mode is OFF. Enable Demo Mode explicitly (demoMode: true) to run isolated priority simulations.'
    );
  }

  const ctx = extractRequestContext(request);
  const suite = runPrioritySimulationSuite({
    scenarioId: typeof body?.scenarioId === 'string' ? body.scenarioId : undefined,
    actorUserId: auth.user.userId,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  return prioritySuccess('Isolated priority simulation suite executed.', suite);
}
