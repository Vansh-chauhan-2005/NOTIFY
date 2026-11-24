import { enforcePriorityRateLimit, prioritySuccess } from '../../../../../lib/priority/http.js';
import { getPriorityAdminStats } from '../../../../../lib/priority/store.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

export async function GET(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'stats', 60, 60_000);
  if (limited) return limited;

  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const stats = getPriorityAdminStats();
  return prioritySuccess('Priority engine admin statistics retrieved.', stats);
}
