import { DEFAULT_DEDUP_CONFIG } from '../../../../../lib/dedup/config.js';
import { dedupSuccess, enforceDedupRateLimit } from '../../../../../lib/dedup/http.js';
import { getDedupStatsSnapshot } from '../../../../../lib/dedup/store.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

export async function GET(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'stats', 60, 60_000);
  if (limited) return limited;

  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const stats = getDedupStatsSnapshot();
  return dedupSuccess('Deduplication admin statistics retrieved.', {
    stats,
    evaluation: DEFAULT_DEDUP_CONFIG.evaluation,
    modelCard: DEFAULT_DEDUP_CONFIG.modelCard,
  });
}
