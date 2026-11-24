import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { DEFAULT_DEDUP_CONFIG } from '../../../../../lib/dedup/config.js';
import { dedupError, dedupSuccess, enforceDedupRateLimit } from '../../../../../lib/dedup/http.js';
import {
  assertNoPlaintextOrVectors,
  getUserDedupSettings,
  updateUserDedupSettings,
} from '../../../../../lib/dedup/store.js';

export async function GET(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'config-get', 90, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  const userId = auth.ok && auth.user ? auth.user.userId : 'guest';
  const settings = getUserDedupSettings(userId);

  return dedupSuccess('Deduplication configuration retrieved.', {
    config: DEFAULT_DEDUP_CONFIG,
    settings,
  });
}

export async function PUT(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'config-put', 60, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return dedupError(400, 'Invalid JSON body.');
  }

  const firewall = assertNoPlaintextOrVectors(body);
  if (!firewall.ok) {
    return dedupError(400, firewall.reason);
  }

  const updated = updateUserDedupSettings(auth.user.userId, {
    dedupEnabled: typeof body?.dedupEnabled === 'boolean' ? body.dedupEnabled : undefined,
    mergeThreshold: typeof body?.mergeThreshold === 'number' ? body.mergeThreshold : undefined,
    reviewThreshold: typeof body?.reviewThreshold === 'number' ? body.reviewThreshold : undefined,
    windowMinutes: typeof body?.windowMinutes === 'number' ? body.windowMinutes : undefined,
    neverMergeCategories: Array.isArray(body?.neverMergeCategories)
      ? body.neverMergeCategories
      : undefined,
  });

  return dedupSuccess('Deduplication preferences updated.', {
    settings: updated,
  });
}
