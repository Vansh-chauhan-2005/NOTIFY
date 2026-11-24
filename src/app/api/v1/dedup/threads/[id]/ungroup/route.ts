import { authenticateUserRequest } from '../../../../../../../lib/auth/requestAuth.js';
import { dedupError, dedupSuccess, enforceDedupRateLimit } from '../../../../../../../lib/dedup/http.js';
import {
  assertNoPlaintextOrVectors,
  ungroupServerThread,
} from '../../../../../../../lib/dedup/store.js';
import { extractRequestContext } from '../../../../../../../lib/telemetry/securityLogger.js';

export async function POST(
  request: Request,
  context: { params: { id: string } | Promise<{ id: string }> }
): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'threads-ungroup', 60, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: unknown = {};
  try {
    const txt = await request.text();
    if (txt) body = JSON.parse(txt);
  } catch {
    return dedupError(400, 'Invalid JSON body.');
  }

  const firewall = assertNoPlaintextOrVectors(body);
  if (!firewall.ok) {
    return dedupError(400, firewall.reason);
  }

  const resolvedParams = await context?.params;
  const threadId = String(resolvedParams?.id || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(threadId)) {
    return dedupError(400, 'Invalid threadId format.');
  }

  const reqCtx = extractRequestContext(request);
  const res = ungroupServerThread({
    userId: auth.user.userId,
    threadId,
    isAdmin: String(auth.user.role || '').toUpperCase() === 'ADMIN',
    ipAddress: reqCtx.ipAddress,
    userAgent: reqCtx.userAgent,
  });

  if (!res.ok) {
    return dedupError(403, res.message);
  }

  return dedupSuccess(res.message, {
    splitThreads: res.splitThreads,
    settings: res.settings,
  });
}
