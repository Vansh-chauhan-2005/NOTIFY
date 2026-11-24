import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { revokeUserProvenanceKey } from '../../../../../../lib/provenance/store.js';
import { checkProvenanceRouteRateLimit, provenanceJson } from '../../../../../../lib/provenance/http.js';

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const rl = checkProvenanceRouteRateLimit(`prov_rev:${auth.user.userId}`, 20, 60_000);
  if (!rl.allowed) {
    return provenanceJson(
      { success: false, message: `Rate limit exceeded. Retry in ${rl.retryAfterSeconds}s.` },
      429
    );
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const isAdmin = String(auth.user.role || '').toUpperCase() === 'ADMIN';
  const result = await revokeUserProvenanceKey({
    userId: auth.user.userId,
    kid: body?.kid ? String(body.kid).trim() : undefined,
    reason: body?.reason ? String(body.reason).slice(0, 160) : 'User-initiated key revocation',
    isAdmin,
  });

  return provenanceJson(
    {
      success: result.ok,
      message: result.message,
      data: result.ok
        ? {
            revokedKey: result.revokedKey,
            logEntry: result.logEntry,
          }
        : null,
    },
    result.status
  );
}
