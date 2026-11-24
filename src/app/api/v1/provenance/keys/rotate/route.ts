import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { rotateUserProvenanceKey } from '../../../../../../lib/provenance/store.js';
import { checkProvenanceRouteRateLimit, provenanceJson } from '../../../../../../lib/provenance/http.js';

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const rl = checkProvenanceRouteRateLimit(`prov_rot:${auth.user.userId}`, 20, 60_000);
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
    return provenanceJson({ success: false, message: 'Invalid JSON request body.' }, 400);
  }

  if (body?.privateKey || body?.secretKey || body?.secretSeed) {
    return provenanceJson(
      {
        success: false,
        message: 'Rejected: private signing keys must NEVER be transmitted to the server.',
      },
      400
    );
  }

  const newPublicKey = String(body?.newPublicKey || body?.publicKey || '').trim();
  if (!newPublicKey || newPublicKey.length > 256) {
    return provenanceJson(
      { success: false, message: 'Valid base64 32-byte Ed25519 newPublicKey is required.' },
      400
    );
  }

  const result = await rotateUserProvenanceKey({
    userId: auth.user.userId,
    newPublicKey,
    oldKid: body?.oldKid ? String(body.oldKid).trim() : undefined,
    reason: body?.reason ? String(body.reason).slice(0, 120) : undefined,
  });

  return provenanceJson(
    {
      success: result.ok,
      message: result.message,
      data: result.ok
        ? {
            oldKey: result.oldKey,
            newKey: result.newKey,
            logEntry: result.logEntry,
          }
        : null,
    },
    result.status
  );
}
