import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { registerUserProvenanceKey } from '../../../../../lib/provenance/store.js';
import { checkProvenanceRouteRateLimit, provenanceJson } from '../../../../../lib/provenance/http.js';

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const rl = checkProvenanceRouteRateLimit(`prov_reg:${auth.user.userId}`, 30, 60_000);
  if (!rl.allowed) {
    return provenanceJson(
      {
        success: false,
        message: `Rate limit exceeded. Retry in ${rl.retryAfterSeconds}s.`,
      },
      429
    );
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return provenanceJson({ success: false, message: 'Invalid JSON request body.' }, 400);
  }

  // Reject any accidental private key submission
  if (body?.privateKey || body?.secretKey || body?.secretSeed) {
    return provenanceJson(
      {
        success: false,
        message: 'Rejected: private signing keys must NEVER be sent to the server.',
      },
      400
    );
  }

  const publicKey = String(body?.publicKey || '').trim();
  if (!publicKey || publicKey.length > 256) {
    return provenanceJson(
      {
        success: false,
        message: 'Valid base64 32-byte Ed25519 publicKey is required.',
      },
      400
    );
  }

  const result = await registerUserProvenanceKey({
    userId: auth.user.userId,
    publicKey,
    reason: body?.reason ? String(body.reason).slice(0, 120) : undefined,
  });

  return provenanceJson(
    {
      success: result.ok,
      message: result.message,
      data: result.ok ? { key: result.key, logEntry: result.logEntry } : null,
    },
    result.status
  );
}
