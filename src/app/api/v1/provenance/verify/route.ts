import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { verifyEnvelopeOnServer } from '../../../../../lib/provenance/store.js';
import { checkProvenanceRouteRateLimit, provenanceJson } from '../../../../../lib/provenance/http.js';

export async function POST(request: Request) {
  const adminCheck = requireAdminRequest(request);
  let actorId = 'admin';
  if (!adminCheck.ok) {
    const userCheck = authenticateUserRequest(request);
    if (!userCheck.ok || !userCheck.user) {
      return userCheck.response!;
    }
    actorId = userCheck.user.userId;
  }

  const rl = checkProvenanceRouteRateLimit(`prov_verify:${actorId}`, 60, 60_000);
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

  try {
    const report = await verifyEnvelopeOnServer({
      envelope: body?.envelope || null,
      expectedRecipientId: body?.expectedRecipientId ? String(body.expectedRecipientId) : undefined,
      expectedCiphertext:
        typeof body?.expectedCiphertext === 'string' ? body.expectedCiphertext : undefined,
      expectedIv: typeof body?.expectedIv === 'string' ? body.expectedIv : undefined,
      expectedCiphertextHash:
        typeof body?.expectedCiphertextHash === 'string' ? body.expectedCiphertextHash : undefined,
      expectedMessageId: body?.expectedMessageId ? String(body.expectedMessageId) : undefined,
      priority: body?.priority ? String(body.priority) : undefined,
      enforceReplay: body?.enforceReplay !== false,
    });

    return provenanceJson(
      {
        success: true,
        message: report.reason,
        data: { report },
      },
      200
    );
  } catch (err: any) {
    return provenanceJson(
      { success: false, message: err?.message || 'Provenance verification failed.' },
      500
    );
  }
}
