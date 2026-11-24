import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { getUserProvenanceKeys } from '../../../../../../lib/provenance/store.js';
import { provenanceJson } from '../../../../../../lib/provenance/http.js';

export async function GET(
  request: Request,
  context: { params?: { userId?: string } }
) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  let userId = String(context?.params?.userId || '').trim();
  if (!userId) {
    const parts = new URL(request.url).pathname.split('/').filter(Boolean);
    userId = parts[parts.length - 1] || '';
  }

  if (!userId) {
    return provenanceJson({ success: false, message: 'userId parameter is required.' }, 400);
  }

  const keys = await getUserProvenanceKeys(userId);
  const activeKey = keys.find((k) => k.status === 'ACTIVE') || null;

  return provenanceJson({
    success: true,
    message: keys.length > 0 ? 'Provenance public keys loaded.' : 'No Ed25519 signing keys registered for this user.',
    data: {
      userId,
      activeKey,
      keys,
    },
  });
}
