import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { getEphemeralPublicBundle } from '../../../../../../lib/ephemeral/ephemeralStore.js';
import { ephemeralJson } from '../../../../../../lib/ephemeral/http.js';

export async function GET(
  request: Request,
  context: { params?: { userId?: string } }
) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const targetUserId = String(context?.params?.userId || '').trim();
  if (!targetUserId) {
    return ephemeralJson(
      {
        success: false,
        message: 'userId parameter is required.',
      },
      400
    );
  }

  const bundle = await getEphemeralPublicBundle(targetUserId);
  if (!bundle) {
    return ephemeralJson(
      {
        success: false,
        message: `No active ephemeral session public key found for ${targetUserId}.`,
      },
      404
    );
  }

  return ephemeralJson({
    success: true,
    message: 'Recipient ephemeral public key loaded.',
    data: { bundle },
  });
}
