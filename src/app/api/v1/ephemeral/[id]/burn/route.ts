import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { burnEphemeralMessage } from '../../../../../../lib/ephemeral/ephemeralStore.js';
import { ephemeralJson } from '../../../../../../lib/ephemeral/http.js';

export async function POST(
  request: Request,
  context: { params?: { id?: string } }
) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const id = String(context?.params?.id || '').trim();
  if (!id) {
    return ephemeralJson(
      {
        success: false,
        message: 'Ephemeral item ID is required.',
      },
      400
    );
  }

  const result = await burnEphemeralMessage({
    id,
    userId: auth.user.userId,
  });

  if (!result.ok) {
    return ephemeralJson(
      {
        success: false,
        message: result.message,
      },
      result.status
    );
  }

  return ephemeralJson({
    success: true,
    message: result.message,
    data: { tombstone: result.tombstone },
  });
}
