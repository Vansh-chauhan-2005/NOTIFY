import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { registerEphemeralPublicBundle } from '../../../../../lib/ephemeral/ephemeralStore.js';
import { ephemeralJson } from '../../../../../lib/ephemeral/http.js';

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return ephemeralJson(
      {
        success: false,
        message: 'Invalid JSON request body.',
      },
      400
    );
  }

  if (!body?.ecdhPublicJwk || !body?.ecdsaPublicJwk) {
    return ephemeralJson(
      {
        success: false,
        message: 'Both ecdhPublicJwk and ecdsaPublicJwk are required.',
      },
      400
    );
  }

  // Never allow private key material ('d') to be uploaded to public key directory
  if (body.ecdhPublicJwk.d || body.ecdsaPublicJwk.d) {
    return ephemeralJson(
      {
        success: false,
        message: 'Private JWK parameter "d" must never leave the client.',
      },
      400
    );
  }

  const saved = await registerEphemeralPublicBundle({
    userId: auth.user.userId,
    ecdhPublicJwk: body.ecdhPublicJwk,
    ecdsaPublicJwk: body.ecdsaPublicJwk,
  });

  return ephemeralJson({
    success: true,
    message: 'Session ephemeral public keys registered.',
    data: { bundle: saved },
  });
}
