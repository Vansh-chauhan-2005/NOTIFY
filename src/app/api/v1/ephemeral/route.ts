import { authenticateUserRequest } from '../../../../lib/auth/requestAuth.js';
import {
  checkEphemeralCreateRateLimit,
  createEphemeralMessage,
  listActiveEphemeralMessages,
} from '../../../../lib/ephemeral/ephemeralStore.js';
import { ephemeralJson } from '../../../../lib/ephemeral/http.js';
import { createDeliveryJob } from '../../../../lib/delivery/deliveryStore.js';
import { processSingleDeliveryJob } from '../../../../lib/delivery/workerLoop.js';
import { buildEphemeralGenericAlertText } from '../../../../lib/ephemeral/constants.js';

function resolveRequestBaseUrl(request: Request): string {
  try {
    const u = new URL(request.url);
    if (u.origin && u.origin !== 'null') {
      return u.origin;
    }
  } catch {
    // ignore
  }
  return process.env.APP_URL?.trim() || 'http://localhost:3000';
}

export async function GET(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  try {
    const messages = await listActiveEphemeralMessages({
      userId: auth.user.userId,
      includeDemo: false,
    });

    return ephemeralJson({
      success: true,
      message: 'Active ephemeral items loaded.',
      data: {
        items: messages,
        total: messages.length,
        serverTime: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    return ephemeralJson(
      {
        success: false,
        message: err?.message || 'Unable to list ephemeral items.',
      },
      500
    );
  }
}

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const rl = checkEphemeralCreateRateLimit(`eph_user:${auth.user.userId}`);
  if (!rl.allowed) {
    return ephemeralJson(
      {
        success: false,
        message: `Rate limit exceeded. Try creating another ephemeral item in ${rl.retryAfterSeconds}s.`,
        data: { retryAfterSeconds: rl.retryAfterSeconds },
      },
      429
    );
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

  // Server never accepts plaintext or client-computed expiresAt clocks
  if (typeof body?.plaintext === 'string' && body.plaintext.length > 0) {
    return ephemeralJson(
      {
        success: false,
        message: 'Rejected: ephemeral messages must be encrypted client-side before upload.',
      },
      400
    );
  }

  const senderId = auth.user.userId;
  const recipientId = String(body?.recipientId || auth.user.userId).trim() || auth.user.userId;
  const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;

  const created = await createEphemeralMessage({
    id: body?.id ? String(body.id) : undefined,
    senderId,
    recipientId,
    ciphertext: String(body?.ciphertext || ''),
    iv: String(body?.iv || ''),
    signature: String(body?.signature || ''),
    wrappedDek: String(body?.wrappedDek || ''),
    wrapIv: String(body?.wrapIv || ''),
    senderEcdhPubJwk: body?.senderEcdhPubJwk,
    senderEcdsaPubJwk: body?.senderEcdsaPubJwk,
    provenanceEnvelope: body?.provenanceEnvelope || null,
    requireEd25519Provenance: Boolean(body?.requireEd25519Provenance),
    priority: body?.priority,
    ttlSeconds: body?.ttlSeconds,
    readOnce: Boolean(body?.readOnce),
    isDemo: false,
    firebaseIdToken,
  });

  if (!created.ok || !created.record) {
    return ephemeralJson(
      {
        success: false,
        message: created.message,
      },
      created.status
    );
  }

  // Optional multi-channel generic notification alert (NEVER contains content/ciphertext/keys)
  let deliveryJob: { id: string; state: string; channel: string; alertText: string } | null = null;
  if (body?.deliverAlert === true) {
    try {
      const jobCreated = await createDeliveryJob({
        notificationId: created.record.id,
        userId: recipientId,
        priority: created.record.priority,
        idempotencyKey: `eph:${created.record.id}`,
        recipientEmail: body?.recipientEmail ? String(body.recipientEmail) : auth.user.email,
        recipientPhone: body?.recipientPhone ? String(body.recipientPhone) : auth.user.phoneNumber,
        userPreferences: body?.userPreferences || null,
        baseUrl: resolveRequestBaseUrl(request),
        isEphemeral: true,
        ephemeralTtlSeconds: created.record.ttlSeconds,
        ephemeralExpiresAt: created.record.expiresAt,
        firebaseIdToken,
      });

      const processed = await processSingleDeliveryJob(jobCreated.job.id).catch(() => jobCreated.job);
      const finalJob = processed || jobCreated.job;
      deliveryJob = {
        id: finalJob.id,
        state: finalJob.state,
        channel: finalJob.channel,
        alertText: buildEphemeralGenericAlertText(created.record.ttlSeconds),
      };
    } catch {
      // Non-fatal alert dispatch failure
    }
  }

  return ephemeralJson(
    {
      success: true,
      message: created.message,
      data: {
        id: created.record.id,
        senderId: created.record.senderId,
        recipientId: created.record.recipientId,
        priority: created.record.priority,
        createdAt: created.record.createdAt,
        expiresAt: created.record.expiresAt,
        ttlSeconds: created.record.ttlSeconds,
        readOnce: created.record.readOnce,
        status: created.record.status,
        deliveryJob,
      },
    },
    201
  );
}
