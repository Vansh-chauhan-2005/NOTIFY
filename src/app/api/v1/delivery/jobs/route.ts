import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import {
  createDeliveryJob,
  listDeliveryJobs,
} from '../../../../../lib/delivery/deliveryStore.js';
import { processSingleDeliveryJob } from '../../../../../lib/delivery/workerLoop.js';

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
    const url = new URL(request.url);
    const state = url.searchParams.get('state') || undefined;
    const priority = url.searchParams.get('priority') || undefined;
    const limitParam = Number(url.searchParams.get('limit') || '100');
    const includeDemoParam = url.searchParams.get('includeDemo');
    const includeDemo = includeDemoParam === 'false' ? false : true;

    const isAdmin = auth.user.role === 'ADMIN';
    const jobs = await listDeliveryJobs({
      userId: auth.user.userId,
      isAdmin,
      state,
      priority,
      limit: Number.isFinite(limitParam) ? limitParam : 100,
      includeDemo: isAdmin ? includeDemo : false,
    });

    return Response.json({
      success: true,
      message: 'Delivery jobs loaded.',
      data: {
        jobs,
        total: jobs.length,
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to load delivery jobs.',
        data: null,
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return Response.json(
      {
        success: false,
        message: 'Invalid JSON request body.',
        data: null,
      },
      { status: 400 }
    );
  }

  const notificationId = String(body?.notificationId || '').trim();
  if (!notificationId) {
    return Response.json(
      {
        success: false,
        message: 'notificationId is required.',
        data: null,
      },
      { status: 400 }
    );
  }

  const isAdmin = auth.user.role === 'ADMIN';
  const requestedUserId = String(body?.userId || auth.user.userId).trim();
  if (!isAdmin && requestedUserId !== auth.user.userId) {
    return Response.json(
      {
        success: false,
        message: 'Forbidden: you can only queue delivery jobs for your own account.',
        data: null,
      },
      { status: 403 }
    );
  }

  const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;

  try {
    const created = await createDeliveryJob({
      notificationId,
      userId: requestedUserId,
      priority: body?.priority,
      idempotencyKey: body?.idempotencyKey ? String(body.idempotencyKey) : undefined,
      title: !body?.isEphemeral && body?.title ? String(body.title) : undefined,
      sourceApp: !body?.isEphemeral && body?.sourceApp ? String(body.sourceApp) : undefined,
      recipientEmail: body?.recipientEmail ? String(body.recipientEmail) : auth.user.email,
      recipientPhone: body?.recipientPhone ? String(body.recipientPhone) : auth.user.phoneNumber,
      recipientWhatsappPhone: body?.recipientWhatsappPhone
        ? String(body.recipientWhatsappPhone)
        : body?.recipientPhone
        ? String(body.recipientPhone)
        : auth.user.phoneNumber,
      userPreferences: body?.userPreferences || null,
      baseUrl: resolveRequestBaseUrl(request),
      firebaseIdToken,
    });

    let finalJob = created.job;
    if (!created.idempotentReplay && body?.deferStart !== true) {
      const processed = await processSingleDeliveryJob(created.job.id).catch(() => null);
      if (processed) {
        finalJob = processed;
      }
    }

    return Response.json(
      {
        success: true,
        message: created.idempotentReplay
          ? 'Existing delivery job returned (idempotent replay prevented duplicate send).'
          : 'Delivery job created and queued in multi-channel state machine.',
        data: {
          job: finalJob,
          created: created.created,
          idempotentReplay: created.idempotentReplay,
          skippedReasons: created.skippedReasons,
        },
      },
      { status: created.idempotentReplay ? 200 : 201 }
    );
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to create delivery job.',
        data: null,
      },
      { status: 500 }
    );
  }
}
