import { authenticateUserRequest } from '../../../../../../../lib/auth/requestAuth.js';
import { getDeliveryJobById } from '../../../../../../../lib/delivery/deliveryStore.js';
import { cancelDeliveryJob } from '../../../../../../../lib/delivery/workerLoop.js';
import { IllegalTransitionError } from '../../../../../../../lib/delivery/stateMachine.js';

interface RouteContext {
  params: {
    id: string;
  };
}

export async function POST(request: Request, context: RouteContext) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const jobId = String(context?.params?.id || '').trim();
  if (!jobId) {
    return Response.json(
      { success: false, message: 'Missing delivery job ID.', data: null },
      { status: 400 }
    );
  }

  let reason: string | undefined;
  try {
    const body = await request.json().catch(() => null);
    if (body && typeof body.reason === 'string' && body.reason.trim()) {
      reason = body.reason.trim().slice(0, 160);
    }
  } catch {
    // optional body
  }

  try {
    const existing = await getDeliveryJobById(jobId);
    if (!existing) {
      return Response.json(
        { success: false, message: `Delivery job "${jobId}" not found.`, data: null },
        { status: 404 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    if (!isAdmin && existing.userId !== auth.user.userId) {
      return Response.json(
        { success: false, message: 'Forbidden: cannot cancel another user delivery job.', data: null },
        { status: 403 }
      );
    }

    const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;
    const updated = await cancelDeliveryJob({
      jobId,
      reason,
      firebaseIdToken,
    });

    return Response.json({
      success: true,
      message: `Delivery job ${jobId} cancelled cleanly.`,
      data: { job: updated },
    });
  } catch (err: any) {
    if (err instanceof IllegalTransitionError) {
      return Response.json(
        { success: false, message: err.message, data: null },
        { status: 409 }
      );
    }
    return Response.json(
      { success: false, message: err?.message || 'Unable to cancel delivery job.', data: null },
      { status: 500 }
    );
  }
}
