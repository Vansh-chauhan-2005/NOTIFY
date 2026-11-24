import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { getDeliveryJobById } from '../../../../../../lib/delivery/deliveryStore.js';

interface RouteContext {
  params: {
    id: string;
  };
}

export async function GET(request: Request, context: RouteContext) {
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

  try {
    const job = await getDeliveryJobById(jobId);
    if (!job) {
      return Response.json(
        { success: false, message: `Delivery job "${jobId}" not found.`, data: null },
        { status: 404 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    if (!isAdmin && job.userId !== auth.user.userId) {
      return Response.json(
        { success: false, message: 'Forbidden: you do not have access to this delivery job.', data: null },
        { status: 403 }
      );
    }

    return Response.json({
      success: true,
      message: 'Delivery job loaded.',
      data: { job },
    });
  } catch (err: any) {
    return Response.json(
      { success: false, message: err?.message || 'Failed to inspect delivery job.', data: null },
      { status: 500 }
    );
  }
}
