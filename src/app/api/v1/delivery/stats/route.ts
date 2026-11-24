import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { getDeliveryStats } from '../../../../../lib/delivery/deliveryStore.js';

export async function GET(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  try {
    const isAdmin = auth.user.role === 'ADMIN';
    const stats = await getDeliveryStats({
      userId: auth.user.userId,
      isAdmin,
    });

    return Response.json({
      success: true,
      message: 'Delivery pipeline metrics loaded.',
      data: stats,
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to compute delivery stats.',
        data: null,
      },
      { status: 500 }
    );
  }
}
