import { z } from 'zod';
import { User, inMemoryUsers } from '../../../../../models/User.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import {
  registerDeviceSubscription,
  getVapidPublicKey,
} from '../../../../../lib/integrations/webPushService.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

const PushSubscriptionSchema = z.object({
  userId: z.string().min(1).optional(),
  subscription: z.object({
    endpoint: z.string().url(),
    expirationTime: z.number().nullable().optional(),
    keys: z.object({
      p256dh: z.string(),
      auth: z.string(),
    }),
  }),
});

export async function POST(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const body = await request.json().catch(() => null);
    const parsed = PushSubscriptionSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        { error: 'Validation Error', details: parsed.error.format() },
        { status: 400 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const userId = parsed.data.userId || auth.user.userId;
    if (!isAdmin && userId !== auth.user.userId) {
      return Response.json(
        { error: 'Forbidden', message: 'Cannot register push subscription for another user.' },
        { status: 403 }
      );
    }

    const { subscription } = parsed.data;
    registerDeviceSubscription(userId, subscription);

    const mongooseConn = await connectToDatabase();
    if (mongooseConn) {
      await User.findByIdAndUpdate(userId, {
        $set: { pushSubscription: subscription },
      }).exec();
    } else {
      const user = Array.from(inMemoryUsers.values()).find(
        (u) => String(u._id) === userId || u.email === userId
      );
      if (user) {
        user.pushSubscription = subscription;
      }
    }

    return Response.json({
      success: true,
      message: 'WebPush device subscription registered successfully',
      endpoint: subscription.endpoint,
    });
  } catch {
    return Response.json(
      { error: 'Internal Server Error', message: 'Failed to register push subscription.' },
      { status: 500 }
    );
  }
}

export async function GET(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const url = new URL(request.url);
    const requestedUserId = url.searchParams.get('userId');
    const isAdmin = auth.user.role === 'ADMIN';

    if (requestedUserId && !isAdmin && requestedUserId !== auth.user.userId) {
      return Response.json(
        { error: 'Forbidden', message: 'Cannot view push subscriptions belonging to another user.' },
        { status: 403 }
      );
    }

    const vapidPublicKey = getVapidPublicKey();

    if (!requestedUserId) {
      return Response.json({
        success: true,
        vapidPublicKey,
        status: 'WebPush ready',
      });
    }

    let sub: any = null;
    const mongooseConn = await connectToDatabase();
    if (mongooseConn) {
      const user = await User.findById(requestedUserId);
      sub = user?.pushSubscription;
    } else {
      const user = Array.from(inMemoryUsers.values()).find(
        (u) => String(u._id) === requestedUserId || u.email === requestedUserId
      );
      sub = user?.pushSubscription;
    }

    return Response.json({
      success: true,
      userId: requestedUserId,
      vapidPublicKey,
      hasActivePushSubscription: !!sub,
      subscription: sub || null,
    });
  } catch {
    return Response.json(
      { error: 'Internal Server Error', message: 'Failed to fetch push subscription.' },
      { status: 500 }
    );
  }
}
