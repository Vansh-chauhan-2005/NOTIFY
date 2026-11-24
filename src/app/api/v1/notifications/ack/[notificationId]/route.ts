import { redis } from '../../../../../../lib/db/redis.js';
import { NotificationLog, inMemoryNotificationLogs } from '../../../../../../models/NotificationLog.js';
import { connectToDatabase } from '../../../../../../lib/db/mongoose.js';
import { listDeliveryJobs } from '../../../../../../lib/delivery/deliveryStore.js';
import { isTerminalState } from '../../../../../../lib/delivery/stateMachine.js';
import { acknowledgeDeliveryJob } from '../../../../../../lib/delivery/workerLoop.js';
import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';

interface RouteContext {
  params: {
    notificationId: string;
  };
}

export async function POST(request: Request, context: RouteContext) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const notificationId = context?.params?.notificationId;
    if (!notificationId) {
      return Response.json({ error: 'Missing notificationId parameter' }, { status: 400 });
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const mongooseConn = await connectToDatabase();

    let ownerUserId: string | null = null;
    if (mongooseConn) {
      const doc = await NotificationLog.findById(notificationId).select('userId').lean();
      if (doc) ownerUserId = String((doc as any).userId || '');
    } else {
      const mem = inMemoryNotificationLogs.find((l) => String(l._id) === notificationId);
      if (mem) ownerUserId = String(mem.userId || '');
    }

    if (ownerUserId && !isAdmin && ownerUserId !== auth.user.userId) {
      return Response.json(
        {
          success: false,
          error: 'Forbidden',
          message: 'You cannot acknowledge notifications belonging to another user.',
        },
        { status: 403 }
      );
    }

    const ackKey = `ack:pending:${notificationId}`;
    const wasPending = await redis.get(ackKey);

    if (!ownerUserId && !wasPending && !isAdmin) {
      return Response.json(
        { success: false, error: 'Not Found', message: 'Notification not found.' },
        { status: 404 }
      );
    }

    // Delete pending key to disarm BullMQ delayed fallback job
    await redis.del(ackKey);

    // Record acknowledgement timestamp
    await redis.set(`ack:received:${notificationId}`, new Date().toISOString(), 'EX', 86400);

    if (mongooseConn) {
      await NotificationLog.findByIdAndUpdate(notificationId, {
        status: 'DISPATCHED_PRIMARY',
      }).exec();
    } else {
      const log = inMemoryNotificationLogs.find((l) => String(l._id) === notificationId);
      if (log && log.status === 'PROCESSING') {
        log.status = 'DISPATCHED_PRIMARY';
      }
    }

    // Acknowledge matching active delivery jobs owned by this user (or any if ADMIN)
    const matchingJobs = await listDeliveryJobs({
      userId: ownerUserId || auth.user.userId,
      isAdmin,
      limit: 100,
    }).catch(() => []);
    for (const job of matchingJobs) {
      if (job.notificationId === notificationId && !isTerminalState(job.state)) {
        await acknowledgeDeliveryJob({ jobId: job.id, via: 'in-app-feed-ack' }).catch(() => {});
      }
    }

    return Response.json({
      success: true,
      notificationId,
      disarmedFallback: !!wasPending,
      acknowledgedAt: new Date().toISOString(),
      message: wasPending
        ? 'Notification acknowledged within 3,000ms SLA. Fallback escalation disarmed.'
        : 'Acknowledgement recorded (fallback window may have expired).',
    });
  } catch {
    return Response.json(
      { success: false, error: 'Internal Server Error', message: 'Failed to acknowledge notification.' },
      { status: 500 }
    );
  }
}
