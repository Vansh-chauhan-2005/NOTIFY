import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { NotificationLog, inMemoryNotificationLogs } from '../../../../../models/NotificationLog.js';
import { activeSocketConnections } from '../../../../../lib/queue/worker.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

const priorityScoreMap: Record<string, number> = {
  LOW: 0.25,
  MEDIUM: 0.55,
  HIGH: 0.82,
  CRITICAL: 0.96,
};

export async function PATCH(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const body = await request.json().catch(() => null);
    const notificationId = body?.notificationId;
    const priority = body?.priority;

    if (!notificationId || !priority) {
      return Response.json(
        { error: 'notificationId and priority are required' },
        { status: 400 }
      );
    }

    const validPriorities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    if (!validPriorities.includes(priority)) {
      return Response.json(
        { error: `Invalid priority: must be one of ${validPriorities.join(', ')}` },
        { status: 400 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const newScore = priorityScoreMap[priority] || 0.5;
    let updatedLog: any = null;
    let ownerUserId: string | null = null;

    const db = await connectToDatabase().catch(() => null);
    if (db) {
      const existing = await NotificationLog.findById(notificationId).lean();
      if (!existing) {
        return Response.json({ error: 'Notification not found' }, { status: 404 });
      }
      ownerUserId = String((existing as any).userId || '');
      if (!isAdmin && ownerUserId !== auth.user.userId) {
        return Response.json(
          { error: 'Forbidden', message: 'You cannot modify another user\'s notification priority.' },
          { status: 403 }
        );
      }
      updatedLog = await NotificationLog.findByIdAndUpdate(
        notificationId,
        { priority, dispatchScore: newScore },
        { new: true }
      ).exec();
    } else {
      const memLog = inMemoryNotificationLogs.find(
        (l) => String(l._id) === String(notificationId)
      );
      if (!memLog) {
        return Response.json({ error: 'Notification not found' }, { status: 404 });
      }
      ownerUserId = String(memLog.userId || '');
      if (!isAdmin && ownerUserId !== auth.user.userId) {
        return Response.json(
          { error: 'Forbidden', message: 'You cannot modify another user\'s notification priority.' },
          { status: 403 }
        );
      }
      memLog.priority = priority as any;
      memLog.dispatchScore = newScore;
      updatedLog = memLog;
    }

    // Broadcast priority change ONLY to the owning user's active sockets
    if (ownerUserId) {
      const ownerSockets = activeSocketConnections.get(ownerUserId);
      if (ownerSockets) {
        const broadcastMsg = JSON.stringify({
          type: 'NOTIFICATION_PRIORITY_UPDATED',
          notificationId,
          priority,
          dispatchScore: newScore,
          updatedAt: new Date().toISOString(),
        });
        for (const socket of Array.from(ownerSockets)) {
          try {
            (socket as any).send(broadcastMsg);
          } catch {}
        }
      }
    }

    return Response.json({
      success: true,
      message: `Priority for ${notificationId} updated to ${priority}`,
      notificationId,
      priority,
      dispatchScore: newScore,
      updatedLog,
    });
  } catch {
    return Response.json(
      { error: 'Failed to update notification priority', message: 'Unable to update notification priority.' },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  return PATCH(request);
}
