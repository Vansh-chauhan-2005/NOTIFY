import { NotificationLog, inMemoryNotificationLogs } from '../../../../../models/NotificationLog.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

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
        {
          success: false,
          error: 'Forbidden',
          message: 'You can only view notification history belonging to your own account.',
        },
        { status: 403 }
      );
    }

    const userId = isAdmin ? requestedUserId : auth.user.userId;
    const status = url.searchParams.get('status');
    const parsedLimit = parseInt(url.searchParams.get('limit') || '50', 10);
    const limit = Math.min(100, Math.max(1, Number.isFinite(parsedLimit) ? parsedLimit : 50));

    const mongooseConn = await connectToDatabase();

    if (mongooseConn) {
      const query: any = {};
      if (userId) query.userId = userId;
      if (status) query.status = status;

      const logs = await NotificationLog.find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean()
        .exec();

      return Response.json({ success: true, count: logs.length, logs });
    } else {
      let filtered = [...inMemoryNotificationLogs];
      if (userId) {
        filtered = filtered.filter((l) => String(l.userId) === userId);
      }
      if (status) {
        filtered = filtered.filter((l) => l.status === status);
      }
      filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

      return Response.json({
        success: true,
        count: filtered.slice(0, limit).length,
        logs: filtered.slice(0, limit),
      });
    }
  } catch {
    return Response.json(
      { success: false, error: 'Internal Server Error', message: 'Failed to load notification history.' },
      { status: 500 }
    );
  }
}
