import { NotificationLog, inMemoryNotificationLogs } from '../../../../../models/NotificationLog.js';
import { activeSocketConnections } from '../../../../../lib/queue/worker.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { getDedupStatsSnapshot } from '../../../../../lib/dedup/store.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

export async function GET(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const mongooseConn = await connectToDatabase();
    let logs: any[] = [];

    if (mongooseConn) {
      const filter = isAdmin ? {} : { userId: auth.user.userId };
      logs = await NotificationLog.find(filter).sort({ createdAt: -1 }).limit(200).lean().exec();
    } else {
      logs = isAdmin
        ? [...inMemoryNotificationLogs]
        : inMemoryNotificationLogs.filter((l) => String(l.userId) === auth.user!.userId);
    }

    const total = logs.length;
    const statusCounts: Record<string, number> = {
      QUEUED: 0,
      PROCESSING: 0,
      DEDUPLICATED: 0,
      DISPATCHED_PRIMARY: 0,
      ESCALATED_FALLBACK: 0,
      FAILED: 0,
    };

    let totalWeight = 0;
    let nonZeroWeightCount = 0;

    for (const log of logs) {
      if (statusCounts[log.status] !== undefined) {
        statusCounts[log.status]++;
      }
      if (log.dispatchScore > 0) {
        totalWeight += log.dispatchScore;
        nonZeroWeightCount++;
      }
    }

    const averageDispatchScore =
      nonZeroWeightCount > 0 ? Number((totalWeight / nonZeroWeightCount).toFixed(3)) : 0;

    let totalActiveSockets = 0;
    if (isAdmin) {
      for (const sockets of activeSocketConnections.values()) {
        totalActiveSockets += sockets.size;
      }
    } else {
      totalActiveSockets = activeSocketConnections.get(auth.user.userId)?.size || 0;
    }

    const escalatedCount = statusCounts['ESCALATED_FALLBACK'] || 0;
    const primaryCount = statusCounts['DISPATCHED_PRIMARY'] || 0;
    const totalDelivered = escalatedCount + primaryCount;
    const fallbackRate =
      totalDelivered > 0 ? Number(((escalatedCount / totalDelivered) * 100).toFixed(1)) : 0;

    const dedupSnapshot = getDedupStatsSnapshot();
    const realDeduplicatedCount = dedupSnapshot.itemsGrouped;
    const realTotalForDedup = dedupSnapshot.itemsReceived;
    const realDedupRate = dedupSnapshot.suppressionRatePercent;

    return Response.json({
      success: true,
      timestamp: new Date().toISOString(),
      overview: {
        totalIngested: total,
        deduplicatedCount: realDeduplicatedCount,
        dedupItemsReceived: realTotalForDedup,
        deduplicationRatePercent: realDedupRate,
        averageDispatchWeight: averageDispatchScore,
        activeSocketConnections: totalActiveSockets,
        fallbackEscalationRatePercent: fallbackRate,
      },
      statusBreakdown: statusCounts,
      performance: {
        targetP99LatencyMs: 45,
        ackSlaMs: 3000,
        vectorDimension: 384,
        dedupThreshold: dedupSnapshot.activeConfig.mergeThreshold,
        escalationThreshold: 0.75,
      },
    });
  } catch {
    return Response.json(
      { error: 'Internal Server Error', message: 'Failed to load analytics metrics.' },
      { status: 500 }
    );
  }
}
