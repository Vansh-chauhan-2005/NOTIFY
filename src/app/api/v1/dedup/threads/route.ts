import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { dedupError, dedupSuccess, enforceDedupRateLimit } from '../../../../../lib/dedup/http.js';
import {
  assertNoPlaintextOrVectors,
  listDedupThreads,
  recordDedupDecisionMetadata,
} from '../../../../../lib/dedup/store.js';
import type {
  DedupDecisionAction,
  DedupProvenanceTrust,
  DedupStage,
  DedupThreadMetadata,
  GuardName,
} from '../../../../../lib/dedup/types.js';
import {
  promoteDeliveryJobPriorityOnce,
  suppressDuplicateDeliveryForThread,
} from '../../../../../lib/delivery/deliveryStore.js';
import { extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'threads-get', 90, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const url = new URL(request.url);
  const includeDemo = url.searchParams.get('includeDemo') === 'true';
  const isAdmin = String(auth.user.role || '').toUpperCase() === 'ADMIN';

  const threads = listDedupThreads({
    userId: auth.user.userId,
    isAdmin,
    includeDemo,
    limit: 100,
  });

  return dedupSuccess('Metadata-only deduplication threads retrieved.', {
    threads,
  });
}

export async function POST(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'threads-post', 120, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return dedupError(400, 'Invalid JSON body.');
  }

  // Strictly block any message plaintext or embedding float vectors
  const firewall = assertNoPlaintextOrVectors(body);
  if (!firewall.ok) {
    return dedupError(400, firewall.reason);
  }

  const metaInput = body?.threadMetadata as Partial<DedupThreadMetadata> | undefined;
  if (!metaInput || typeof metaInput.threadId !== 'string') {
    return dedupError(400, 'threadMetadata with valid threadId is required.');
  }

  const action = (['MERGE', 'SUGGEST', 'NEW_THREAD'].includes(body?.action)
    ? body.action
    : 'NEW_THREAD') as DedupDecisionAction;
  const stageMatched = (['EXACT', 'MINHASH', 'SEMANTIC_ONNX', 'TFIDF_FALLBACK', 'NONE'].includes(
    body?.stageMatched
  )
    ? body.stageMatched
    : 'NONE') as DedupStage;

  const reqCtx = extractRequestContext(request);
  const recorded = recordDedupDecisionMetadata({
    userId: auth.user.userId,
    action,
    stageMatched,
    similarity: Number(body?.similarity || 0),
    blockedByGuard: (body?.blockedByGuard || null) as GuardName | null,
    perSourceCapHit: Boolean(body?.perSourceCapHit),
    isDemo: Boolean(body?.isDemo),
    ipAddress: reqCtx.ipAddress,
    userAgent: reqCtx.userAgent,
    threadMetadata: {
      threadId: metaInput.threadId,
      userId: auth.user.userId,
      createdAt: String(metaInput.createdAt || new Date().toISOString()),
      lastMemberAt: String(metaInput.lastMemberAt || new Date().toISOString()),
      memberCount: Number(metaInput.memberCount || 1),
      memberIds: Array.isArray(metaInput.memberIds) ? metaInput.memberIds : [],
      sourceId: String(metaInput.sourceId || 'direct'),
      senderId: String(metaInput.senderId || auth.user.userId),
      category: String(metaInput.category || 'work'),
      topPriority: (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(String(metaInput.topPriority))
        ? metaInput.topPriority
        : 'MEDIUM') as DedupThreadMetadata['topPriority'],
      lowestTrust: (['VERIFIED', 'GATEWAY_ATTESTED', 'UNVERIFIED'].includes(
        String(metaInput.lowestTrust)
      )
        ? metaInput.lowestTrust
        : 'UNVERIFIED') as DedupProvenanceTrust,
      status: (['ACTIVE', 'RESOLVED', 'MUTED'].includes(String(metaInput.status))
        ? metaInput.status
        : 'ACTIVE') as DedupThreadMetadata['status'],
      stageMatched,
      lastSimilarity: Number(metaInput.lastSimilarity || body?.similarity || 0),
      memberSimilarities:
        metaInput.memberSimilarities && typeof metaInput.memberSimilarities === 'object'
          ? metaInput.memberSimilarities
          : undefined,
      relatedThreadIds: Array.isArray(metaInput.relatedThreadIds)
        ? metaInput.relatedThreadIds
        : [],
      containsEphemeral: Boolean(metaInput.containsEphemeral),
      ephemeralMemberIds: Array.isArray(metaInput.ephemeralMemberIds)
        ? metaInput.ephemeralMemberIds
        : [],
    },
  });

  // Coordinate with Fallback Delivery Engine (suppress duplicate SMS/email or escalate)
  let deliverySuppressed = false;
  let deliveryEscalated = false;
  const primaryId = recorded.memberIds[0];
  const latestId =
    typeof body?.notificationId === 'string'
      ? body.notificationId
      : recorded.memberIds[recorded.memberIds.length - 1];

  if (action === 'MERGE' && primaryId && latestId && primaryId !== latestId) {
    const sup = await suppressDuplicateDeliveryForThread({
      userId: auth.user.userId,
      primaryNotificationId: primaryId,
      duplicateNotificationId: latestId,
      threadId: recorded.threadId,
      similarity: recorded.lastSimilarity,
    });
    deliverySuppressed = sup.suppressed;

    if (body?.priorityEscalatedInThread) {
      const esc = await promoteDeliveryJobPriorityOnce({
        notificationId: primaryId,
        userId: auth.user.userId,
        newPriority: recorded.topPriority,
      });
      deliveryEscalated = esc.promoted;
    }
  }

  return dedupSuccess('Metadata-only thread decision synchronized.', {
    thread: recorded,
    deliverySuppressed,
    deliveryEscalated,
  });
}
