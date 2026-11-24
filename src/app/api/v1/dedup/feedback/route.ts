import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { dedupError, dedupSuccess, enforceDedupRateLimit } from '../../../../../lib/dedup/http.js';
import {
  assertNoPlaintextOrVectors,
  recordDedupFeedback,
} from '../../../../../lib/dedup/store.js';
import type { DedupFeedbackKind } from '../../../../../lib/dedup/types.js';
import { extractRequestContext, logSecurityEvent } from '../../../../../lib/telemetry/securityLogger.js';

const ALLOWED_FEEDBACK = new Set<DedupFeedbackKind>([
  'NOT_DUPLICATE',
  'UNGROUP',
  'CONFIRM_MERGE',
]);

export async function POST(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'feedback', 90, 60_000);
  if (limited) return limited;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return dedupError(400, 'Invalid JSON payload.');
  }

  const firewall = assertNoPlaintextOrVectors(body);
  if (!firewall.ok) {
    return dedupError(400, firewall.reason);
  }

  const reqCtx = extractRequestContext(request);
  const auth = authenticateUserRequest(request);
  const userId = auth.ok && auth.user ? auth.user.userId : 'browser-client';

  // Client lifecycle signals (DEDUP_MODEL_LOADED / DEDUP_FALLBACK_USED)
  if (
    body?.clientSignal === 'DEDUP_MODEL_LOADED' ||
    body?.clientSignal === 'DEDUP_FALLBACK_USED'
  ) {
    const safeDetails = String(body?.details || body.clientSignal)
      .replace(/[^\w\s.,:;()/=+-]/g, '')
      .slice(0, 180);
    logSecurityEvent({
      eventType: body.clientSignal,
      severity: body.clientSignal === 'DEDUP_FALLBACK_USED' ? 'warning' : 'info',
      result: 'success',
      userId,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: safeDetails,
    });
    return dedupSuccess('Client deduplication telemetry recorded.', {
      eventType: body.clientSignal,
    });
  }

  if (!auth.ok || !auth.user) return auth.response!;

  const feedbackKind = String(body?.feedbackKind || '').trim().toUpperCase() as DedupFeedbackKind;
  if (!ALLOWED_FEEDBACK.has(feedbackKind)) {
    return dedupError(
      400,
      'Invalid feedbackKind. Must be NOT_DUPLICATE, UNGROUP, or CONFIRM_MERGE.'
    );
  }

  const threadId =
    typeof body?.threadId === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(body.threadId)
      ? body.threadId
      : undefined;
  const notificationId =
    typeof body?.notificationId === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(body.notificationId)
      ? body.notificationId
      : undefined;

  const res = recordDedupFeedback({
    userId: auth.user.userId,
    feedbackKind,
    threadId,
    notificationId,
    ipAddress: reqCtx.ipAddress,
    userAgent: reqCtx.userAgent,
  });

  return dedupSuccess('Deduplication feedback applied to personal threshold.', res);
}
