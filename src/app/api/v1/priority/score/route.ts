import { promoteDeliveryJobPriorityOnce } from '../../../../../lib/delivery/deliveryStore.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { validateNumericOnlyScoreInput } from '../../../../../lib/priority/features.js';
import { enforcePriorityRateLimit, priorityError, prioritySuccess } from '../../../../../lib/priority/http.js';
import { scoreForUser } from '../../../../../lib/priority/store.js';
import type { HardRuleContext, SigmoidPriorityLabel } from '../../../../../lib/priority/types.js';
import { extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

export async function POST(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'score', 120, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return priorityError(400, 'Invalid JSON payload.');
  }

  const validated = validateNumericOnlyScoreInput(body);
  if (!validated.ok) {
    return priorityError(400, 'message' in validated ? validated.message : 'Invalid numeric features.');
  }

  const ctx = extractRequestContext(request);
  const validLabels: SigmoidPriorityLabel[] = ['CRITICAL', 'HIGH', 'NORMAL', 'LOW'];
  const prevLabel = validLabels.includes(body?.previousLabel)
    ? (body.previousLabel as SigmoidPriorityLabel)
    : undefined;

  const elapsedSeconds =
    typeof body?.elapsedSeconds === 'number' && Number.isFinite(body.elapsedSeconds)
      ? Math.max(0, body.elapsedSeconds)
      : undefined;

  const isAcked = typeof body?.isAcked === 'boolean' ? body.isAcked : undefined;

  const ruleContext: HardRuleContext | undefined =
    body?.ruleContext && typeof body.ruleContext === 'object'
      ? {
          isSecurityAlert: Boolean(body.ruleContext.isSecurityAlert),
          isAccountAtRisk: Boolean(body.ruleContext.isAccountAtRisk),
          isOtpOrNewDevice: Boolean(body.ruleContext.isOtpOrNewDevice),
          provenanceFailedOrRevoked: Boolean(body.ruleContext.provenanceFailedOrRevoked),
          isProvenanceVerified:
            typeof body.ruleContext.isProvenanceVerified === 'boolean'
              ? body.ruleContext.isProvenanceVerified
              : undefined,
          isPromo: Boolean(body.ruleContext.isPromo),
          source: typeof body.ruleContext.source === 'string' ? body.ruleContext.source.slice(0, 64) : undefined,
        }
      : undefined;

  const breakdown = scoreForUser({
    userId: auth.user.userId,
    features: validated.features,
    source: typeof body?.source === 'string' ? body.source.slice(0, 64) : undefined,
    previousLabel: prevLabel,
    elapsedSeconds,
    isAcked,
    ruleContext,
    recordStats: body?.previewOnly === true ? false : true,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  if (
    typeof body?.notificationId === 'string' &&
    body.notificationId.trim() &&
    !isAcked &&
    prevLabel &&
    breakdown.label !== prevLabel
  ) {
    await promoteDeliveryJobPriorityOnce({
      notificationId: body.notificationId.trim(),
      userId: auth.user.userId,
      newPriority: breakdown.label,
    }).catch(() => {});
  }

  return prioritySuccess('Notification priority scored cleanly.', breakdown);
}
