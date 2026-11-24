import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { validateNumericOnlyScoreInput } from '../../../../../lib/priority/features.js';
import { shouldUsePersonalizedWeights } from '../../../../../lib/priority/learning.js';
import { enforcePriorityRateLimit, priorityError, prioritySuccess } from '../../../../../lib/priority/http.js';
import { recordUserPriorityFeedback } from '../../../../../lib/priority/store.js';
import type { PriorityFeedbackKind } from '../../../../../lib/priority/types.js';
import { extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

const VALID_FEEDBACK: PriorityFeedbackKind[] = [
  'MORE_IMPORTANT',
  'LESS_IMPORTANT',
  'ACKED_FAST',
  'IGNORED',
  'MARKED_SPAM',
];

export async function POST(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'feedback', 60, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return priorityError(400, 'Invalid JSON body.');
  }

  const feedbackKind = String(body?.feedbackKind || '').toUpperCase() as PriorityFeedbackKind;
  if (!VALID_FEEDBACK.includes(feedbackKind)) {
    return priorityError(
      400,
      `Invalid feedbackKind. Must be one of: ${VALID_FEEDBACK.join(', ')}.`
    );
  }

  const validated = validateNumericOnlyScoreInput(body?.features ? { features: body.features } : body);
  if (!validated.ok) {
    return priorityError(400, 'message' in validated ? validated.message : 'Invalid numeric features.');
  }

  const ctx = extractRequestContext(request);
  const result = recordUserPriorityFeedback({
    userId: auth.user.userId,
    features: validated.features,
    feedbackKind,
    ipAddress: ctx.ipAddress,
    userAgent: ctx.userAgent,
  });

  const activeMode = shouldUsePersonalizedWeights(
    result.updatedState.feedbackCount,
    result.updatedState.personalizationEnabled
  )
    ? 'PERSONALIZED'
    : 'GLOBAL_DEFAULT';

  return prioritySuccess('Feedback recorded via online logistic regression.', {
    ...result,
    activeMode,
  });
}
