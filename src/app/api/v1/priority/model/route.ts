import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { shouldUsePersonalizedWeights } from '../../../../../lib/priority/learning.js';
import {
  DEFAULT_PRIORITY_ARTIFACT,
  TFIDF_DEFAULT_MODEL_SUMMARY,
} from '../../../../../lib/priority/math.js';
import { enforcePriorityRateLimit, priorityError, prioritySuccess } from '../../../../../lib/priority/http.js';
import {
  getUserPriorityModelState,
  updateUserPrioritySettings,
} from '../../../../../lib/priority/store.js';

export async function GET(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'model-get', 90, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const state = getUserPriorityModelState(auth.user.userId);
  const coldStartThreshold = DEFAULT_PRIORITY_ARTIFACT.hyperparams.coldStartFeedbackThreshold;
  const activeMode = shouldUsePersonalizedWeights(state.feedbackCount, state.personalizationEnabled)
    ? 'PERSONALIZED'
    : 'GLOBAL_DEFAULT';

  return prioritySuccess('Priority model retrieved.', {
    model: state,
    activeMode,
    coldStartThreshold,
    coldStartRemaining: Math.max(0, coldStartThreshold - state.feedbackCount),
    defaultModel: {
      version: DEFAULT_PRIORITY_ARTIFACT.version,
      bias: DEFAULT_PRIORITY_ARTIFACT.bias,
      weights: DEFAULT_PRIORITY_ARTIFACT.weights,
      thresholds: DEFAULT_PRIORITY_ARTIFACT.thresholds,
      metrics: DEFAULT_PRIORITY_ARTIFACT.metrics,
      modelCard: DEFAULT_PRIORITY_ARTIFACT.modelCard,
    },
    tfidfDefaultModel: TFIDF_DEFAULT_MODEL_SUMMARY,
  });
}

export async function PUT(request: Request): Promise<Response> {
  const limited = enforcePriorityRateLimit(request, 'model-put', 60, 60_000);
  if (limited) return limited;

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return priorityError(400, 'Invalid JSON body.');
  }

  // Reject any attempt to store raw message/text fields inside user model state
  const forbidden = ['message', 'text', 'plaintext', 'body', 'decrypted'];
  for (const key of forbidden) {
    if (body && typeof body === 'object' && key in body) {
      return priorityError(400, `Forbidden field "${key}" cannot be stored in priority model.`);
    }
  }

  const updated = updateUserPrioritySettings(auth.user.userId, {
    personalizationEnabled:
      typeof body?.personalizationEnabled === 'boolean' ? body.personalizationEnabled : undefined,
    urgentKeywords: Array.isArray(body?.urgentKeywords) ? body.urgentKeywords : undefined,
    quietHours:
      body?.quietHours && typeof body.quietHours === 'object' ? body.quietHours : undefined,
    sourceReliability:
      body?.sourceReliability && typeof body.sourceReliability === 'object'
        ? body.sourceReliability
        : undefined,
    thresholds:
      body?.thresholds && typeof body.thresholds === 'object' ? body.thresholds : undefined,
  });

  const coldStartThreshold = DEFAULT_PRIORITY_ARTIFACT.hyperparams.coldStartFeedbackThreshold;
  const activeMode = shouldUsePersonalizedWeights(
    updated.feedbackCount,
    updated.personalizationEnabled
  )
    ? 'PERSONALIZED'
    : 'GLOBAL_DEFAULT';

  return prioritySuccess('Priority model preferences saved.', {
    model: updated,
    activeMode,
    coldStartThreshold,
    coldStartRemaining: Math.max(0, coldStartThreshold - updated.feedbackCount),
  });
}
