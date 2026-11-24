import { z } from 'zod';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../../lib/telemetry/securityLogger.js';

const ClientEventSchema = z.object({
  eventType: z.enum(['CONSENT_GRANTED', 'CONSENT_DENIED', 'DEVICE_SCAN_RUN']),
  result: z.enum(['success', 'blocked', 'failed']).optional().default('success'),
  details: z.string().trim().min(1).max(200),
});

export async function POST(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  const reqCtx = extractRequestContext(request);

  try {
    const body = await request.json().catch(() => null);
    const parsed = ClientEventSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        { success: false, message: 'Invalid telemetry event payload.' },
        { status: 400 }
      );
    }

    const { eventType, result, details } = parsed.data;
    const event = logSecurityEvent({
      eventType,
      severity: eventType === 'CONSENT_DENIED' ? 'warning' : 'info',
      result,
      userId: authResult.user.userId,
      email: authResult.user.email,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details,
    });

    return Response.json({
      success: true,
      message: 'Telemetry event recorded.',
      data: { id: event.id, eventType: event.eventType },
    });
  } catch (err: any) {
    return Response.json(
      { success: false, message: err?.message || 'Unable to log telemetry event.' },
      { status: 500 }
    );
  }
}
