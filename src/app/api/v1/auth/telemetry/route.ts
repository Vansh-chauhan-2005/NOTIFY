import { z } from 'zod';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../../lib/telemetry/securityLogger.js';

const AuthTelemetrySchema = z.object({
  eventType: z.enum([
    'SIGNUP_STARTED',
    'SIGNUP_COMPLETED',
    'LOGIN_FAILED',
    'RETURNING_DEVICE_DETECTED',
  ]),
  method: z.string().max(40).optional(),
  details: z.string().max(180).optional(),
});

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const parsed = AuthTelemetrySchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        { success: false, message: 'Invalid telemetry payload.', data: null },
        { status: 400 }
      );
    }

    const reqCtx = extractRequestContext(request);
    const cleanMethod = (parsed.data.method || 'auth').replace(/[^\w\s-]/g, '').slice(0, 32);
    const safeDetails =
      parsed.data.details ||
      `${parsed.data.eventType} triggered (${cleanMethod}).`;

    const evt = logSecurityEvent({
      eventType: parsed.data.eventType,
      severity: parsed.data.eventType === 'LOGIN_FAILED' ? 'warning' : 'info',
      result: parsed.data.eventType === 'LOGIN_FAILED' ? 'failed' : 'success',
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: safeDetails,
    });

    return Response.json({
      success: true,
      message: 'Auth telemetry recorded.',
      data: { id: evt.id, eventType: evt.eventType },
    });
  } catch (err: any) {
    return Response.json(
      { success: false, message: err?.message || 'Unable to log telemetry.', data: null },
      { status: 500 }
    );
  }
}
