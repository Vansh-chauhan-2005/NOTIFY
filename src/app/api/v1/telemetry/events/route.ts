import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import {
  getSecurityEvents,
  SECURITY_EVENT_TYPES,
  type SecurityEventType,
} from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request) {
  try {
    const authCheck = requireAdminRequest(request);
    if (!authCheck.ok) {
      return (
        authCheck.response ||
        Response.json({ success: false, message: 'Unauthorized', data: null }, { status: 401 })
      );
    }

    const url = new URL(request.url);
    const rawLimit = url.searchParams.get('limit');
    const rawSeverity = (url.searchParams.get('severity') || '').trim().toLowerCase();
    const rawType = (url.searchParams.get('type') || '').trim().toUpperCase();

    const parsedLimit = rawLimit ? parseInt(rawLimit, 10) : 100;
    const limit = Number.isFinite(parsedLimit) ? Math.min(500, Math.max(1, parsedLimit)) : 100;

    if (rawSeverity && !['info', 'warning', 'critical'].includes(rawSeverity)) {
      return Response.json(
        {
          success: false,
          message: 'Invalid severity filter. Allowed values: info, warning, critical.',
          data: null,
        },
        { status: 400 }
      );
    }

    if (rawType && !SECURITY_EVENT_TYPES.includes(rawType as SecurityEventType)) {
      return Response.json(
        {
          success: false,
          message: `Invalid event type filter '${rawType}'.`,
          data: null,
        },
        { status: 400 }
      );
    }

    const { events, totalMatching } = getSecurityEvents({
      limit,
      severity: rawSeverity || undefined,
      type: rawType || undefined,
    });

    return Response.json({
      success: true,
      message: `Retrieved ${events.length} security telemetry event(s).`,
      data: {
        events,
        totalMatching,
        filters: {
          limit,
          severity: rawSeverity || null,
          type: rawType || null,
        },
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to retrieve security telemetry events.',
        data: null,
      },
      { status: 500 }
    );
  }
}
