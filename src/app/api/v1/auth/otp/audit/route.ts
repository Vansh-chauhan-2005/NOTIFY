import {
  getOtpAuditLogs,
  getOtpSecurityPolicy,
} from '../../../../../../lib/auth/node_auth.js';
import { requireAdminRequest } from '../../../../../../lib/telemetry/adminAuth.js';

export async function GET(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }

    const url = new URL(request.url);
    const limit = Math.min(200, Math.max(1, parseInt(url.searchParams.get('limit') || '50', 10) || 50));
    const destination = url.searchParams.get('destination') || undefined;
    const eventType = url.searchParams.get('eventType') || undefined;

    const logs = getOtpAuditLogs({ limit, destination, eventType });

    return Response.json({
      success: true,
      count: logs.length,
      policy: getOtpSecurityPolicy(),
      logs,
      message: `Retrieved ${logs.length} OTP audit log record(s).`,
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: 'Failed to read OTP audit logs.',
      },
      { status: 500 }
    );
  }
}
