import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { getSecurityStats } from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request) {
  try {
    const authCheck = requireAdminRequest(request);
    if (!authCheck.ok) {
      return (
        authCheck.response ||
        Response.json({ success: false, message: 'Unauthorized', data: null }, { status: 401 })
      );
    }

    const stats = getSecurityStats();

    return Response.json({
      success: true,
      message: 'Security telemetry statistics retrieved successfully.',
      data: stats,
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to compute security telemetry statistics.',
        data: null,
      },
      { status: 500 }
    );
  }
}
