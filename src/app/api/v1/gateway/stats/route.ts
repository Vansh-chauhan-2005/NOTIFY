import { getGatewayMetrics } from '../../../../../lib/gateway/metrics.js';
import { getGlobalPenaltyBox } from '../../../../../lib/gateway/penaltyBox.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

export async function GET(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const stats = getGatewayMetrics().getSnapshot();
  const auditLog = getGlobalPenaltyBox().listAuditLog().slice(0, 30);

  return Response.json({
    success: true,
    message: 'Ingress gateway telemetry and metrics retrieved.',
    data: {
      stats,
      auditLog,
    },
  });
}
