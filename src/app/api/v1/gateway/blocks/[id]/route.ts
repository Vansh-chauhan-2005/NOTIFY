import { getGlobalPenaltyBox } from '../../../../../../lib/gateway/penaltyBox.js';
import { requireAdminRequest } from '../../../../../../lib/telemetry/adminAuth.js';
import { logSecurityEvent } from '../../../../../../lib/telemetry/securityLogger.js';

export async function DELETE(
  request: Request,
  context?: { params?: Promise<{ id?: string }> | { id?: string } }
): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const resolvedParams =
    context?.params && 'then' in (context.params as any)
      ? await (context.params as Promise<{ id?: string }>)
      : ((context?.params || {}) as { id?: string });

  let id = decodeURIComponent(resolvedParams?.id || '').trim();
  if (!id) {
    const parts = new URL(request.url).pathname.split('/').filter(Boolean);
    id = decodeURIComponent(parts[parts.length - 1] || '');
  }

  if (!id) {
    return Response.json(
      { success: false, message: 'Missing block ID parameter.' },
      { status: 400 }
    );
  }

  const pb = getGlobalPenaltyBox();
  const removed = pb.removeBlock(id, auth.user.userId);
  if (!removed) {
    return Response.json(
      { success: false, message: 'Block entry not found or already expired.' },
      { status: 404 }
    );
  }

  logSecurityEvent({
    eventType: 'GATEWAY_MANUAL_BLOCK',
    severity: 'info',
    result: 'success',
    userId: auth.user.userId,
    details: `Admin ${auth.user.userId} unblocked key entry (${id.slice(0, 12)}).`,
  });

  return Response.json({
    success: true,
    message: 'Gateway block removed.',
    data: { id },
  });
}
