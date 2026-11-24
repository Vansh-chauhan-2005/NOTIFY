import { hashIdentifier, hashIp, normalizeIp } from '../../../../../lib/gateway/identity.js';
import { getGatewayMetrics } from '../../../../../lib/gateway/metrics.js';
import { getGlobalPenaltyBox } from '../../../../../lib/gateway/penaltyBox.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { logSecurityEvent } from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const pb = getGlobalPenaltyBox();
  return Response.json({
    success: true,
    message: 'Active gateway blocks retrieved.',
    data: {
      blocks: pb.listActiveBlocks(),
      auditLog: pb.listAuditLog().slice(0, 25),
    },
  });
}

export async function POST(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') {
    return Response.json(
      { success: false, message: 'Request body must be valid JSON.' },
      { status: 400 }
    );
  }

  const rawTarget = String(body.target || body.hashedKey || '').trim();
  const scope = (['ip', 'user', 'connection', 'manual'].includes(body.scope)
    ? body.scope
    : 'manual') as 'ip' | 'user' | 'connection' | 'manual';
  const reason = String(body.reason || 'Manual administrator block').trim();
  const durationMinutes = Number(body.durationMinutes ?? 60);

  if (!rawTarget || rawTarget.length < 3 || rawTarget.length > 160) {
    return Response.json(
      { success: false, message: 'Please supply a valid IP, user ID, connection ID, or hashed key to block.' },
      { status: 400 }
    );
  }

  if (!Number.isFinite(durationMinutes) || durationMinutes < 1 || durationMinutes > 1440) {
    return Response.json(
      { success: false, message: 'Block duration must be between 1 and 1440 minutes (24h cap).' },
      { status: 400 }
    );
  }

  // Hash raw IP inputs before storing; accept already-prefixed hashed keys cleanly
  let hashedKey = rawTarget;
  if (scope === 'ip' && !rawTarget.startsWith('ip:')) {
    hashedKey = `ip:${hashIp(normalizeIp(rawTarget))}`;
  } else if (scope === 'user' && !rawTarget.startsWith('user:')) {
    hashedKey = `user:${rawTarget}`;
  } else if (scope === 'connection' && !rawTarget.startsWith('conn:')) {
    hashedKey = `conn:${rawTarget}`;
  } else if (scope === 'manual' && !rawTarget.includes(':')) {
    hashedKey = hashIdentifier(rawTarget);
  }

  const pb = getGlobalPenaltyBox();
  const block = pb.addManualBlock({
    hashedKey,
    scope,
    reason,
    durationMinutes,
    adminId: auth.user.userId,
  });

  getGatewayMetrics().enqueueTelemetry({
    eventType: 'GATEWAY_MANUAL_BLOCK',
    severity: 'warning',
    result: 'blocked',
    shortIpHash: block.shortKey,
    routeGroup: 'admin',
    detail: `Admin ${auth.user.userId} blocked key ${block.shortKey} for ${durationMinutes}m (${block.reason}).`,
  });

  logSecurityEvent({
    eventType: 'GATEWAY_MANUAL_BLOCK',
    severity: 'warning',
    result: 'blocked',
    userId: auth.user.userId,
    ipAddress: `hash:${block.shortKey}`,
    details: `Manual block added for ${block.shortKey} (${durationMinutes}m): ${block.reason}`,
  });

  return Response.json(
    {
      success: true,
      message: `Key ${block.shortKey} blocked until ${block.expiresAt}.`,
      data: { block },
    },
    { status: 201 }
  );
}
