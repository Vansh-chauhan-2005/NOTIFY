import { getGlobalPenaltyBox } from '../../../../../lib/gateway/penaltyBox.js';
import {
  getRoutePolicies,
  POLICY_VALIDATION_BOUNDS,
  resetAllRoutePolicies,
  validateAndUpdateRoutePolicy,
} from '../../../../../lib/gateway/policies.js';
import type { RouteGroup } from '../../../../../lib/gateway/types.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { logSecurityEvent } from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  return Response.json({
    success: true,
    message: 'Gateway policies retrieved.',
    data: {
      policies: getRoutePolicies(),
      bounds: POLICY_VALIDATION_BOUNDS,
    },
  });
}

export async function PUT(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') {
    return Response.json(
      { success: false, message: 'Request body must be valid JSON.' },
      { status: 400 }
    );
  }

  const pb = getGlobalPenaltyBox();

  if (body.reset === true) {
    const policies = resetAllRoutePolicies();
    pb.appendAudit({
      adminId: auth.user.userId,
      action: 'POLICY_RESET',
      targetShortKey: 'all',
      details: 'Reset all ingress gateway route policies to safe defaults.',
    });
    logSecurityEvent({
      eventType: 'GATEWAY_POLICY_CHANGED',
      severity: 'info',
      result: 'success',
      userId: auth.user.userId,
      details: 'Admin reset all gateway policies to defaults.',
    });
    return Response.json({
      success: true,
      message: 'All gateway policies reset to defaults.',
      data: { policies },
    });
  }

  const group = String(body.group || '').trim() as RouteGroup;
  const result = validateAndUpdateRoutePolicy(group, {
    cost: body.cost,
    limit: body.limit,
    windowMs: body.windowMs,
    burst: body.burst,
    refillPerSec: body.refillPerSec,
    maxBodyBytes: body.maxBodyBytes,
    requestTimeoutMs: body.requestTimeoutMs,
    failureMode: body.failureMode,
  });

  if (!result.ok || !result.policy) {
    return Response.json(
      { success: false, message: result.message },
      { status: 400 }
    );
  }

  pb.appendAudit({
    adminId: auth.user.userId,
    action: 'POLICY_UPDATE',
    targetShortKey: group,
    details: `Updated ${group} policy (limit=${result.policy.limit}, burst=${result.policy.burst}, cost=${result.policy.cost}, maxBodyKB=${Math.round(result.policy.maxBodyBytes / 1024)})`,
  });

  logSecurityEvent({
    eventType: 'GATEWAY_POLICY_CHANGED',
    severity: 'info',
    result: 'success',
    userId: auth.user.userId,
    details: `Policy updated for ${group}: limit=${result.policy.limit}, burst=${result.policy.burst}, cost=${result.policy.cost}.`,
  });

  return Response.json({
    success: true,
    message: result.message,
    data: {
      policy: result.policy,
      policies: getRoutePolicies(),
    },
  });
}
