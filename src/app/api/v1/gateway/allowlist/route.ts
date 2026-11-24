import {
  hashIp,
  parseTrustedClientIp,
  shortKeyHash,
} from '../../../../../lib/gateway/identity.js';
import { getGlobalPenaltyBox } from '../../../../../lib/gateway/penaltyBox.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { logSecurityEvent } from '../../../../../lib/telemetry/securityLogger.js';

export async function GET(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const pb = getGlobalPenaltyBox();
  return Response.json({
    success: true,
    message: 'Gateway allowlist retrieved.',
    data: {
      allowlist: pb.listAllowlist(),
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

  const allowlistMyIp = Boolean(body.allowlistMyIp);
  const rawTarget = String(body.target || '').trim();
  const durationMinutes = Number(body.durationMinutes ?? 60);
  const multiplier = Number(body.multiplier ?? 3);
  const label = String(body.label || (allowlistMyIp ? 'Admin Demo IP' : 'Trusted Client')).trim();

  if (!Number.isFinite(durationMinutes) || durationMinutes < 1 || durationMinutes > 10080) {
    return Response.json(
      { success: false, message: 'Allowlist duration must be between 1 and 10080 minutes (7 days).' },
      { status: 400 }
    );
  }

  let hashedKey = '';
  if (allowlistMyIp) {
    const trustedIp = parseTrustedClientIp({
      xForwardedFor: request.headers.get('x-forwarded-for'),
      socketRemoteAddress: request.headers.get('x-real-ip') || '127.0.0.1',
    });
    hashedKey = `ip:${hashIp(trustedIp)}`;
  } else {
    if (!rawTarget || rawTarget.length < 3 || rawTarget.length > 160) {
      return Response.json(
        { success: false, message: 'Please supply an IP, userId, or hashed key.' },
        { status: 400 }
      );
    }
    if (/^[0-9a-f.:/]+$/i.test(rawTarget) && (rawTarget.includes('.') || rawTarget.includes(':'))) {
      hashedKey = `ip:${hashIp(parseTrustedClientIp({ socketRemoteAddress: rawTarget, trustProxyHops: 0 }))}`;
    } else if (rawTarget.startsWith('ip:') || rawTarget.startsWith('user:') || rawTarget.startsWith('conn:')) {
      hashedKey = rawTarget;
    } else {
      hashedKey = `user:${rawTarget}`;
    }
  }

  const pb = getGlobalPenaltyBox();
  const entry = pb.addAllowlist({
    hashedKey,
    label,
    durationMinutes,
    multiplier,
    adminId: auth.user.userId,
  });

  logSecurityEvent({
    eventType: 'GATEWAY_POLICY_CHANGED',
    severity: 'info',
    result: 'success',
    userId: auth.user.userId,
    ipAddress: `hash:${shortKeyHash(hashedKey.replace(/^(ip|user|conn):/, ''))}`,
    details: `Admin allowlisted ${entry.shortKey} (${entry.label}) for ${durationMinutes}m.`,
  });

  return Response.json(
    {
      success: true,
      message: `Allowlisted ${entry.shortKey} (${entry.label}) for ${durationMinutes} minutes.`,
      data: { entry },
    },
    { status: 201 }
  );
}

export async function DELETE(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const url = new URL(request.url);
  let id = url.searchParams.get('id')?.trim() || '';
  if (!id) {
    const body = await request.json().catch(() => null);
    id = String(body?.id || '').trim();
  }

  if (!id) {
    return Response.json(
      { success: false, message: 'Missing allowlist entry id.' },
      { status: 400 }
    );
  }

  const pb = getGlobalPenaltyBox();
  const removed = pb.removeAllowlist(id, auth.user.userId);
  if (!removed) {
    return Response.json(
      { success: false, message: 'Allowlist entry not found.' },
      { status: 404 }
    );
  }

  return Response.json({
    success: true,
    message: 'Allowlist entry removed.',
    data: { id },
  });
}
