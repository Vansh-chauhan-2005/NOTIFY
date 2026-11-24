import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import {
  checkAckRateLimit,
  verifyAndConsumeAckToken,
} from '../../../../../../lib/delivery/ackTokens.js';
import { getDeliveryJobById } from '../../../../../../lib/delivery/deliveryStore.js';
import { acknowledgeDeliveryJob } from '../../../../../../lib/delivery/workerLoop.js';
import { isTerminalState } from '../../../../../../lib/delivery/stateMachine.js';
import { extractRequestContext, logSecurityEvent } from '../../../../../../lib/telemetry/securityLogger.js';

interface RouteContext {
  params?: {
    jobId?: string;
  };
}

async function handleAck(request: Request, context?: RouteContext) {
  const ctx = extractRequestContext(request);

  if (!checkAckRateLimit(ctx.ipAddress)) {
    logSecurityEvent({
      eventType: 'RATE_LIMIT_HIT',
      severity: 'warning',
      result: 'blocked',
      ipAddress: ctx.ipAddress,
      userAgent: ctx.userAgent,
      details: 'ACK endpoint rate limit exceeded (30 requests/min).',
    });
    return Response.json(
      {
        success: false,
        message: 'Too many acknowledgement requests. Please wait a minute and retry.',
        data: null,
      },
      { status: 429 }
    );
  }

  const url = new URL(request.url);
  const routeJobId = String(context?.params?.jobId || '').trim();
  let body: any = null;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    body = await request.json().catch(() => null);
  }

  const tokenParam =
    url.searchParams.get('token')?.trim() ||
    (body && typeof body.token === 'string' ? body.token.trim() : '');

  // Path 1: Signed single-use HMAC ACK link (from SMS or Email generic notification)
  if (tokenParam) {
    const expectedJobId = routeJobId && routeJobId !== 'ack' ? routeJobId : undefined;
    const verification = verifyAndConsumeAckToken(tokenParam, expectedJobId);
    if (!verification.valid || !verification.payload) {
      logSecurityEvent({
        eventType: 'ACK_LINK_INVALID',
        severity: 'warning',
        result: 'blocked',
        ipAddress: ctx.ipAddress,
        userAgent: ctx.userAgent,
        details: `Rejected invalid/expired/replayed ACK link: ${verification.reason || 'invalid token'}.`,
      });
      return Response.json(
        {
          success: false,
          message: verification.reason || 'Invalid or expired acknowledgement link.',
          data: null,
        },
        { status: 400 }
      );
    }

    const targetJobId = verification.payload.j;
    const existing = await getDeliveryJobById(targetJobId);
    if (!existing) {
      return Response.json(
        {
          success: false,
          message: `Delivery job "${targetJobId}" was not found.`,
          data: null,
        },
        { status: 404 }
      );
    }

    if (isTerminalState(existing.state)) {
      return Response.json({
        success: true,
        message:
          existing.state === 'DELIVERED_ACKED'
            ? 'Delivery job was already acknowledged.'
            : `Delivery job already reached terminal state (${existing.state}).`,
        data: { job: existing, alreadyTerminal: true },
      });
    }

    const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;
    const updated = await acknowledgeDeliveryJob({
      jobId: targetJobId,
      via: 'signed-link',
      firebaseIdToken,
    });

    return Response.json({
      success: true,
      message: 'Notification acknowledged via signed link. Remaining fallback timers cancelled.',
      data: { job: updated },
    });
  }

  // Path 2: Authenticated owner or admin ACK (in-app button / operator console)
  if (request.method === 'GET') {
    return Response.json(
      {
        success: false,
        message: 'A signed acknowledgement token query parameter (?token=...) is required.',
        data: null,
      },
      { status: 400 }
    );
  }

  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const targetJobId =
    routeJobId && routeJobId !== 'ack'
      ? routeJobId
      : String(body?.jobId || '').trim();

  if (!targetJobId) {
    return Response.json(
      { success: false, message: 'Missing delivery jobId.', data: null },
      { status: 400 }
    );
  }

  const existing = await getDeliveryJobById(targetJobId);
  if (!existing) {
    return Response.json(
      { success: false, message: `Delivery job "${targetJobId}" not found.`, data: null },
      { status: 404 }
    );
  }

  const isAdmin = auth.user.role === 'ADMIN';
  if (!isAdmin && existing.userId !== auth.user.userId) {
    return Response.json(
      { success: false, message: 'Forbidden: cannot acknowledge another user delivery job.', data: null },
      { status: 403 }
    );
  }

  if (isTerminalState(existing.state)) {
    return Response.json({
      success: true,
      message:
        existing.state === 'DELIVERED_ACKED'
          ? 'Delivery job already acknowledged.'
          : `Delivery job is already terminal (${existing.state}).`,
      data: { job: existing, alreadyTerminal: true },
    });
  }

  const via =
    body && typeof body.via === 'string' && body.via.trim()
      ? body.via.trim().slice(0, 60)
      : 'in-app-ack';
  const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;
  const updated = await acknowledgeDeliveryJob({
    jobId: targetJobId,
    via,
    firebaseIdToken,
  });

  return Response.json({
    success: true,
    message: 'Notification acknowledged. Escalation timers stopped cleanly.',
    data: { job: updated },
  });
}

export async function GET(request: Request, context: RouteContext) {
  return handleAck(request, context);
}

export async function POST(request: Request, context: RouteContext) {
  return handleAck(request, context);
}
