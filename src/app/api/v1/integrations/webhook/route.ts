import crypto from 'crypto';
import { z } from 'zod';
import { getConnectedAppById, updateConnectedApp } from '../../../../../lib/integrations/store.js';
import * as IngestRoute from '../../notifications/ingest/route.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import {
  getInternalWebhookToken,
  isValidInternalWebhookToken,
} from '../../../../../lib/integrations/internalWebhookToken.js';

const WebhookPayloadSchema = z
  .object({
    message: z.string().max(4000).optional(),
    text: z.string().max(4000).optional(),
    summary: z.string().max(4000).optional(),
    description: z.string().max(4000).optional(),
    eventType: z.string().max(120).optional(),
    event: z.string().max(120).optional(),
    userId: z.string().max(128).optional(),
    priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    riskScore: z.number().min(0).max(1).optional(),
    otp: z.string().max(32).optional(),
    code: z.string().max(32).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough();

function timingSafeMatch(candidate: string, expected: string): boolean {
  if (!candidate || !expected) return false;
  const bufA = Buffer.from(candidate, 'utf8');
  const bufB = Buffer.from(expected, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export async function POST(request: Request) {
  try {
    const url = new URL(request.url);
    const appId = url.searchParams.get('appId') || 'custom_api';
    const app = getConnectedAppById(appId);

    if (!app) {
      return Response.json({ error: `Integration '${appId}' not registered` }, { status: 404 });
    }

    const isInternalCall = isValidInternalWebhookToken(
      request.headers.get('x-aegis-internal-webhook-token')
    );
    const providedApiKey = (request.headers.get('x-api-key') || '').trim();
    const matchesAppKey = timingSafeMatch(providedApiKey, app.apiKey);

    let callerUserId: string | null = null;
    if (!isInternalCall && !matchesAppKey) {
      const auth = authenticateUserRequest(request);
      if (!auth.ok || !auth.user) {
        return Response.json(
          {
            success: false,
            error: 'Unauthorized',
            message: 'Valid integration X-API-Key or Bearer authentication is required.',
          },
          { status: 401 }
        );
      }
      if (auth.user.role !== 'ADMIN' && auth.user.role !== 'SERVICE') {
        return Response.json(
          {
            success: false,
            error: 'Forbidden',
            message: 'Insufficient permissions to trigger integration webhooks without app key.',
          },
          { status: 403 }
        );
      }
      callerUserId = auth.user.userId;
    }

    // Check if the user paused/muted this app
    if (!app.enabled) {
      return Response.json(
        {
          success: false,
          status: 'MUTED',
          appName: app.name,
          message: `Notifications from ${app.name} are currently paused by your notification control settings.`,
        },
        { status: 200 }
      );
    }

    const rawBody = await request.json().catch(() => ({}));
    const parsed = WebhookPayloadSchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        { success: false, error: 'Validation Error', message: 'Invalid webhook payload.' },
        { status: 400 }
      );
    }

    const payload = parsed.data;

    // Normalize external payload fields
    const rawText =
      payload.message ||
      payload.text ||
      payload.summary ||
      payload.description ||
      `Notification from ${app.name}`;
    const eventType = payload.eventType || payload.event || `${app.id.toUpperCase()}_ALERT`;
    const userId = payload.userId || callerUserId || 'usr_sec_admin_01';

    let priority = payload.priority || 'MEDIUM';
    let riskScore = typeof payload.riskScore === 'number' ? payload.riskScore : 0.6;

    // Apply Connected App Notification Controls
    if (app.rules.urgencyOverride === 'ALL_CRITICAL') {
      priority = 'CRITICAL';
      riskScore = Math.max(riskScore, 0.95);
    } else if (app.rules.urgencyOverride === 'HIGH_ONLY') {
      if (priority === 'LOW' || priority === 'MEDIUM') {
        return Response.json({
          success: true,
          status: 'FILTERED_BY_APP_RULE',
          appName: app.name,
          message: `Suppressed: ${app.name} is configured to only deliver High Priority alerts.`,
        });
      }
    }

    // Call Ingest Route with process-local internal webhook token
    const ingestReq = new Request('http://localhost:3000/api/v1/notifications/ingest', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Aegis-Internal-Webhook-Token': getInternalWebhookToken(),
      },
      body: JSON.stringify({
        userId,
        eventType,
        rawText: `[${app.name}] ${rawText}`,
        priority,
        riskScore,
        otp: payload.otp || payload.code,
        metadata: {
          sourceApp: app.name,
          appId: app.id,
          receivedVia: 'WEBHOOK',
          ...(payload.metadata || {}),
        },
      }),
    });

    const ingestRes = await IngestRoute.POST(ingestReq);
    const result = await ingestRes.json();

    if (!ingestRes.ok) {
      return Response.json(
        {
          success: false,
          appName: app.name,
          error: result?.error || 'Ingest Failed',
          message: result?.message || 'Webhook notification could not be ingested.',
        },
        { status: ingestRes.status }
      );
    }

    // Increment app stats
    updateConnectedApp(app.id, {
      stats: {
        totalReceived: (app.stats.totalReceived || 0) + 1,
        filteredCount:
          (app.stats.filteredCount || 0) + (result.status === 'DEDUPLICATED' ? 1 : 0),
        lastReceivedAt: new Date().toISOString(),
      },
    });

    return Response.json({
      success: true,
      appName: app.name,
      ingestResult: result,
    });
  } catch {
    return Response.json(
      { success: false, error: 'Webhook processing error', message: 'Unable to process webhook.' },
      { status: 500 }
    );
  }
}
