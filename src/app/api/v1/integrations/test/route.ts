import { getConnectedAppById } from '../../../../../lib/integrations/store.js';
import * as WebhookRoute from '../webhook/route.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { getInternalWebhookToken } from '../../../../../lib/integrations/internalWebhookToken.js';

const appTestPayloads: Record<string, { eventType: string; message: string; priority: string; riskScore: number; otp?: string }> = {
  slack: {
    eventType: 'URGENT_MENTION',
    message: '@alex mentioned you in #incident-war-room: "Production cluster latency spike detected in EU region. Need assistance."',
    priority: 'HIGH',
    riskScore: 0.78,
  },
  github: {
    eventType: 'SECURITY_VULNERABILITY',
    message: 'Dependabot alert: Critical Remote Code Execution vulnerability detected in package-lock dependencies.',
    priority: 'CRITICAL',
    riskScore: 0.94,
  },
  stripe: {
    eventType: 'DISPUTE_FILED',
    message: 'Fraudulent transaction dispute filed for $2,450.00 USD (Charge: ch_3M5qL2). Evidence due within 48h.',
    priority: 'CRITICAL',
    riskScore: 0.96,
  },
  jira: {
    eventType: 'BLOCKER_INCIDENT',
    message: 'Ticket SEC-1049 (Auth gateway timeout) escalated to P0 Blocker by Site Reliability Engineering.',
    priority: 'HIGH',
    riskScore: 0.75,
  },
  google_workspace: {
    eventType: 'ADMIN_PRIVILEGE_CHANGE',
    message: 'Security Audit: New Super Admin role assigned to user account devops-deployer@enterprise.internal',
    priority: 'HIGH',
    riskScore: 0.88,
    otp: '482-195',
  },
  custom_api: {
    eventType: 'CUSTOM_HEARTBEAT',
    message: 'Internal microservice customer-billing healthcheck failed 3 consecutive times.',
    priority: 'MEDIUM',
    riskScore: 0.65,
  },
};

export async function POST(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const body = await request.json().catch(() => null);
    const appId = body?.appId;
    if (!appId || typeof appId !== 'string') {
      return Response.json({ error: 'appId is required' }, { status: 400 });
    }

    const app = getConnectedAppById(appId);
    if (!app) {
      return Response.json({ error: `App ${appId} not found` }, { status: 404 });
    }

    const testData = appTestPayloads[appId] || {
      eventType: 'APP_NOTIFICATION',
      message: `Test notification sent from connected app ${app.name}.`,
      priority: 'MEDIUM',
      riskScore: 0.6,
    };

    const webhookReq = new Request(
      `http://localhost:3000/api/v1/integrations/webhook?appId=${encodeURIComponent(appId)}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Aegis-Internal-Webhook-Token': getInternalWebhookToken(),
        },
        body: JSON.stringify({
          ...testData,
          userId: auth.user.userId,
        }),
      }
    );

    const res = await WebhookRoute.POST(webhookReq);
    const data = await res.json();

    return Response.json(
      {
        success: res.ok && Boolean(data?.success),
        appName: app.name,
        testData,
        response: data,
      },
      { status: res.ok ? 200 : res.status }
    );
  } catch {
    return Response.json(
      { error: 'Failed to dispatch test notification', message: 'Unable to test integration.' },
      { status: 500 }
    );
  }
}
