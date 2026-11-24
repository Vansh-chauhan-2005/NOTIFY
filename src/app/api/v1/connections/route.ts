import { z } from 'zod';
import { authenticateUserRequest } from '../../../../lib/auth/requestAuth.js';
import { APP_CATALOG_BY_ID } from '../../../../data/appCatalog.js';
import {
  listUserConnections,
  createUserConnection,
  deleteUserConnection,
  deleteAllUserConnections,
  toPublicConnectionView,
  validateExternalWebhookUrl,
  deriveTelegramSecretToken,
} from '../../../../lib/integrations/connectionsStore.js';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../lib/telemetry/securityLogger.js';

const CreateConnectionSchema = z.object({
  appId: z.string().min(1).max(64),
  label: z.string().trim().max(80).optional(),
  botToken: z.string().trim().max(180).optional(),
  externalWebhookUrl: z.string().trim().max(500).optional(),
  telegramChatId: z.string().trim().max(64).optional(),
  registerWebhook: z.boolean().optional().default(false),
});

function resolveBaseUrl(request: Request): string {
  const configured = process.env.APP_URL?.trim();
  if (configured) {
    return configured.replace(/\/+$/, '');
  }
  const forwardedProto = request.headers.get('x-forwarded-proto');
  const forwardedHost = request.headers.get('x-forwarded-host') || request.headers.get('host');
  if (forwardedHost) {
    const proto = forwardedProto || (forwardedHost.includes('localhost') ? 'http' : 'https');
    return `${proto}://${forwardedHost}`;
  }
  try {
    return new URL(request.url).origin;
  } catch {
    return 'http://localhost:3000';
  }
}

export async function GET(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  try {
    const connections = listUserConnections(authResult.user.userId);
    return Response.json({
      success: true,
      message: 'Connections loaded.',
      data: {
        connections,
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to load connections.',
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  const reqCtx = extractRequestContext(request);

  try {
    const rawBody = await request.json().catch(() => null);
    if (!rawBody || typeof rawBody !== 'object') {
      return Response.json(
        { success: false, message: 'Request body must be valid JSON.' },
        { status: 400 }
      );
    }

    const parsed = CreateConnectionSchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          message: 'Invalid connection settings provided.',
          data: { details: parsed.error.format() },
        },
        { status: 400 }
      );
    }

    const { appId, label, botToken, externalWebhookUrl, telegramChatId, registerWebhook } =
      parsed.data;

    const app = APP_CATALOG_BY_ID[appId];
    if (!app) {
      return Response.json(
        { success: false, message: 'Selected app is not in the Aegis catalog.' },
        { status: 404 }
      );
    }

    if (app.connectionType === 'telegram' && !botToken) {
      return Response.json(
        {
          success: false,
          message: 'Please paste your Telegram Bot Token from @BotFather.',
        },
        { status: 400 }
      );
    }

    if (botToken && !/^\d{5,14}:[A-Za-z0-9_-]{20,80}$/.test(botToken)) {
      return Response.json(
        {
          success: false,
          message: 'Bot Token format looks invalid. Expected format: 123456789:ABCdef...',
        },
        { status: 400 }
      );
    }

    let cleanWebhookUrl: string | undefined;
    if (externalWebhookUrl) {
      const check = validateExternalWebhookUrl(externalWebhookUrl, app.connectionType);
      if (!check.valid) {
        return Response.json(
          { success: false, message: check.error || 'Webhook URL is not allowed.' },
          { status: 400 }
        );
      }
      cleanWebhookUrl = check.normalized;
    }

    const { connection, signingSecretShownOnce } = createUserConnection({
      userId: authResult.user.userId,
      appId: app.id,
      label,
      botToken,
      externalWebhookUrl: cleanWebhookUrl,
      telegramChatId,
    });

    const baseUrl = resolveBaseUrl(request);
    const ingestUrl = `${baseUrl}/api/v1/ingest/${connection.id}`;

    // Best-effort Telegram webhook registration when requested & public HTTPS URL is available
    let webhookRegistered = false;
    let webhookNote: string | undefined;

    if (app.connectionType === 'telegram' && registerWebhook && botToken) {
      const isPublicHttps =
        ingestUrl.startsWith('https://') &&
        !ingestUrl.includes('localhost') &&
        !ingestUrl.includes('127.0.0.1');

      if (!isPublicHttps) {
        webhookNote =
          'Connection saved and token encrypted. Telegram requires a public HTTPS URL for automatic setWebhook; use the generated ingest URL once deployed over HTTPS.';
      } else {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/setWebhook`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: ingestUrl,
              secret_token: deriveTelegramSecretToken(signingSecretShownOnce),
            }),
            signal: controller.signal,
          });
          clearTimeout(timer);

          const tgJson = await tgRes.json().catch(() => null);
          if (tgRes.ok && tgJson?.ok) {
            webhookRegistered = true;
            webhookNote = 'Telegram webhook registered with secret token verification.';
          } else {
            webhookNote = `Telegram setWebhook returned: ${String(
              tgJson?.description || `HTTP ${tgRes.status}`
            ).slice(0, 120)}`;
          }
        } catch {
          webhookNote =
            'Bot token encrypted and connection created, but Telegram webhook registration timed out.';
        }
      }
    }

    if (webhookNote || webhookRegistered) {
      connection.webhookRegistered = webhookRegistered;
      connection.webhookNote = webhookNote;
    }

    logSecurityEvent({
      eventType: 'CONNECTION_CREATED',
      severity: 'info',
      result: 'success',
      userId: authResult.user.userId,
      email: authResult.user.email,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Encrypted connection created for ${app.name} (${app.connectionType}, id=${connection.id}).`,
    });

    return Response.json(
      {
        success: true,
        message: `${app.name} connection created. Copy your signing secret now — it will only be shown once.`,
        data: {
          connection: toPublicConnectionView(connection),
          signingSecretShownOnce,
          ingestUrl,
        },
      },
      { status: 201 }
    );
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to create app connection.',
      },
      { status: 500 }
    );
  }
}

export async function DELETE(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  const reqCtx = extractRequestContext(request);

  try {
    const url = new URL(request.url);
    const scope = url.searchParams.get('scope');
    const id = url.searchParams.get('id');

    if (scope === 'all') {
      const removedCount = deleteAllUserConnections(authResult.user.userId);
      logSecurityEvent({
        eventType: 'CONNECTION_REMOVED',
        severity: 'info',
        result: 'success',
        userId: authResult.user.userId,
        email: authResult.user.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Removed all (${removedCount}) direct app connections for user.`,
      });
      return Response.json({
        success: true,
        message: `Disconnected ${removedCount} connection${removedCount === 1 ? '' : 's'}.`,
        data: { removedCount },
      });
    }

    if (!id) {
      return Response.json(
        { success: false, message: 'Provide connection id or scope=all.' },
        { status: 400 }
      );
    }

    const removed = deleteUserConnection(authResult.user.userId, id);
    if (!removed) {
      return Response.json(
        { success: false, message: 'Connection not found or already deleted.' },
        { status: 404 }
      );
    }

    logSecurityEvent({
      eventType: 'CONNECTION_REMOVED',
      severity: 'info',
      result: 'success',
      userId: authResult.user.userId,
      email: authResult.user.email,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Removed direct connection ${id}.`,
    });

    return Response.json({
      success: true,
      message: 'Connection removed and encrypted secret purged.',
      data: { id },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to delete connection.',
      },
      { status: 500 }
    );
  }
}
