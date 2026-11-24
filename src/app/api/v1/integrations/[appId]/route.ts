import { z } from 'zod';
import {
  updateConnectedApp,
  getConnectedAppById,
  ConnectedApp,
} from '../../../../../lib/integrations/store.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

const UpdateIntegrationSchema = z
  .object({
    enabled: z.boolean().optional(),
    status: z.enum(['CONNECTED', 'DISCONNECTED']).optional(),
    description: z.string().trim().max(240).optional(),
    rules: z
      .object({
        urgencyOverride: z.enum(['AUTO', 'HIGH_ONLY', 'ALL_CRITICAL', 'NORMAL']).optional(),
        filterDuplicates: z.boolean().optional(),
        duplicateSensitivity: z.enum(['STANDARD', 'STRICT', 'RELAXED']).optional(),
        forwardToBackup: z.boolean().optional(),
        quietHoursMuted: z.boolean().optional(),
      })
      .optional(),
  })
  .strict();

function sanitizeAppForCaller(app: ConnectedApp, isAdmin: boolean) {
  if (isAdmin) return app;
  const suffix = app.apiKey.length > 4 ? app.apiKey.slice(-4) : '****';
  return {
    ...app,
    apiKey: `****${suffix}`,
  };
}

export async function GET(
  request: Request,
  { params }: { params: { appId: string } }
) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const app = getConnectedAppById(params.appId);
  if (!app) {
    return Response.json({ error: 'Connected app not found' }, { status: 404 });
  }

  const isAdmin = auth.user.role === 'ADMIN';
  return Response.json({ success: true, app: sanitizeAppForCaller(app, isAdmin) });
}

export async function PUT(
  request: Request,
  { params }: { params: { appId: string } }
) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }

    const rawBody = await request.json().catch(() => null);
    const parsed = UpdateIntegrationSchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        { error: parsed.error.issues[0]?.message || 'Invalid integration update payload' },
        { status: 400 }
      );
    }

    const body = parsed.data;
    const existing = getConnectedAppById(params.appId);
    if (!existing) {
      return Response.json({ error: 'Connected app not found' }, { status: 404 });
    }

    const patch: Partial<ConnectedApp> = {
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.status !== undefined ? { status: body.status } : {}),
      ...(body.description !== undefined ? { description: body.description } : {}),
      ...(body.rules
        ? {
            rules: {
              ...existing.rules,
              ...body.rules,
            },
          }
        : {}),
    };

    const updated = updateConnectedApp(params.appId, patch);
    if (!updated) {
      return Response.json({ error: 'Connected app not found' }, { status: 404 });
    }

    return Response.json({
      success: true,
      message: `Notification rules for ${updated.name} updated successfully`,
      app: updated,
    });
  } catch {
    return Response.json(
      { error: 'Failed to update app rules', message: 'Unable to update integration.' },
      { status: 500 }
    );
  }
}
