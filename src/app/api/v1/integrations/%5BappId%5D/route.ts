import { z } from 'zod';
import { updateConnectedApp, getConnectedAppById } from '../../../../../lib/integrations/store.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

const UpdateIntegrationSchema = z.object({
  enabled: z.boolean().optional(),
  status: z.enum(['CONNECTED', 'DISCONNECTED']).optional(),
  name: z.string().trim().min(1).max(80).optional(),
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
});

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
  const safeApp = isAdmin
    ? app
    : { ...app, apiKey: `****${app.apiKey.length > 4 ? app.apiKey.slice(-4) : '****'}` };

  return Response.json({ success: true, app: safeApp });
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
        { error: 'Validation Error', message: 'Invalid integration rule update fields.' },
        { status: 400 }
      );
    }

    const patch: any = {
      ...(parsed.data.enabled !== undefined ? { enabled: parsed.data.enabled } : {}),
      ...(parsed.data.status !== undefined ? { status: parsed.data.status } : {}),
      ...(parsed.data.name !== undefined ? { name: parsed.data.name } : {}),
      ...(parsed.data.description !== undefined ? { description: parsed.data.description } : {}),
      ...(parsed.data.rules ? { rules: parsed.data.rules } : {}),
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
      { error: 'Failed to update app rules', message: 'Unable to update integration settings.' },
      { status: 500 }
    );
  }
}
