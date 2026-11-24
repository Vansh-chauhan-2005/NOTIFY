import { z } from 'zod';
import { getConnectedApps, addConnectedApp, ConnectedApp } from '../../../../lib/integrations/store.js';
import { authenticateUserRequest } from '../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../lib/telemetry/adminAuth.js';

const CreateIntegrationSchema = z.object({
  name: z.string().trim().min(1, 'App name is required').max(80),
  category: z.enum(['Dev', 'Payments', 'Chat', 'Security', 'Custom']).optional().default('Custom'),
  description: z.string().trim().max(240).optional(),
  iconName: z.string().trim().max(40).optional(),
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

function sanitizeAppForCaller(app: ConnectedApp, isAdmin: boolean) {
  if (isAdmin) return app;
  const suffix = app.apiKey.length > 4 ? app.apiKey.slice(-4) : '****';
  return {
    ...app,
    apiKey: `****${suffix}`,
  };
}

export async function GET(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const isAdmin = auth.user.role === 'ADMIN';
  const apps = getConnectedApps().map((app) => sanitizeAppForCaller(app, isAdmin));
  return Response.json({
    success: true,
    totalApps: apps.length,
    connectedCount: apps.filter((a) => a.status === 'CONNECTED' && a.enabled).length,
    apps,
  });
}

export async function POST(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }

    const rawBody = await request.json().catch(() => null);
    const parsed = CreateIntegrationSchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        { error: parsed.error.issues[0]?.message || 'Invalid app integration payload' },
        { status: 400 }
      );
    }

    const body = parsed.data;
    const created = addConnectedApp({
      name: body.name,
      category: body.category,
      description: body.description || 'Custom application notification integration',
      iconName: body.iconName || 'Globe',
      status: 'CONNECTED',
      enabled: true,
      rules: {
        urgencyOverride: body.rules?.urgencyOverride || 'AUTO',
        filterDuplicates: body.rules?.filterDuplicates ?? true,
        duplicateSensitivity: body.rules?.duplicateSensitivity || 'STANDARD',
        forwardToBackup: body.rules?.forwardToBackup ?? true,
        quietHoursMuted: body.rules?.quietHoursMuted ?? false,
      },
    });

    return Response.json({ success: true, app: created }, { status: 201 });
  } catch {
    return Response.json(
      { error: 'Failed to register app integration', message: 'Unable to create integration.' },
      { status: 500 }
    );
  }
}
