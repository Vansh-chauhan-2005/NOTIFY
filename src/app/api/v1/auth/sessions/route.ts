import { z } from 'zod';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import {
  getOrCreateUserSecurityRecord,
  incrementUserSessionVersion,
  updateUserSecurityPreferences,
  deleteServerUserSecurityAccount,
} from '../../../../../lib/auth/sessionSecurity.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

const SessionActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('revoke_all'),
  }),
  z.object({
    action: z.literal('update_inactivity'),
    inactivityTimeoutDays: z.number().int().min(1).max(90),
  }),
  z.object({
    action: z.literal('sync_profile'),
    authMethods: z.array(z.string().max(32)).max(8).optional(),
    onboardingCompleted: z.boolean().optional(),
    email: z.string().email().optional(),
    emailVerified: z.boolean().optional(),
  }),
  z.object({
    action: z.literal('delete_account'),
  }),
]);

export async function GET(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  const rec = getOrCreateUserSecurityRecord(authResult.user.userId, {
    email: authResult.user.email,
    phoneNumber: authResult.user.phoneNumber,
    role: authResult.user.role,
  });

  return Response.json({
    success: true,
    message: 'Session and security settings loaded.',
    data: {
      sessionVersion: rec.sessionVersion,
      inactivityTimeoutDays: rec.inactivityTimeoutDays,
      onboardingCompleted: rec.onboardingCompleted,
      keySetupCompleted: rec.keySetupCompleted,
      hasKeyBackup: Boolean(rec.keyBackup),
      authMethods: rec.authMethods,
      recentSignIns: rec.loginAudits.slice(0, 15),
    },
  });
}

export async function POST(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  try {
    const body = await request.json().catch(() => null);
    const parsed = SessionActionSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          message: 'Invalid session management request.',
          data: null,
        },
        { status: 400 }
      );
    }

    const reqCtx = extractRequestContext(request);
    const userId = authResult.user.userId;

    if (parsed.data.action === 'revoke_all') {
      const nextVersion = incrementUserSessionVersion(userId);
      logSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        severity: 'warning',
        result: 'success',
        userId,
        email: authResult.user.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `User triggered Sign out of all devices (sessionVersion=${nextVersion}).`,
      });
      return Response.json({
        success: true,
        message: 'All sessions have been signed out. Please sign in again.',
        data: { sessionVersion: nextVersion },
      });
    }

    if (parsed.data.action === 'update_inactivity') {
      const updated = updateUserSecurityPreferences(userId, {
        inactivityTimeoutDays: parsed.data.inactivityTimeoutDays,
      });
      return Response.json({
        success: true,
        message: `Inactivity auto-signout updated to ${updated.inactivityTimeoutDays} days.`,
        data: { inactivityTimeoutDays: updated.inactivityTimeoutDays },
      });
    }

    if (parsed.data.action === 'sync_profile') {
      const updated = updateUserSecurityPreferences(userId, {
        ...(parsed.data.authMethods ? { authMethods: parsed.data.authMethods } : {}),
        ...(typeof parsed.data.onboardingCompleted === 'boolean'
          ? { onboardingCompleted: parsed.data.onboardingCompleted }
          : {}),
        ...(parsed.data.email ? { email: parsed.data.email } : {}),
        ...(typeof parsed.data.emailVerified === 'boolean'
          ? { emailVerified: parsed.data.emailVerified }
          : {}),
      });
      return Response.json({
        success: true,
        message: 'Security profile synced.',
        data: {
          authMethods: updated.authMethods,
          onboardingCompleted: updated.onboardingCompleted,
        },
      });
    }

    if (parsed.data.action === 'delete_account') {
      incrementUserSessionVersion(userId);
      deleteServerUserSecurityAccount(userId);
      return Response.json({
        success: true,
        message: 'Account records and active sessions deleted.',
        data: { deleted: true },
      });
    }

    return Response.json(
      { success: false, message: 'Unsupported action.', data: null },
      { status: 400 }
    );
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Session management update failed.',
        data: null,
      },
      { status: 500 }
    );
  }
}
