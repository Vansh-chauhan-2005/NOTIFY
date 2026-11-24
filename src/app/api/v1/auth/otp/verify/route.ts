import { z } from 'zod';
import {
  authenticateWithOtp,
  authenticateWithFirebasePhone,
} from '../../../../../../lib/auth/node_auth.js';
import { inMemoryUsers, IUser } from '../../../../../../models/User.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../../lib/telemetry/securityLogger.js';

const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || 'rajputvanshc@gmail.com').toLowerCase();

const FirebaseVerifySchema = z.object({
  firebaseIdToken: z.string().min(20, 'Invalid Firebase ID token'),
});

const OtpCodeVerifySchema = z
  .object({
    destination: z.string().min(5).optional(),
    phoneNumber: z.string().min(5).optional(),
    code: z.string().length(6, 'Verification code must be exactly 6 digits'),
  })
  .refine((data) => Boolean((data.destination || data.phoneNumber || '').trim()), {
    message: 'Destination email or phone number is required.',
  });

function extractAuditContext(request: Request) {
  const ctx = extractRequestContext(request);
  return { ip: ctx.ipAddress, userAgent: ctx.userAgent };
}

function resolveOtpUserRole(destination: string): 'ADMIN' | 'USER' {
  const normalized = String(destination || '').trim().toLowerCase();
  if (normalized && normalized === DEFAULT_ADMIN_EMAIL) {
    return 'ADMIN';
  }
  const existing = inMemoryUsers.get(normalized);
  if (existing && String(existing.role || '').toUpperCase() === 'ADMIN') {
    return 'ADMIN';
  }
  return 'USER';
}

function syncInMemoryUser(user: any) {
  if (!user?.id) return;
  const existing = inMemoryUsers.get(user.id);
  if (!existing) {
    inMemoryUsers.set(user.id, {
      _id: user.id,
      email: user.email || `${user.id}@aegis.mobile`,
      phoneNumber: user.phoneNumber,
      passwordHash: '',
      role: user.role || 'USER',
      preferences: {
        dndEnabled: false,
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
        preferredChannel: 'WEBSOCKET',
      },
      createdAt: new Date(),
    } as unknown as IUser);
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return Response.json(
        {
          success: false,
          error: 'Invalid JSON',
          message: 'Request body must be valid JSON.',
        },
        { status: 400 }
      );
    }

    const auditContext = extractAuditContext(request);

    // Path A: Firebase Phone Authentication ID token verification via node_auth.js
    if (body?.firebaseIdToken) {
      const parsedFb = FirebaseVerifySchema.safeParse(body);
      if (!parsedFb.success) {
        return Response.json(
          {
            success: false,
            error: 'Validation Error',
            message: 'Missing or invalid Firebase Phone ID token.',
            details: parsedFb.error.format(),
          },
          { status: 400 }
        );
      }

      const authResult = await authenticateWithFirebasePhone({
        firebaseIdToken: parsedFb.data.firebaseIdToken,
        role: 'USER',
        auditContext,
      });

      if (!authResult.success || !authResult.user || !authResult.token) {
        logSecurityEvent({
          eventType: 'LOGIN_FAILED',
          severity: 'warning',
          result: 'failed',
          ipAddress: auditContext.ip,
          userAgent: auditContext.userAgent,
          details: authResult.error || 'Firebase Phone OTP login verification failed.',
        });
        return Response.json(
          {
            success: false,
            error: 'Firebase Verification Failed',
            message: authResult.error || 'Could not verify Firebase Phone ID token.',
          },
          { status: 401 }
        );
      }

      syncInMemoryUser(authResult.user);

      logSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        severity: 'info',
        result: 'success',
        userId: authResult.user.id,
        destination: authResult.user.phoneNumber,
        ipAddress: auditContext.ip,
        userAgent: auditContext.userAgent,
        details: 'Authenticated via Firebase Phone OTP.',
      });

      return Response.json({
        success: true,
        message: 'Firebase Phone verification successful',
        token: authResult.token,
        user: authResult.user,
      });
    }

    // Path B: Email / destination 6-digit OTP verification via node_auth.js
    const parsed = OtpCodeVerifySchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Please provide your email/phone and the 6-digit OTP code.',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const destination = (parsed.data.destination || parsed.data.phoneNumber || '').trim();
    const resolvedRole = resolveOtpUserRole(destination);
    const authResult = authenticateWithOtp({
      destination,
      code: parsed.data.code,
      role: resolvedRole,
      auditContext,
    });

    if (!authResult.success || !authResult.user || !authResult.token) {
      logSecurityEvent({
        eventType: 'LOGIN_FAILED',
        severity: 'warning',
        result: authResult.locked ? 'blocked' : 'failed',
        destination,
        ipAddress: auditContext.ip,
        userAgent: auditContext.userAgent,
        details: authResult.error || 'OTP login failed.',
      });
      const status = authResult.locked ? 429 : 400;
      return Response.json(
        {
          success: false,
          error: authResult.locked ? 'Destination Locked' : 'Verification Failed',
          message: authResult.error || 'Invalid verification code.',
          locked: authResult.locked,
          lockoutSeconds: authResult.lockoutSeconds,
          attemptsRemaining: authResult.attemptsRemaining,
        },
        { status }
      );
    }

    syncInMemoryUser(authResult.user);

    logSecurityEvent({
      eventType: 'LOGIN_SUCCESS',
      severity: 'info',
      result: 'success',
      userId: authResult.user.id,
      email: authResult.user.email,
      destination: authResult.user.phoneNumber || destination,
      ipAddress: auditContext.ip,
      userAgent: auditContext.userAgent,
      details: 'Authenticated via 6-digit OTP verification.',
    });

    return Response.json({
      success: true,
      message: 'Verification successful',
      token: authResult.token,
      user: authResult.user,
    });
  } catch (err: any) {
    console.error('[Verify OTP API Error]', err);
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Unexpected server error verifying OTP.',
      },
      { status: 500 }
    );
  }
}
