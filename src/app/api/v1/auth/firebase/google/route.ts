import { z } from 'zod';
import {
  authenticateWithFirebaseGoogle,
  mintSessionToken,
} from '../../../../../../lib/auth/node_auth.js';
import { User, inMemoryUsers, IUser } from '../../../../../../models/User.js';
import { connectToDatabase } from '../../../../../../lib/db/mongoose.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../../lib/telemetry/securityLogger.js';

const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || '').trim().toLowerCase();

const GoogleAuthSchema = z.object({
  firebaseIdToken: z.string().min(20, 'Invalid Firebase Google ID token'),
});

function extractAuditContext(request: Request) {
  const ctx = extractRequestContext(request);
  return { ip: ctx.ipAddress, userAgent: ctx.userAgent };
}

async function resolveGoogleRole(email: string): Promise<'ADMIN' | 'USER'> {
  const normalized = email.trim().toLowerCase();
  if (DEFAULT_ADMIN_EMAIL && normalized === DEFAULT_ADMIN_EMAIL) {
    return 'ADMIN';
  }
  const mongooseConn = await connectToDatabase().catch(() => null);
  if (mongooseConn) {
    const existing = await User.findOne({ email: normalized }).select('role').lean();
    if (existing && String((existing as any).role || '').toUpperCase() === 'ADMIN') {
      return 'ADMIN';
    }
  } else {
    const mem = inMemoryUsers.get(normalized);
    if (mem && String(mem.role || '').toUpperCase() === 'ADMIN') {
      return 'ADMIN';
    }
  }
  return 'USER';
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return Response.json(
        { success: false, error: 'Invalid JSON', message: 'Request body must be valid JSON.' },
        { status: 400 }
      );
    }

    const parsed = GoogleAuthSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Missing or invalid Firebase Google ID token.',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const auditContext = extractAuditContext(request);
    const authResult = await authenticateWithFirebaseGoogle({
      firebaseIdToken: parsed.data.firebaseIdToken,
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
        details: authResult.error || 'Google Sign-In verification failed.',
      });
      return Response.json(
        {
          success: false,
          error: 'Google Verification Failed',
          message: authResult.error || 'Could not verify Firebase Google Sign-In token.',
        },
        { status: 401 }
      );
    }

    const assignedRole = await resolveGoogleRole(authResult.user.email);
    if (assignedRole !== authResult.user.role) {
      authResult.user.role = assignedRole;
      authResult.token = mintSessionToken(
        {
          userId: authResult.user.id,
          firebaseUid: authResult.user.firebaseUid,
          email: authResult.user.email,
          role: assignedRole,
          authMethod: 'NODE_AUTH_FIREBASE_GOOGLE',
        },
        '7d'
      );
    }

    if (!inMemoryUsers.has(authResult.user.id)) {
      inMemoryUsers.set(authResult.user.id, {
        _id: authResult.user.id,
        email: authResult.user.email,
        passwordHash: '',
        role: assignedRole,
        preferences: {
          dndEnabled: false,
          quietHoursStart: '22:00',
          quietHoursEnd: '07:00',
          preferredChannel: 'WEBSOCKET',
        },
        createdAt: new Date(),
      } as unknown as IUser);
    }

    logSecurityEvent({
      eventType: 'LOGIN_SUCCESS',
      severity: 'info',
      result: 'success',
      userId: authResult.user.id,
      email: authResult.user.email,
      ipAddress: auditContext.ip,
      userAgent: auditContext.userAgent,
      details: 'Authenticated via Google Sign-In.',
    });

    return Response.json({
      success: true,
      message: 'Google Sign-In verified successfully.',
      token: authResult.token,
      user: authResult.user,
    });
  } catch (err: any) {
    console.error('[Firebase Google Auth Error]', err);
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Unexpected error during Google authentication.',
      },
      { status: 500 }
    );
  }
}
