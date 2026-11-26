import { z } from 'zod';
import { mintSessionToken } from '../../../../../../lib/auth/node_auth.js';
import { User, inMemoryUsers, IUser } from '../../../../../../models/User.js';
import { connectToDatabase } from '../../../../../../lib/db/mongoose.js';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../../../lib/telemetry/securityLogger.js';
import {
  verifyFirebaseIdTokenGeneral,
  getOrCreateUserSecurityRecord,
  recordLoginAuditAndDetectNewDevice,
  updateUserSecurityPreferences,
} from '../../../../../../lib/auth/sessionSecurity.js';

const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || '').trim().toLowerCase();

const FirebaseSessionSchema = z.object({
  firebaseIdToken: z.string().min(20, 'Invalid Firebase ID token'),
  isNewUser: z.boolean().optional(),
  method: z.string().max(40).optional(),
  deviceId: z.string().max(128).optional(),
  keepSignedIn: z.boolean().optional().default(true),
  onboardingCompleted: z.boolean().optional(),
});

async function resolveRole(email?: string): Promise<'ADMIN' | 'USER'> {
  if (!email) return 'USER';
  const normalized = email.trim().toLowerCase();
  if (DEFAULT_ADMIN_EMAIL && normalized === DEFAULT_ADMIN_EMAIL) return 'ADMIN';

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
        { success: false, message: 'Request body must be valid JSON.', data: null },
        { status: 400 }
      );
    }

    const parsed = FirebaseSessionSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        { success: false, message: 'Invalid Firebase session exchange request.', data: null },
        { status: 400 }
      );
    }

    const reqCtx = extractRequestContext(request);
    const verified = await verifyFirebaseIdTokenGeneral(parsed.data.firebaseIdToken);
    if (!verified.valid || !verified.uid) {
      logSecurityEvent({
        eventType: 'LOGIN_FAILED',
        severity: 'warning',
        result: 'failed',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Firebase session token verification failed.',
      });
      return Response.json(
        {
          success: false,
          message: verified.error || 'Could not verify your session. Please sign in again.',
          data: null,
        },
        { status: 401 }
      );
    }

    const role = await resolveRole(verified.email);
    const userId = verified.uid;
    const providerLabel =
      parsed.data.method ||
      (verified.signInProvider === 'google.com'
        ? 'Google'
        : verified.signInProvider === 'phone'
        ? 'Phone'
        : 'Email & Password');

    const mappedMethods: string[] = [];
    for (const p of verified.providers || []) {
      if (p === 'google.com') mappedMethods.push('google');
      if (p === 'password') mappedMethods.push('password');
      if (p === 'phone') mappedMethods.push('phone');
    }
    if (mappedMethods.length === 0) {
      if (verified.signInProvider === 'google.com') mappedMethods.push('google');
      else if (verified.signInProvider === 'phone') mappedMethods.push('phone');
      else mappedMethods.push('password');
    }

    const existingBefore = Boolean(inMemoryUsers.has(userId));
    const rec = getOrCreateUserSecurityRecord(userId, {
      firebaseUid: verified.uid,
      email: verified.email,
      phoneNumber: verified.phoneNumber,
      displayName: verified.name,
      role,
      emailVerified: Boolean(verified.emailVerified),
      authMethods: mappedMethods,
    });

    if (typeof parsed.data.onboardingCompleted === 'boolean' && parsed.data.onboardingCompleted) {
      updateUserSecurityPreferences(userId, { onboardingCompleted: true });
    }

    const isNewUser = Boolean(parsed.data.isNewUser) && !existingBefore && rec.loginAudits.length === 0;

    if (!inMemoryUsers.has(userId)) {
      inMemoryUsers.set(userId, {
        _id: userId,
        email: verified.email || `${userId}@firebase.local`,
        passwordHash: '',
        role,
        preferences: {
          dndEnabled: false,
          quietHoursStart: '22:00',
          quietHoursEnd: '07:00',
          preferredChannel: 'WEBSOCKET',
        },
        createdAt: new Date(),
      } as unknown as IUser);
    }

    const token = mintSessionToken(
      {
        userId,
        firebaseUid: verified.uid,
        ...(verified.email ? { email: verified.email } : {}),
        ...(verified.phoneNumber ? { phoneNumber: verified.phoneNumber } : {}),
        role,
        sv: rec.sessionVersion,
        authMethod: `FIREBASE_${(verified.signInProvider || 'SESSION').toUpperCase()}`,
      },
      parsed.data.keepSignedIn ? '14d' : '12h'
    );

    const deviceId =
      parsed.data.deviceId || request.headers.get('x-aegis-device-id') || undefined;

    const { audit, isNewDevice } = await recordLoginAuditAndDetectNewDevice({
      userId,
      email: verified.email,
      displayName: verified.name,
      deviceId,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      method: providerLabel,
      isFirstSignup: isNewUser,
      sendAlertEmail: !isNewUser,
    });

    if (isNewUser) {
      logSecurityEvent({
        eventType: 'SIGNUP_COMPLETED',
        severity: 'info',
        result: 'success',
        userId,
        email: verified.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `New account created via ${providerLabel}.`,
      });
    } else {
      logSecurityEvent({
        eventType: 'LOGIN_SUCCESS',
        severity: 'info',
        result: 'success',
        userId,
        email: verified.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Returning user signed in via ${providerLabel}.`,
      });
    }

    const safeUser = {
      id: userId,
      firebaseUid: verified.uid,
      ...(verified.email ? { email: verified.email } : {}),
      ...(verified.phoneNumber ? { phoneNumber: verified.phoneNumber } : {}),
      ...(verified.name ? { displayName: verified.name } : {}),
      ...(verified.picture ? { photoURL: verified.picture } : {}),
      emailVerified: Boolean(verified.emailVerified),
      role,
      authenticatedAt: new Date().toISOString(),
      channels: verified.phoneNumber ? ['WEBSOCKET', 'SMS'] : ['WEBSOCKET', 'EMAIL'],
      authEngine: 'Firebase + node_auth.js',
    };

    return Response.json({
      success: true,
      message: isNewUser ? 'Account created and session ready.' : 'Signed in successfully.',
      data: {
        token,
        user: safeUser,
        isNewUser,
        isNewDevice,
        hasKeyBackup: Boolean(rec.keyBackup),
        keyBackup: rec.keyBackup || null,
        onboardingCompleted: rec.onboardingCompleted,
        emailVerified: Boolean(verified.emailVerified),
        requiresEmailVerification:
          verified.signInProvider === 'password' && !verified.emailVerified,
        sessionVersion: rec.sessionVersion,
        inactivityTimeoutDays: rec.inactivityTimeoutDays,
        authMethods: rec.authMethods,
        recentSignIns: rec.loginAudits.slice(0, 15),
        loginAudit: audit,
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to establish session.',
        data: null,
      },
      { status: 500 }
    );
  }
}
