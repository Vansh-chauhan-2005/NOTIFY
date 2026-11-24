import jwt from 'jsonwebtoken';
import { z } from 'zod';
import {
  checkSmsOtp,
  linkVerifiedPhoneToUser,
  findUserByVerifiedPhone,
} from '../../../../../../lib/integrations/smsService.js';
import { mintSessionToken } from '../../../../../../lib/auth/node_auth.js';
import { inMemoryUsers, IUser } from '../../../../../../models/User.js';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../../../lib/telemetry/securityLogger.js';
import { getJwtSecret } from '../../../../../../lib/auth/jwtSecret.js';

const VerifySmsSchema = z.object({
  phone: z.string().trim().min(7, 'Phone number is required.').max(24),
  code: z
    .string()
    .trim()
    .regex(/^\d{6}$/, 'Verification code must be exactly 6 digits.'),
  linkOnly: z.boolean().optional(),
  email: z.string().email().optional(),
  displayName: z.string().max(120).optional(),
  firebaseUid: z.string().max(128).optional(),
});

function getAuthenticatedCaller(request: Request): {
  userId: string;
  email?: string;
  role: string;
} | null {
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, getJwtSecret()) as any;
    if (!decoded?.userId) return null;
    return {
      userId: String(decoded.userId),
      email: decoded.email ? String(decoded.email).toLowerCase() : undefined,
      role: String(decoded.role || 'USER').toUpperCase(),
    };
  } catch {
    return null;
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return Response.json(
        {
          success: false,
          message: 'Request body must be valid JSON.',
          data: null,
        },
        { status: 400 }
      );
    }

    const parsed = VerifySmsSchema.safeParse(body);
    if (!parsed.success) {
      const firstIssue = parsed.error.issues[0]?.message || 'Invalid phone or 6-digit code.';
      return Response.json(
        {
          success: false,
          message: firstIssue,
          data: null,
        },
        { status: 400 }
      );
    }

    const reqCtx = extractRequestContext(request);
    const caller = getAuthenticatedCaller(request);

    if (parsed.data.linkOnly && !caller) {
      return Response.json(
        {
          success: false,
          message: 'Please sign in first to link a verified phone number to your profile.',
          data: null,
        },
        { status: 401 }
      );
    }

    const verifyResult = await checkSmsOtp(parsed.data.phone, parsed.data.code, {
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
    });

    if (!verifyResult.approved || !verifyResult.normalizedPhone || !verifyResult.maskedPhone) {
      if (!caller) {
        logSecurityEvent({
          eventType: 'LOGIN_FAILED',
          severity: 'warning',
          result: verifyResult.locked ? 'blocked' : 'failed',
          userId: verifyResult.maskedPhone,
          ipAddress: reqCtx.ipAddress,
          userAgent: reqCtx.userAgent,
          details: verifyResult.message || 'SMS OTP login attempt failed.',
        });
      }

      return Response.json(
        {
          success: false,
          message: verifyResult.message,
          data: {
            mode: verifyResult.mode,
            demoMode: verifyResult.demoMode,
            maskedPhone: verifyResult.maskedPhone,
            locked: Boolean(verifyResult.locked),
            lockoutSeconds: verifyResult.lockoutSeconds,
            attemptsRemaining: verifyResult.attemptsRemaining,
          },
        },
        { status: verifyResult.status || 400 }
      );
    }

    // Mode A: Logged-in user linking their verified phone in Settings
    if (caller) {
      const linkRecord = await linkVerifiedPhoneToUser({
        normalizedPhone: verifyResult.normalizedPhone,
        userId: caller.userId,
        email: caller.email || parsed.data.email,
        displayName: parsed.data.displayName,
        role: caller.role,
      });

      return Response.json({
        success: true,
        message: 'Phone number verified and linked to your profile.',
        data: {
          linked: true,
          phoneVerified: true,
          maskedPhone: linkRecord.maskedPhone,
          phoneHash: linkRecord.phoneHash,
          mode: verifyResult.mode,
          demoMode: verifyResult.demoMode,
        },
      });
    }

    // Mode B: Unauthenticated login — look up user by verified phone hash
    const matchedUser = await findUserByVerifiedPhone(verifyResult.normalizedPhone);
    if (!matchedUser) {
      logSecurityEvent({
        eventType: 'LOGIN_FAILED',
        severity: 'warning',
        result: 'failed',
        userId: verifyResult.maskedPhone,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `SMS OTP verified for ${verifyResult.maskedPhone}, but no account is linked to this phone.`,
      });

      return Response.json(
        {
          success: false,
          message:
            'Your phone code was valid, but no account is linked to this phone number yet. Please sign up with Email or Google first and add your phone in Settings.',
          data: {
            phoneVerified: true,
            accountLinked: false,
            maskedPhone: verifyResult.maskedPhone,
            mode: verifyResult.mode,
            demoMode: verifyResult.demoMode,
          },
        },
        { status: 404 }
      );
    }

    // Mint the exact same JWT session mechanism used by Email OTP
    const token = mintSessionToken(
      {
        userId: matchedUser.userId,
        ...(matchedUser.email ? { email: matchedUser.email } : {}),
        phoneNumber: matchedUser.maskedPhone,
        phoneVerified: true,
        role: matchedUser.role || 'USER',
        authMethod: 'NODE_AUTH_SMS_OTP',
      },
      '7d'
    );

    const sessionUser = {
      id: matchedUser.userId,
      ...(matchedUser.email ? { email: matchedUser.email } : {}),
      ...(matchedUser.displayName ? { displayName: matchedUser.displayName } : {}),
      phoneNumber: matchedUser.maskedPhone,
      phoneVerified: true,
      role: matchedUser.role || 'USER',
      authenticatedAt: new Date().toISOString(),
      channels: ['WEBSOCKET', 'SMS'],
      authEngine: 'node_auth.js + Twilio Verify',
    };

    if (!inMemoryUsers.has(matchedUser.userId)) {
      inMemoryUsers.set(matchedUser.userId, {
        _id: matchedUser.userId,
        email: matchedUser.email || `${matchedUser.userId}@aegis.mobile`,
        phoneNumber: matchedUser.maskedPhone,
        passwordHash: '',
        role: matchedUser.role || 'USER',
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
      userId: matchedUser.userId,
      email: matchedUser.email,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Authenticated via SMS OTP (${verifyResult.mode === 'mock' ? 'Demo Mode' : 'Twilio Verify'}) for ${matchedUser.maskedPhone}.`,
    });

    return Response.json({
      success: true,
      message: 'SMS verification successful.',
      token,
      user: sessionUser,
      data: {
        token,
        user: sessionUser,
        phoneVerified: true,
        maskedPhone: matchedUser.maskedPhone,
        mode: verifyResult.mode,
        demoMode: verifyResult.demoMode,
      },
    });
  } catch (err: any) {
    console.error('[SMS Verify Route Error]', err?.message || 'Unexpected error');
    return Response.json(
      {
        success: false,
        message: 'Unexpected error while verifying SMS code.',
        data: null,
      },
      { status: 500 }
    );
  }
}
