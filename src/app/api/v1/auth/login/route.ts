import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { User, inMemoryUsers, IUser } from '../../../../../models/User.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { mintSessionToken } from '../../../../../lib/auth/node_auth.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';
import {
  GENERIC_LOGIN_ERROR,
  enforceMinimumAuthDelay,
  getUserSessionVersion,
  recordLoginAuditAndDetectNewDevice,
} from '../../../../../lib/auth/sessionSecurity.js';

const DUMMY_PASSWORD_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

const DEFAULT_ADMIN_EMAIL = (process.env.DEFAULT_ADMIN_EMAIL || 'rajputvanshc@gmail.com').toLowerCase();
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@Aegis2026!';

const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

const failedLoginAttempts = new Map<string, { count: number; lockedUntil: number }>();

const CredentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

let defaultAdminSeeded = false;

function extractAuditContext(request: Request) {
  const ctx = extractRequestContext(request);
  return { ip: ctx.ipAddress, userAgent: ctx.userAgent };
}

function getThrottleKeys(email: string, ip: string): string[] {
  return [`email:${email}`, `ip:${ip}`];
}

function checkLoginLockout(email: string, ip: string): { locked: boolean; lockoutSeconds: number } {
  const now = Date.now();
  let maxRemainingMs = 0;

  for (const key of getThrottleKeys(email, ip)) {
    const entry = failedLoginAttempts.get(key);
    if (!entry) continue;
    if (entry.lockedUntil > now) {
      maxRemainingMs = Math.max(maxRemainingMs, entry.lockedUntil - now);
    } else if (entry.lockedUntil > 0 && now >= entry.lockedUntil) {
      failedLoginAttempts.delete(key);
    }
  }

  return {
    locked: maxRemainingMs > 0,
    lockoutSeconds: Math.ceil(maxRemainingMs / 1000),
  };
}

function recordFailedLoginAttempt(email: string, ip: string): { lockedNow: boolean; lockoutSeconds: number } {
  const now = Date.now();
  let lockedNow = false;

  for (const key of getThrottleKeys(email, ip)) {
    const existing = failedLoginAttempts.get(key);
    const nextCount = (existing && existing.lockedUntil <= now ? existing.count : 0) + 1;

    if (nextCount >= MAX_FAILED_LOGIN_ATTEMPTS) {
      failedLoginAttempts.set(key, { count: 0, lockedUntil: now + LOGIN_LOCKOUT_MS });
      lockedNow = true;
    } else {
      failedLoginAttempts.set(key, { count: nextCount, lockedUntil: 0 });
    }
  }

  return {
    lockedNow,
    lockoutSeconds: lockedNow ? Math.ceil(LOGIN_LOCKOUT_MS / 1000) : 0,
  };
}

function clearFailedLoginAttempts(email: string, ip: string) {
  for (const key of getThrottleKeys(email, ip)) {
    failedLoginAttempts.delete(key);
  }
}

async function ensureDefaultAdminUser() {
  const mongooseConn = await connectToDatabase();
  if (mongooseConn) {
    if (!defaultAdminSeeded) {
      const existing = await User.findOne({ email: DEFAULT_ADMIN_EMAIL });
      if (!existing) {
        const passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
        await User.create({
          email: DEFAULT_ADMIN_EMAIL,
          passwordHash,
          role: 'ADMIN',
          preferences: {
            dndEnabled: false,
            quietHoursStart: '22:00',
            quietHoursEnd: '07:00',
            preferredChannel: 'WEBSOCKET',
          },
          createdAt: new Date(),
        });
      }
      defaultAdminSeeded = true;
    }
    return { mongooseConn };
  }

  if (!inMemoryUsers.has(DEFAULT_ADMIN_EMAIL)) {
    const passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 10);
    inMemoryUsers.set(DEFAULT_ADMIN_EMAIL, {
      _id: 'usr_root_admin',
      email: DEFAULT_ADMIN_EMAIL,
      passwordHash,
      role: 'ADMIN',
      preferences: {
        dndEnabled: false,
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
        preferredChannel: 'WEBSOCKET',
      },
      createdAt: new Date(),
    } as unknown as IUser);
  }

  return { mongooseConn: null };
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

    const parsedCreds = CredentialsSchema.safeParse(body);
    if (!parsedCreds.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Please enter a valid email and admin key.',
          details: parsedCreds.error.format(),
        },
        { status: 400 }
      );
    }

    const { email, password } = parsedCreds.data;
    const normalizedEmail = email.trim().toLowerCase();

    const lockout = checkLoginLockout(normalizedEmail, auditContext.ip);
    if (lockout.locked) {
      logSecurityEvent({
        eventType: 'RATE_LIMIT_HIT',
        severity: 'warning',
        result: 'blocked',
        email: normalizedEmail,
        ipAddress: auditContext.ip,
        userAgent: auditContext.userAgent,
        details: `Admin login temporarily locked after ${MAX_FAILED_LOGIN_ATTEMPTS} failed attempts.`,
      });
      const mins = Math.max(1, Math.ceil(lockout.lockoutSeconds / 60));
      return Response.json(
        {
          success: false,
          error: 'Too Many Attempts',
          message: `Too many failed login attempts. Please try again in ${mins} minute${mins === 1 ? '' : 's'}.`,
          lockoutSeconds: lockout.lockoutSeconds,
        },
        { status: 429 }
      );
    }

    const startedAt = Date.now();
    const { mongooseConn } = await ensureDefaultAdminUser();
    let user: any = null;
    if (mongooseConn) {
      user = await User.findOne({ email: normalizedEmail });
    } else {
      user = inMemoryUsers.get(normalizedEmail);
    }

    if (!user) {
      await bcrypt.compare(password, DUMMY_PASSWORD_HASH);
      await enforceMinimumAuthDelay(startedAt, 200);
      const lockState = recordFailedLoginAttempt(normalizedEmail, auditContext.ip);
      logSecurityEvent({
        eventType: lockState.lockedNow ? 'RATE_LIMIT_HIT' : 'LOGIN_FAILED',
        severity: 'warning',
        result: lockState.lockedNow ? 'blocked' : 'failed',
        email: normalizedEmail,
        ipAddress: auditContext.ip,
        userAgent: auditContext.userAgent,
        details: 'Password login failed (generic response returned).',
      });
      return Response.json(
        {
          success: false,
          error: lockState.lockedNow ? 'Too Many Attempts' : 'Invalid credentials',
          message: lockState.lockedNow
            ? 'Too many failed login attempts. Please wait 15 minutes before trying again.'
            : GENERIC_LOGIN_ERROR,
          ...(lockState.lockedNow ? { lockoutSeconds: lockState.lockoutSeconds } : {}),
        },
        { status: lockState.lockedNow ? 429 : 401 }
      );
    }

    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      await enforceMinimumAuthDelay(startedAt, 200);
      const lockState = recordFailedLoginAttempt(normalizedEmail, auditContext.ip);
      logSecurityEvent({
        eventType: lockState.lockedNow ? 'RATE_LIMIT_HIT' : 'LOGIN_FAILED',
        severity: 'warning',
        result: lockState.lockedNow ? 'blocked' : 'failed',
        userId: String(user._id || ''),
        email: normalizedEmail,
        ipAddress: auditContext.ip,
        userAgent: auditContext.userAgent,
        details: 'Password login failed (generic response returned).',
      });
      return Response.json(
        {
          success: false,
          error: lockState.lockedNow ? 'Too Many Attempts' : 'Invalid credentials',
          message: lockState.lockedNow
            ? 'Too many failed login attempts. Please wait 15 minutes before trying again.'
            : GENERIC_LOGIN_ERROR,
          ...(lockState.lockedNow ? { lockoutSeconds: lockState.lockoutSeconds } : {}),
        },
        { status: lockState.lockedNow ? 429 : 401 }
      );
    }

    await enforceMinimumAuthDelay(startedAt, 200);
    clearFailedLoginAttempts(normalizedEmail, auditContext.ip);

    const userId = String(user._id);
    const sv = getUserSessionVersion(userId);
    const token = mintSessionToken(
      {
        userId,
        email: user.email,
        ...(user.phoneNumber ? { phoneNumber: user.phoneNumber } : {}),
        role: user.role || 'ADMIN',
        sv,
        authMethod: 'NODE_AUTH_PASSWORD',
      },
      '24h'
    );

    const deviceId = request.headers.get('x-aegis-device-id') || undefined;
    const { isNewDevice } = await recordLoginAuditAndDetectNewDevice({
      userId,
      email: user.email,
      deviceId,
      ipAddress: auditContext.ip,
      userAgent: auditContext.userAgent,
      method: 'Admin Password',
    });

    const safeUser = {
      id: userId,
      email: user.email,
      ...(user.phoneNumber ? { phoneNumber: user.phoneNumber } : {}),
      role: user.role || 'ADMIN',
      preferences: user.preferences,
      authenticatedAt: new Date().toISOString(),
      authEngine: 'node_auth.js',
    };

    logSecurityEvent({
      eventType: 'LOGIN_SUCCESS',
      severity: 'info',
      result: 'success',
      userId,
      email: user.email,
      ...(user.phoneNumber ? { destination: user.phoneNumber } : {}),
      ipAddress: auditContext.ip,
      userAgent: auditContext.userAgent,
      details: 'Password login completed.',
    });

    return Response.json({
      success: true,
      message: 'Signed in successfully.',
      token,
      user: safeUser,
      data: {
        token,
        user: safeUser,
        isNewDevice,
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Unexpected server error during login.',
      },
      { status: 500 }
    );
  }
}
