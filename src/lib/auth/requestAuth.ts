import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { getJwtSecret } from './jwtSecret.js';
import { redis } from '../db/redis.js';
import { getUserSessionVersion } from './sessionSecurity.js';

export interface AuthenticatedRequestUser {
  userId: string;
  email?: string;
  phoneNumber?: string;
  role: string;
  authMethod?: string;
}

export interface AuthCheckResult {
  ok: boolean;
  user?: AuthenticatedRequestUser;
  response?: Response;
}

export function verifySessionToken(token: string): AuthenticatedRequestUser | null {
  const trimmed = String(token || '').trim();
  if (!trimmed) return null;

  try {
    const decoded = jwt.verify(trimmed, getJwtSecret()) as Record<string, any>;
    const userId = String(decoded?.userId || '').trim();
    if (!userId) return null;

    const currentVersion = getUserSessionVersion(userId);
    const tokenVersion = typeof decoded.sv === 'number' ? decoded.sv : 1;
    if (tokenVersion < currentVersion) {
      return null;
    }

    return {
      userId,
      email: decoded.email ? String(decoded.email) : undefined,
      phoneNumber: decoded.phoneNumber ? String(decoded.phoneNumber) : undefined,
      role: String(decoded.role || 'USER').toUpperCase(),
      authMethod: decoded.authMethod ? String(decoded.authMethod) : undefined,
    };
  } catch {
    return null;
  }
}

export function authenticateUserRequest(request: Request): AuthCheckResult {
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Authentication required. Please sign in first.',
          data: null,
        },
        { status: 401 }
      ),
    };
  }

  const token = authHeader.slice(7).trim();
  if (!token) {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Missing bearer authentication token.',
          data: null,
        },
        { status: 401 }
      ),
    };
  }

  const verifiedUser = verifySessionToken(token);
  if (!verifiedUser) {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Your session token is invalid or expired. Please sign in again.',
          data: null,
        },
        { status: 401 }
      ),
    };
  }

  return {
    ok: true,
    user: verifiedUser,
  };
}

export async function authenticateUserOrApiKey(request: Request): Promise<AuthCheckResult> {
  const authHeader = request.headers.get('authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authenticateUserRequest(request);
  }

  const rawApiKey = (request.headers.get('x-api-key') || '').trim();
  if (!rawApiKey) {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Authentication required. Supply a Bearer token or valid X-API-Key.',
          data: null,
        },
        { status: 401 }
      ),
    };
  }

  try {
    const keyHash = crypto.createHash('sha256').update(rawApiKey).digest('hex');
    const stored = await redis.get(`apikey:${keyHash}`);
    if (!stored) {
      return {
        ok: false,
        response: Response.json(
          {
            success: false,
            message: 'Invalid or revoked API key.',
            data: null,
          },
          { status: 401 }
        ),
      };
    }

    const parsed = JSON.parse(stored);
    const userId = String(parsed?.userId || '').trim();
    if (!userId) {
      return {
        ok: false,
        response: Response.json(
          {
            success: false,
            message: 'API key metadata is invalid.',
            data: null,
          },
          { status: 401 }
        ),
      };
    }

    return {
      ok: true,
      user: {
        userId,
        role: String(parsed.role || 'USER').toUpperCase(),
        authMethod: 'API_KEY',
      },
    };
  } catch {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Unable to verify API key credentials.',
          data: null,
        },
        { status: 401 }
      ),
    };
  }
}
