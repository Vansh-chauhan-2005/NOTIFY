import jwt from 'jsonwebtoken';
import { getJwtSecret } from '../auth/jwtSecret.js';

export interface AdminTokenPayload {
  userId: string;
  email?: string;
  phoneNumber?: string;
  role: string;
  authMethod?: string;
}

export interface AdminCheckResult {
  ok: boolean;
  user?: AdminTokenPayload;
  response?: Response;
}

export function requireAdminRequest(request: Request): AdminCheckResult {
  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Authentication required. Please sign in as an administrator.',
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

  let decoded: any;
  try {
    decoded = jwt.verify(token, getJwtSecret());
  } catch {
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

  const role = String(decoded?.role || '').toUpperCase();
  if (role !== 'ADMIN') {
    return {
      ok: false,
      response: Response.json(
        {
          success: false,
          message: 'Forbidden: Administrator access is required to view security telemetry.',
          data: null,
        },
        { status: 403 }
      ),
    };
  }

  return {
    ok: true,
    user: {
      userId: String(decoded.userId || ''),
      email: decoded.email ? String(decoded.email) : undefined,
      phoneNumber: decoded.phoneNumber ? String(decoded.phoneNumber) : undefined,
      role,
      authMethod: decoded.authMethod ? String(decoded.authMethod) : undefined,
    },
  };
}
