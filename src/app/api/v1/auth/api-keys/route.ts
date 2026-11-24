import crypto from 'crypto';
import { z } from 'zod';
import { redis } from '../../../../../lib/db/redis.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

const CreateApiKeySchema = z.object({
  userId: z.string().trim().min(1).max(128).optional(),
  role: z.enum(['USER', 'SERVICE', 'ADMIN']).optional(),
  label: z.string().trim().min(1).max(100).optional(),
});

export async function POST(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const rawBody = await request.json().catch(() => ({}));
    const parsed = CreateApiKeySchema.safeParse(rawBody);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Invalid API key creation parameters.',
        },
        { status: 400 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const userId =
      isAdmin && parsed.data.userId ? parsed.data.userId : auth.user.userId;
    const role =
      isAdmin && parsed.data.role ? parsed.data.role : 'USER';
    const label = parsed.data.label || 'Default Service Ingress Key';

    if (!isAdmin && parsed.data.userId && parsed.data.userId !== auth.user.userId) {
      return Response.json(
        {
          success: false,
          error: 'Forbidden',
          message: 'You can only create API keys for your own account.',
        },
        { status: 403 }
      );
    }

    if (!isAdmin && parsed.data.role && parsed.data.role !== 'USER') {
      return Response.json(
        {
          success: false,
          error: 'Forbidden',
          message: 'Only administrators can mint SERVICE or ADMIN API keys.',
        },
        { status: 403 }
      );
    }

    // Generate high-entropy API key
    const rawKey = `aegis_${crypto.randomBytes(24).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const storedRecord = {
      keyId: keyHash.slice(0, 12),
      rawKeyPreview: `${rawKey.substring(0, 10)}...${rawKey.substring(rawKey.length - 4)}`,
      keyHash,
      userId,
      role,
      label,
      createdAt: new Date().toISOString(),
    };

    const publicMetadata = {
      keyId: storedRecord.keyId,
      rawKeyPreview: storedRecord.rawKeyPreview,
      userId: storedRecord.userId,
      role: storedRecord.role,
      label: storedRecord.label,
      createdAt: storedRecord.createdAt,
    };

    await redis.set(`apikey:${keyHash}`, JSON.stringify(storedRecord));
    await redis.lpush(`user:keys:${userId}`, JSON.stringify(publicMetadata));

    return Response.json(
      {
        success: true,
        apiKey: rawKey,
        metadata: publicMetadata,
        warning: 'Store this key securely. It will not be shown again in full plaintext.',
      },
      { status: 201 }
    );
  } catch {
    return Response.json(
      { success: false, error: 'Internal Server Error', message: 'Failed to create API key.' },
      { status: 500 }
    );
  }
}

export async function GET(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const url = new URL(request.url);
    const requestedUserId = url.searchParams.get('userId');
    const isAdmin = auth.user.role === 'ADMIN';

    if (requestedUserId && !isAdmin && requestedUserId !== auth.user.userId) {
      return Response.json(
        {
          success: false,
          error: 'Forbidden',
          message: 'You can only list API keys belonging to your own account.',
        },
        { status: 403 }
      );
    }

    const targetUserId = isAdmin && requestedUserId ? requestedUserId : auth.user.userId;

    const keysRaw = await redis.lrange(`user:keys:${targetUserId}`, 0, 50);
    const keys = keysRaw
      .map((k) => {
        try {
          const parsed = JSON.parse(k);
          const { keyHash: _omitted, ...safe } = parsed || {};
          return safe;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    return Response.json({ success: true, keys });
  } catch {
    return Response.json(
      { success: false, error: 'Internal Server Error', message: 'Failed to list API keys.' },
      { status: 500 }
    );
  }
}
