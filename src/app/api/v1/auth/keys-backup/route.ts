import { z } from 'zod';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import {
  getServerKeyBackup,
  saveServerKeyBackup,
  type StoredEncryptedKeyBackup,
} from '../../../../../lib/auth/sessionSecurity.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

const KeyBackupSchema = z.object({
  v: z.literal(1),
  kdf: z.literal('PBKDF2-HMAC-SHA256'),
  iterations: z.number().int().min(100_000).max(1_000_000),
  cipher: z.literal('AES-256-GCM'),
  salt: z.string().min(16).max(128),
  iv: z.string().min(12).max(128),
  encryptedPrivateKeysBundle: z.string().min(32).max(16384),
  ed25519PublicKey: z.string().min(32).max(128),
  ed25519Kid: z.string().min(4).max(128),
  fingerprintHex: z.string().max(128).optional().default(''),
  fingerprintWords: z.array(z.string().max(32)).max(12).optional().default([]),
  ecdhPublicJwk: z.record(z.string(), z.unknown()),
  ecdsaPublicJwk: z.record(z.string(), z.unknown()),
  createdAt: z.string().max(64).optional(),
});

export async function GET(request: Request) {
  const authResult = authenticateUserRequest(request);
  if (!authResult.ok || !authResult.user) {
    return authResult.response!;
  }

  const backup = getServerKeyBackup(authResult.user.userId);
  return Response.json({
    success: true,
    message: backup ? 'Encrypted key backup loaded.' : 'No encrypted key backup found.',
    data: {
      hasKeyBackup: Boolean(backup),
      backup,
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
    const parsed = KeyBackupSchema.safeParse(body);
    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          message: 'Invalid encrypted key backup payload.',
          data: null,
        },
        { status: 400 }
      );
    }

    // Explicitly block any JWK containing private component 'd'
    if ('d' in parsed.data.ecdhPublicJwk || 'd' in parsed.data.ecdsaPublicJwk) {
      return Response.json(
        {
          success: false,
          message: 'Private JWK components must never be sent to the server unencrypted.',
          data: null,
        },
        { status: 400 }
      );
    }

    const nowIso = new Date().toISOString();
    const saved = saveServerKeyBackup(authResult.user.userId, {
      ...parsed.data,
      userId: authResult.user.userId,
      createdAt: parsed.data.createdAt || nowIso,
      updatedAt: nowIso,
    } as StoredEncryptedKeyBackup);

    const reqCtx = extractRequestContext(request);
    logSecurityEvent({
      eventType: 'PROVENANCE_KEY_REGISTERED',
      severity: 'info',
      result: 'success',
      userId: authResult.user.userId,
      email: authResult.user.email,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Encrypted PBKDF2 private-key backup stored for kid ${saved.ed25519Kid}.`,
    });

    return Response.json({
      success: true,
      message: 'Encrypted key backup saved.',
      data: {
        hasKeyBackup: true,
        ed25519Kid: saved.ed25519Kid,
        updatedAt: saved.updatedAt,
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to store encrypted key backup.',
        data: null,
      },
      { status: 400 }
    );
  }
}
