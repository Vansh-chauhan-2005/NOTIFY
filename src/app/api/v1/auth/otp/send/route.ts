import { z } from 'zod';
import {
  sendOtpToPhone,
  getFirebaseProjectId,
  getOtpSecurityPolicy,
} from '../../../../../../lib/auth/otpService.js';
import { isLiveSmtpConfigured, verifyLiveSmtpHealth } from '../../../../../../lib/integrations/emailService.js';
import { isFast2SmsConfigured, setFast2SmsTargetPhone } from '../../../../../../lib/integrations/fast2smsService.js';
import { extractRequestContext } from '../../../../../../lib/telemetry/securityLogger.js';

const SendOtpSchema = z
  .object({
    destination: z.string().min(5, 'Destination is too short').max(120, 'Destination is too long').optional(),
    phoneNumber: z.string().min(5, 'Destination is too short').max(120, 'Destination is too long').optional(),
  })
  .refine((data) => Boolean((data.destination || data.phoneNumber || '').trim()), {
    message: 'Please provide an email address or mobile number.',
  });

function extractAuditContext(request: Request) {
  const ctx = extractRequestContext(request);
  return { ip: ctx.ipAddress, userAgent: ctx.userAgent };
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

    const parsed = SendOtpSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Please provide a valid email address or mobile number.',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const rawTarget = (parsed.data.destination || parsed.data.phoneNumber || '').trim();

    if (!rawTarget.includes('@')) {
      setFast2SmsTargetPhone(rawTarget);
    }

    const auditContext = extractAuditContext(request);
    const result = await sendOtpToPhone(rawTarget, {
      purpose: 'LOGIN_OTP',
      auditContext,
    });

    if (!result.success) {
      const isRateLimited = Boolean(
        (result as any).cooldownSeconds ||
          (result as any).locked ||
          (result as any).lockoutSeconds ||
          (result as any).dailyLimitReached
      );
      const status = isRateLimited ? 429 : 502;
      return Response.json(
        {
          success: false,
          error: (result as any).locked
            ? 'Destination Locked'
            : (result as any).dailyLimitReached
            ? 'Daily Limit Reached'
            : 'Failed to send OTP',
          message: result.error || 'Real-time OTP delivery failed.',
          channel: (result as any).channel,
          cooldownSeconds: (result as any).cooldownSeconds,
          locked: (result as any).locked,
          lockoutSeconds: (result as any).lockoutSeconds,
          dailyLimitReached: (result as any).dailyLimitReached,
          dailyLimit: (result as any).dailyLimit,
          dailyRemaining: (result as any).dailyRemaining,
        },
        { status }
      );
    }

    return Response.json({
      success: true,
      destination: (result as any).destination,
      phoneNumber: (result as any).phoneNumber,
      channel: (result as any).channel,
      emailConfigured: isLiveSmtpConfigured(),
      fast2smsConfigured: isFast2SmsConfigured(),
      messageId: result.messageId,
      expiresInSeconds: result.expiresInSeconds || 300,
      cooldownSeconds: (result as any).cooldownSeconds || 60,
      dailyLimit: (result as any).dailyLimit,
      dailyRemaining: (result as any).dailyRemaining,
      message: (result as any).note || `Verification code sent to ${(result as any).destination}`,
    });
  } catch (err: any) {
    console.error('[Send OTP API Error]', err);
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Unexpected error sending OTP.',
      },
      { status: 500 }
    );
  }
}

export async function GET() {
  try {
    const firebaseProjectId = getFirebaseProjectId();
    const smtpHealth = await verifyLiveSmtpHealth();
    return Response.json({
      success: true,
      status: 'ready',
      smsProvider: 'Firebase Phone Auth',
      firebaseProjectId,
      firebasePhoneAuthConfigured: Boolean(firebaseProjectId),
      fast2smsConfigured: isFast2SmsConfigured(),
      emailProvider: 'Nodemailer SMTP',
      emailConfigured: isLiveSmtpConfigured(),
      emailVerified: smtpHealth.ok,
      emailError: smtpHealth.error,
      supportedChannels: ['FIREBASE_PHONE', 'EMAIL', 'WEBPUSH'],
      otpPolicy: getOtpSecurityPolicy(),
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        error: 'Internal Server Error',
        message: err?.message || 'Failed to check gateway status.',
      },
      { status: 500 }
    );
  }
}
