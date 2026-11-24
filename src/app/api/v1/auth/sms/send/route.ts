import { z } from 'zod';
import { sendSmsOtp } from '../../../../../../lib/integrations/smsService.js';
import { extractRequestContext } from '../../../../../../lib/telemetry/securityLogger.js';

const SendSmsSchema = z.object({
  phone: z.string().trim().min(7, 'Please enter a valid mobile number.').max(24),
});

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

    const parsed = SendSmsSchema.safeParse(body);
    if (!parsed.success) {
      const firstIssue = parsed.error.issues[0]?.message || 'Invalid phone number.';
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
    const result = await sendSmsOtp(parsed.data.phone, {
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
    });

    if (!result.success) {
      return Response.json(
        {
          success: false,
          message: result.message,
          data: {
            mode: result.mode,
            demoMode: result.demoMode,
            maskedPhone: result.maskedPhone,
            cooldownSeconds: result.cooldownSeconds,
            lockoutSeconds: result.lockoutSeconds,
            dailyRemaining: result.dailyRemaining,
          },
        },
        { status: result.status || 400 }
      );
    }

    return Response.json({
      success: true,
      message: result.message,
      data: {
        mode: result.mode,
        demoMode: result.demoMode,
        maskedPhone: result.maskedPhone,
        cooldownSeconds: result.cooldownSeconds ?? 60,
        dailyRemaining: result.dailyRemaining,
      },
    });
  } catch (err: any) {
    console.error('[SMS Send Route Error]', err?.message || 'Unexpected error');
    return Response.json(
      {
        success: false,
        message: 'Unexpected error while sending SMS verification code.',
        data: null,
      },
      { status: 500 }
    );
  }
}
