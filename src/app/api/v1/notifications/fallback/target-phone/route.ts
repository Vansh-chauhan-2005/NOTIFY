import { z } from 'zod';
import {
  setFast2SmsTargetPhone,
  getFast2SmsTargetPhone,
  isFast2SmsConfigured,
} from '../../../../../../lib/integrations/fast2smsService.js';
import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../../lib/telemetry/adminAuth.js';

const TargetPhoneSchema = z.object({
  targetPhone: z
    .string()
    .min(10, 'Mobile number must be at least 10 digits')
    .max(20, 'Mobile number exceeds valid length'),
});

function maskPhone(phone: string): string {
  const clean = String(phone || '').trim();
  if (!clean) return '';
  if (clean.length <= 4) return '****';
  return `${'*'.repeat(Math.max(4, clean.length - 4))}${clean.slice(-4)}`;
}

export async function GET(request: Request) {
  const auth = authenticateUserRequest(request);
  if (!auth.ok || !auth.user) {
    return auth.response!;
  }

  const phone = getFast2SmsTargetPhone();
  const isAdmin = auth.user.role === 'ADMIN';
  return Response.json({
    success: true,
    targetPhone: isAdmin ? phone : maskPhone(phone),
    configured: isFast2SmsConfigured(),
    source: phone ? 'Configured from User Mobile' : 'Unset',
  });
}

export async function POST(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }

    const body = await request.json().catch(() => ({}));
    const parsed = TargetPhoneSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        {
          error: 'Validation Error',
          message: 'Please provide a valid user mobile number (at least 10 digits).',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const cleaned = setFast2SmsTargetPhone(parsed.data.targetPhone);

    return Response.json({
      success: true,
      message: `FAST2SMS_TARGET_PHONE successfully set to ${cleaned}`,
      targetPhone: cleaned,
      timestamp: new Date().toISOString(),
    });
  } catch {
    return Response.json(
      { error: 'Failed to update target phone', message: 'Unable to update target phone.' },
      { status: 500 }
    );
  }
}
