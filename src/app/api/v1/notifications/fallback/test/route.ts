import { z } from 'zod';
import {
  sendEmailNotification,
  isEmailConfigured,
  escapeHtml,
} from '../../../../../../lib/integrations/emailService.js';
import {
  broadcastWebPushAlert,
  isWebPushConfigured,
  getVapidPublicKey,
} from '../../../../../../lib/integrations/webPushService.js';
import {
  sendFast2Sms,
  isFast2SmsConfigured,
  getFast2SmsTargetPhone,
  setFast2SmsTargetPhone,
} from '../../../../../../lib/integrations/fast2smsService.js';
import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../../lib/telemetry/adminAuth.js';

const TestChannelsSchema = z.object({
  channel: z.enum(['EMAIL', 'WEBPUSH', 'FAST2SMS', 'ALL']).optional().default('FAST2SMS'),
  action: z.enum(['TEST', 'SET_TARGET_PHONE']).optional().default('TEST'),
  targetEmail: z.string().email().optional(),
  targetPhone: z.string().optional(),
  title: z.string().max(160).optional(),
  message: z.string().max(2000).optional(),
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

  const currentTargetPhone = getFast2SmsTargetPhone();
  const visiblePhone = auth.user.role === 'ADMIN' ? currentTargetPhone : maskPhone(currentTargetPhone);
  return Response.json({
    status: 'ready',
    channels: {
      email: {
        provider: 'Nodemailer',
        configured: isEmailConfigured(),
        status: isEmailConfigured() ? 'SMTP Connected' : 'Sandbox (Ethereal test mode)',
      },
      webPush: {
        provider: 'WebPush API (VAPID)',
        configured: isWebPushConfigured(),
        vapidPublicKey: getVapidPublicKey(),
        status: 'Active (Device level alerts enabled)',
      },
      sms: {
        provider: 'Fast2SMS',
        configured: isFast2SmsConfigured(),
        targetPhone: visiblePhone,
        status: isFast2SmsConfigured() ? 'Fast2SMS Gateway Active' : 'Sandbox / Test Mode Active',
      },
    },
    targetPhone: visiblePhone,
    fast2smsTargetPhone: visiblePhone,
  });
}

export async function POST(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }

    const body = await request.json().catch(() => ({}));
    const parsed = TestChannelsSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        { error: 'Validation Error', details: parsed.error.format() },
        { status: 400 }
      );
    }

    const { channel, action, targetEmail, targetPhone, title, message } = parsed.data;

    // Dynamically configure FAST2SMS_TARGET_PHONE if a user mobile number is supplied
    if (targetPhone && targetPhone.trim()) {
      setFast2SmsTargetPhone(targetPhone);
    }

    // Direct configuration mutation action without dispatching test SMS
    if (action === 'SET_TARGET_PHONE') {
      const activePhone = getFast2SmsTargetPhone();
      return Response.json({
        success: true,
        message: 'FAST2SMS_TARGET_PHONE successfully configured with user mobile number',
        targetPhone: activePhone,
        fast2smsTargetPhone: activePhone,
        timestamp: new Date().toISOString(),
      });
    }

    const testTitle = title || 'Aegis Sentinel Security Test';
    const testMessage =
      message || 'Test dispatch verifying Nodemailer, WebPush, and Fast2SMS fallback channels.';
    const safeTestMessage = escapeHtml(testMessage);
    const results: Record<string, any> = {};

    // 1. Test Nodemailer Email
    if (channel === 'EMAIL' || channel === 'ALL') {
      const emailRecipient = targetEmail || process.env.NOTIFICATION_TARGET_EMAIL || 'rajputvanshc@gmail.com';
      const emailResult = await sendEmailNotification({
        to: emailRecipient,
        subject: `[Aegis Test] ${testTitle}`,
        text: testMessage,
        html: `
          <div style="font-family: sans-serif; background: #0b0f19; color: #ffffff; padding: 24px; border-radius: 12px;">
            <h2 style="color: #6366f1;">🛡️ Aegis Sentinel Dispatch Test</h2>
            <p style="color: #cbd5e1;">${safeTestMessage}</p>
            <div style="font-size: 11px; color: #64748b; margin-top: 16px;">Delivered via Nodemailer Service</div>
          </div>
        `,
      });
      results.email = {
        recipient: emailRecipient,
        ...emailResult,
      };
    }

    // 2. Test WebPush API
    if (channel === 'WEBPUSH' || channel === 'ALL') {
      const pushResult = await broadcastWebPushAlert({
        title: `🚨 ${testTitle}`,
        body: testMessage,
        icon: '/assets/logo.png',
        badge: '/assets/logo.png',
        data: { url: '/', test: true },
      });
      results.webPush = pushResult;
    }

    // 3. Test Fast2SMS
    if (channel === 'FAST2SMS' || channel === 'ALL') {
      const phoneRecipient = targetPhone?.trim() || getFast2SmsTargetPhone() || '9876543210';
      const smsResult = await sendFast2Sms(phoneRecipient, `[Aegis] ${testMessage}`);
      results.fast2sms = smsResult;
    }

    return Response.json({
      success: true,
      timestamp: new Date().toISOString(),
      testedChannel: channel,
      targetPhone: getFast2SmsTargetPhone(),
      results,
    });
  } catch {
    return Response.json(
      { error: 'Channel test failed', message: 'Unable to run fallback channel test.' },
      { status: 500 }
    );
  }
}
