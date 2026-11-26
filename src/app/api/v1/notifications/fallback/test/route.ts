import { z } from 'zod';
import {
  sendEmailNotification,
  isLiveSmtpConfigured,
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
import {
  isWhatsappConfigured,
  sendWhatsappCloudMessage,
} from '../../../../../../lib/delivery/channels/whatsappAdapter.js';
import { authenticateUserRequest } from '../../../../../../lib/auth/requestAuth.js';

const TestChannelsSchema = z.object({
  channel: z.enum(['EMAIL', 'WEBPUSH', 'FAST2SMS', 'WHATSAPP', 'ALL']).optional().default('FAST2SMS'),
  action: z.enum(['TEST', 'SET_TARGET_PHONE']).optional().default('TEST'),
  targetEmail: z.string().email().optional().or(z.literal('')),
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
  const smtpLive = isLiveSmtpConfigured();
  const waLive = isWhatsappConfigured();

  return Response.json({
    status: 'ready',
    channels: {
      email: {
        provider: 'Nodemailer',
        configured: smtpLive,
        status: smtpLive ? 'Live SMTP Connected' : 'Sandbox (Ethereal test mode)',
      },
      webPush: {
        provider: 'WebPush API (VAPID)',
        configured: isWebPushConfigured(),
        vapidPublicKey: getVapidPublicKey(),
        status: 'Active (Device level alerts enabled)',
      },
      whatsapp: {
        provider: 'Meta WhatsApp Cloud API',
        configured: waLive,
        status: waLive ? 'WhatsApp Business Cloud API Active' : 'Dry-Run Mode (Meta credentials unset)',
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
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
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
    const isAdmin = auth.user.role === 'ADMIN';

    if (action === 'SET_TARGET_PHONE') {
      if (!isAdmin) {
        return Response.json(
          { error: 'Forbidden', message: 'Only administrators may update the global gateway phone target.' },
          { status: 403 }
        );
      }
      if (targetPhone && targetPhone.trim()) {
        setFast2SmsTargetPhone(targetPhone);
      }
      const activePhone = getFast2SmsTargetPhone();
      return Response.json({
        success: true,
        message: 'FAST2SMS_TARGET_PHONE successfully configured with user mobile number',
        targetPhone: activePhone,
        fast2smsTargetPhone: activePhone,
        timestamp: new Date().toISOString(),
      });
    }

    // Only admins mutate the global Fast2SMS target phone during diagnostics
    if (isAdmin && channel === 'FAST2SMS' && targetPhone && targetPhone.trim()) {
      setFast2SmsTargetPhone(targetPhone);
    }

    const testTitle = title?.trim() || 'Aegis Sentinel Security Test';
    const testMessage =
      message?.trim() ||
      'Test dispatch verifying Nodemailer, WebPush, WhatsApp Cloud API, and Fast2SMS fallback channels.';
    const safeTestTitle = escapeHtml(testTitle);
    const safeTestMessage = escapeHtml(testMessage);
    const dispatchedAt = new Date().toISOString();
    const results: Record<string, any> = {};

    // 1. Test Nodemailer Email
    if (channel === 'EMAIL' || channel === 'ALL') {
      const emailRecipient =
        targetEmail?.trim() ||
        auth.user.email?.trim() ||
        process.env.NOTIFICATION_TARGET_EMAIL?.trim() ||
        '';

      if (!emailRecipient) {
        if (channel === 'EMAIL') {
          return Response.json(
            {
              success: false,
              error: 'Missing Target Email',
              message: 'Provide a targetEmail address or sign in with a verified email.',
            },
            { status: 400 }
          );
        }
        results.email = {
          success: false,
          skipped: true,
          error: 'No recipient email available for test dispatch.',
        };
      } else {
        const emailResult = await sendEmailNotification({
          to: emailRecipient,
          subject: `[Aegis Test] ${testTitle}`,
          text: `${testTitle}\n\n${testMessage}\n\nPriority: HIGH\nChannel: EMAIL\nTimestamp: ${dispatchedAt}`,
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f8fafc; padding: 24px; border-radius: 12px; border: 1px solid #1e293b;">
              <h2 style="color: #818cf8; margin: 0 0 12px 0;">🛡️ ${safeTestTitle}</h2>
              <p style="color: #cbd5e1; line-height: 1.5; margin: 0 0 16px 0;">${safeTestMessage}</p>
              <table style="width: 100%; border-collapse: collapse; font-size: 12px; color: #94a3b8; background: #111827; border-radius: 8px;">
                <tr><td style="padding: 8px 12px; border-bottom: 1px solid #1e293b;"><strong>Priority</strong></td><td style="padding: 8px 12px; border-bottom: 1px solid #1e293b;">HIGH (Diagnostic)</td></tr>
                <tr><td style="padding: 8px 12px; border-bottom: 1px solid #1e293b;"><strong>Channel</strong></td><td style="padding: 8px 12px; border-bottom: 1px solid #1e293b;">Nodemailer Email Gateway</td></tr>
                <tr><td style="padding: 8px 12px;"><strong>Timestamp</strong></td><td style="padding: 8px 12px;">${escapeHtml(dispatchedAt)}</td></tr>
              </table>
            </div>
          `,
        });
        results.email = {
          recipient: emailRecipient,
          ...emailResult,
        };
      }
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

    // 3. Test Meta WhatsApp Business Cloud API
    if (channel === 'WHATSAPP' || channel === 'ALL') {
      const waRecipient =
        targetPhone?.trim() ||
        process.env.WHATSAPP_DEFAULT_RECIPIENT?.trim() ||
        getFast2SmsTargetPhone() ||
        '';
      if (!waRecipient) {
        if (channel === 'WHATSAPP') {
          return Response.json(
            {
              success: false,
              error: 'Missing WhatsApp Phone',
              message: 'Provide a WhatsApp phone number in E.164 format (e.g. +919876543210).',
            },
            { status: 400 }
          );
        }
        results.whatsapp = {
          ok: false,
          skipped: true,
          error: 'No WhatsApp recipient phone configured.',
        };
      } else {
        const waResult = await sendWhatsappCloudMessage({
          to: waRecipient,
          bodyText: `🛡️ [Aegis Test] ${testTitle}\n${testMessage}`,
        });
        results.whatsapp = waResult;
      }
    }

    // 4. Test Fast2SMS
    if (channel === 'FAST2SMS' || channel === 'ALL') {
      const phoneRecipient = targetPhone?.trim() || getFast2SmsTargetPhone() || '9876543210';
      const smsResult = await sendFast2Sms(phoneRecipient, `[Aegis] ${testTitle}: ${testMessage}`);
      results.fast2sms = smsResult;
    }

    const visiblePhone = isAdmin ? getFast2SmsTargetPhone() : maskPhone(getFast2SmsTargetPhone());
    return Response.json({
      success: true,
      timestamp: dispatchedAt,
      testedChannel: channel,
      targetPhone: visiblePhone,
      results,
    });
  } catch {
    return Response.json(
      { error: 'Channel test failed', message: 'Unable to run fallback channel test.' },
      { status: 500 }
    );
  }
}
