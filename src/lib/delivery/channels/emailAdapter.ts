import { sendEmailNotification } from '../../integrations/emailService.js';
import { buildEphemeralGenericAlertText } from '../../ephemeral/constants.js';
import type { ChannelAdapter, ChannelSendResult, DeliveryJobRecord } from './types.js';

/**
 * Email channel adapter reusing Nodemailer emailService.
 *
 * STRICT PRIVACY RULE:
 * Email MUST NEVER contain decrypted notification message content.
 * Only a generic priority notice + short signed ACK link is included.
 */
export const emailChannelAdapter: ChannelAdapter = {
  channel: 'email',
  async send(job: DeliveryJobRecord, ackUrl: string): Promise<ChannelSendResult> {
    if (job.isDemoJob) {
      if (job.demoFaults?.forceAllDown || job.demoFaults?.forceEmailFail) {
        return {
          ok: false,
          retryable: true,
          error: 'Simulated SMTP email failure (Demo Mode).',
        };
      }
      return {
        ok: true,
        providerId: `mock-email-${job.id}-a${job.attempt}`,
        retryable: false,
        mockDelivered: true,
        detail: 'mock-delivered',
      };
    }

    const to =
      job.recipientEmail?.trim() ||
      process.env.ADMIN_FALLBACK_EMAIL?.trim() ||
      process.env.NOTIFICATION_TARGET_EMAIL?.trim();

    if (!to) {
      return {
        ok: false,
        retryable: false,
        error: 'No recipient email configured for email fallback.',
      };
    }

    const ephemeralLine = buildEphemeralGenericAlertText(job.ephemeralTtlSeconds || 300);
    const subject = job.isEphemeral
      ? '[AegisNotify] Self-destructing message waiting (expires shortly)'
      : `[AegisNotify] New ${job.priority} notification waiting`;
    const genericText = job.isEphemeral
      ? [
          ephemeralLine,
          'Content is end-to-end encrypted and will be crypto-shredded at expiry.',
          '',
          `Acknowledge receipt (single-use): ${ackUrl}`,
        ].join('\n')
      : [
          `You have a new ${job.priority} notification.`,
          'Open AegisNotify to read the decrypted message.',
          '',
          `Acknowledge receipt (single-use, expires in 15 minutes): ${ackUrl}`,
        ].join('\n');

    const safeHtml = `
<!DOCTYPE html>
<html>
  <body style="font-family: system-ui, -apple-system, sans-serif; background:#FAF6F0; color:#16161D; padding:24px;">
    <div style="max-width:520px; margin:0 auto; background:#FFFDF9; border:1px solid #E5DDD0; border-radius:16px; padding:24px;">
      <h2 style="margin:0 0 8px; font-size:18px; color:#16161D;">AegisNotify · ${
        job.isEphemeral ? 'Self-Destructing Message' : `${job.priority} Alert`
      }</h2>
      <p style="margin:0 0 16px; font-size:14px; color:#464451; line-height:1.5;">
        ${
          job.isEphemeral
            ? ephemeralLine
            : `You have a new <strong>${job.priority}</strong> notification. Message details are encrypted and only readable inside AegisNotify.`
        }
      </p>
      <a href="${ackUrl}" style="display:inline-block; background:#D9468F; color:#FFFDF9; text-decoration:none; padding:10px 18px; border-radius:10px; font-weight:600; font-size:13px;">
        Acknowledge Notification
      </a>
      <p style="margin:16px 0 0; font-size:11px; color:#6F6C7A;">
        This acknowledgement link is single-use and expires in 15 minutes.
      </p>
    </div>
  </body>
</html>`.trim();

    try {
      const res = await sendEmailNotification({
        to,
        subject,
        text: genericText,
        html: safeHtml,
      });

      if (!res.success) {
        const isThrottled = /429|rate.?limit|throttl/i.test(String(res.error || ''));
        return {
          ok: false,
          retryable: true,
          error: isThrottled ? `throttled (${res.error})` : res.error || 'Email transport returned failure.',
        };
      }

      return {
        ok: true,
        providerId: res.messageId || `email-${Date.now()}`,
        retryable: false,
        mockDelivered: Boolean(res.simulated),
        detail: res.simulated ? 'Email delivered via test/stream transport' : 'Delivered via SMTP',
      };
    } catch (err: any) {
      const msg = String(err?.message || 'Unexpected email dispatch failure.');
      const isThrottled = err?.status === 429 || /429|rate.?limit|throttl/i.test(msg);
      return {
        ok: false,
        retryable: true,
        error: isThrottled ? `throttled (${msg})` : msg,
      };
    }
  },
};
