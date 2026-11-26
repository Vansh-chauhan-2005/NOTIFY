import { sendEmailNotification, escapeHtml } from '../../integrations/emailService.js';
import { buildEphemeralGenericAlertText } from '../../ephemeral/constants.js';
import type { ChannelAdapter, ChannelSendResult, DeliveryJobRecord } from './types.js';

/**
 * Email channel adapter reusing Nodemailer emailService.
 *
 * CONTENT POLICY:
 * - Ephemeral alerts MUST NEVER contain plaintext or ciphertext.
 * - Non-ephemeral alerts include the full escaped alert title, priority badge,
 *   source app, timestamp, Job ID, and signed single-use ACK button.
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
    const nonEphemeralTitle = (job.title || `New ${job.priority} Security Alert`).trim();
    const sourceApp = (job.sourceApp || 'AegisNotify').trim();
    const sentTimestamp = new Date().toISOString();

    const safeTitle = escapeHtml(nonEphemeralTitle);
    const safePriority = escapeHtml(job.priority);
    const safeSourceApp = escapeHtml(sourceApp);
    const safeJobId = escapeHtml(job.id);
    const safeTimestamp = escapeHtml(sentTimestamp);
    const safeAckUrl = escapeHtml(ackUrl);

    const subject = job.isEphemeral
      ? '[AegisNotify] Self-destructing message waiting (expires shortly)'
      : `[AegisNotify · ${job.priority}] ${nonEphemeralTitle.slice(0, 110)}`;

    const textBody = job.isEphemeral
      ? [
          ephemeralLine,
          'Content is end-to-end encrypted and will be crypto-shredded at expiry.',
          '',
          `Acknowledge receipt (single-use): ${ackUrl}`,
        ].join('\n')
      : [
          `Priority: ${job.priority}`,
          `Title: ${nonEphemeralTitle}`,
          `Source App: ${sourceApp}`,
          `Timestamp: ${sentTimestamp}`,
          `Job ID: ${job.id}`,
          '',
          `Acknowledge receipt (single-use, expires in 15 minutes): ${ackUrl}`,
        ].join('\n');

    const safeHtml = job.isEphemeral
      ? `
<!DOCTYPE html>
<html>
  <body style="font-family: system-ui, -apple-system, sans-serif; background:#FAF6F0; color:#16161D; padding:24px;">
    <div style="max-width:540px; margin:0 auto; background:#FFFDF9; border:1px solid #E5DDD0; border-radius:16px; padding:24px;">
      <h2 style="margin:0 0 8px; font-size:18px; color:#16161D;">AegisNotify · Self-Destructing Message</h2>
      <p style="margin:0 0 16px; font-size:14px; color:#464451; line-height:1.5;">
        ${escapeHtml(ephemeralLine)}
      </p>
      <a href="${safeAckUrl}" style="display:inline-block; background:#D9468F; color:#FFFDF9; text-decoration:none; padding:10px 18px; border-radius:10px; font-weight:600; font-size:13px;">
        Acknowledge Notification
      </a>
      <p style="margin:16px 0 0; font-size:11px; color:#6F6C7A;">
        This acknowledgement link is single-use and expires in 15 minutes.
      </p>
    </div>
  </body>
</html>`.trim()
      : `
<!DOCTYPE html>
<html>
  <body style="font-family: system-ui, -apple-system, sans-serif; background:#FAF6F0; color:#16161D; padding:24px;">
    <div style="max-width:560px; margin:0 auto; background:#FFFDF9; border:1px solid #E5DDD0; border-radius:16px; overflow:hidden;">
      <div style="background:#16161D; color:#FAF6F0; padding:18px 24px;">
        <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#F472B6; font-weight:700;">
          AegisNotify · ${safePriority} Alert
        </div>
        <h2 style="margin:6px 0 0; font-size:18px; line-height:1.35; color:#FAF6F0;">
          ${safeTitle}
        </h2>
      </div>
      <div style="padding:24px;">
        <table style="width:100%; border-collapse:collapse; margin-bottom:20px; font-size:12px;">
          <tr>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; color:#6F6C7A;">Priority</td>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; text-align:right; font-weight:700; color:#B52A70;">${safePriority}</td>
          </tr>
          <tr>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; color:#6F6C7A;">Source App</td>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; text-align:right; font-weight:600; color:#16161D;">${safeSourceApp}</td>
          </tr>
          <tr>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; color:#6F6C7A;">Timestamp</td>
            <td style="padding:8px 0; border-bottom:1px solid #E5DDD0; text-align:right; font-family:monospace; color:#464451;">${safeTimestamp}</td>
          </tr>
          <tr>
            <td style="padding:8px 0; color:#6F6C7A;">Delivery Job ID</td>
            <td style="padding:8px 0; text-align:right; font-family:monospace; color:#464451;">${safeJobId}</td>
          </tr>
        </table>
        <a href="${safeAckUrl}" style="display:inline-block; background:#D9468F; color:#FFFDF9; text-decoration:none; padding:11px 20px; border-radius:10px; font-weight:600; font-size:13px;">
          Acknowledge Notification
        </a>
        <p style="margin:16px 0 0; font-size:11px; color:#6F6C7A;">
          This acknowledgement link is single-use and expires in 15 minutes.
        </p>
      </div>
    </div>
  </body>
</html>`.trim();

    try {
      const res = await sendEmailNotification({
        to,
        subject,
        text: textBody,
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

      const previewNote = res.previewUrl ? ` (Preview: ${res.previewUrl})` : '';
      return {
        ok: true,
        providerId: res.messageId || `email-${Date.now()}`,
        retryable: false,
        mockDelivered: Boolean(res.simulated),
        detail: res.simulated
          ? `Email delivered via test/stream transport${previewNote}`
          : 'Delivered via SMTP',
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
