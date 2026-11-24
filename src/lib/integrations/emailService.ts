import nodemailer, { Transporter } from 'nodemailer';

export interface EmailSendOptions {
  to: string;
  subject: string;
  text?: string;
  html?: string;
  requireLiveTransport?: boolean;
}

export interface EmailSendResult {
  success: boolean;
  messageId?: string;
  previewUrl?: string | false;
  simulated?: boolean;
  error?: string;
}

let cachedTransporter: Transporter | null = null;
let cachedTransportIsLive = false;

export function escapeHtml(input: unknown): string {
  return String(input ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function isLiveSmtpConfigured(): boolean {
  const host = (process.env.SMTP_HOST || process.env.EMAIL_HOST || process.env.NODEMAILER_HOST || '').trim();
  const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
  const pass = (process.env.SMTP_PASS || process.env.EMAIL_PASS || '').trim();
  return Boolean((host || user.toLowerCase().endsWith('@gmail.com')) && user && pass);
}

export function isEmailConfigured(): boolean {
  return Boolean(
    process.env.SMTP_HOST?.trim() ||
    process.env.EMAIL_HOST?.trim() ||
    process.env.NODEMAILER_HOST?.trim() ||
    process.env.ETHEREAL_USER?.trim() ||
    isLiveSmtpConfigured()
  );
}

export async function getMailTransporter(requireLiveTransport = false): Promise<Transporter> {
  if (cachedTransporter && (!requireLiveTransport || cachedTransportIsLive)) {
    return cachedTransporter;
  }

  try {
    const user = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    const rawPass = (process.env.SMTP_PASS || process.env.EMAIL_PASS || '').trim();
    // Strip spaces if user pasted a 16-char Google App Password in "xxxx xxxx xxxx xxxx" format
    const pass = /^[a-zA-Z0-9]{4}(\s+[a-zA-Z0-9]{4}){3}$/.test(rawPass)
      ? rawPass.replace(/\s+/g, '')
      : rawPass;
    const rawHost = (
      process.env.SMTP_HOST ||
      process.env.EMAIL_HOST ||
      process.env.NODEMAILER_HOST ||
      ''
    ).trim();
    const host = rawHost || (user.toLowerCase().endsWith('@gmail.com') ? 'smtp.gmail.com' : '');
    const parsedPort = parseInt(process.env.SMTP_PORT || process.env.EMAIL_PORT || '587', 10);
    const port = Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : 587;
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;

    if (host && user && pass) {
      console.log(`[Email] Initializing SMTP Transport via ${host}:${port} (${user})`);
      cachedTransporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
      });
      cachedTransportIsLive = true;
      return cachedTransporter;
    }

    if (requireLiveTransport) {
      throw new Error(
        'Live SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASS in environment secrets.'
      );
    }

    // If no SMTP server configured and live transport isn't required, create test Ethereal or sandbox fallback transporter
    console.log('[Email] No SMTP credentials provided. Creating ethereal test account...');
    try {
      const testAccount = await nodemailer.createTestAccount();
      console.log(`[Email] Ethereal test inbox created: ${testAccount.user}`);
      cachedTransporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      cachedTransportIsLive = false;
      return cachedTransporter;
    } catch (err: any) {
      console.log('[Email] Could not create Ethereal account, using stream test transport:', err.message);
      cachedTransporter = nodemailer.createTransport({
        streamTransport: true,
        newline: 'unix',
        buffer: true,
      });
      cachedTransportIsLive = false;
      return cachedTransporter;
    }
  } catch (err: any) {
    cachedTransporter = null;
    cachedTransportIsLive = false;
    throw new Error(err?.message || 'Failed to initialize Nodemailer transport.');
  }
}

let cachedSmtpVerify: { checkedAt: number; ok: boolean; error?: string } | null = null;

function formatSmtpError(err: any): string {
  const rawMsg = String(err?.message || 'Unknown SMTP failure');
  const isGmailAppPasswordError =
    rawMsg.includes('534-5.7.9') ||
    rawMsg.includes('Application-specific password required') ||
    rawMsg.includes('InvalidSecondFactor');

  return isGmailAppPasswordError
    ? 'Gmail SMTP rejected login (534-5.7.9 Application-specific password required). Update SMTP_PASS in Secrets to a 16-character Google App Password (Google Account → Security → 2-Step Verification → App passwords).'
    : rawMsg;
}

export async function verifyLiveSmtpHealth(): Promise<{ ok: boolean; error?: string }> {
  if (!isLiveSmtpConfigured()) {
    return { ok: false, error: 'Live SMTP credentials not configured.' };
  }

  const now = Date.now();
  if (cachedSmtpVerify && now - cachedSmtpVerify.checkedAt < 60000) {
    return { ok: cachedSmtpVerify.ok, error: cachedSmtpVerify.error };
  }

  try {
    const transporter = await getMailTransporter(true);
    await transporter.verify();
    cachedSmtpVerify = { checkedAt: now, ok: true };
    return { ok: true };
  } catch (err: any) {
    cachedTransporter = null;
    cachedTransportIsLive = false;
    const friendlyMsg = formatSmtpError(err);
    cachedSmtpVerify = { checkedAt: now, ok: false, error: friendlyMsg };
    return { ok: false, error: friendlyMsg };
  }
}

export async function sendEmailNotification(options: EmailSendOptions): Promise<EmailSendResult> {
  try {
    const transporter = await getMailTransporter(Boolean(options.requireLiveTransport));
    const configuredUser = (process.env.SMTP_USER || process.env.EMAIL_USER || '').trim();
    const fromAddress =
      process.env.SMTP_FROM?.trim() ||
      process.env.EMAIL_FROM?.trim() ||
      (configuredUser ? `"Aegis Sentinel Security" <${configuredUser}>` : '"Aegis Sentinel Security" <notifications@aegis-security.internal>');

    const info = await transporter.sendMail({
      from: fromAddress,
      to: options.to,
      subject: options.subject,
      text: options.text || '',
      html: options.html || `<p>${escapeHtml(options.text || '')}</p>`,
    });

    const previewUrl = nodemailer.getTestMessageUrl(info);
    console.log(`[Email] Notification sent to ${options.to}. ID: ${info.messageId}`);
    if (previewUrl) {
      console.log(`[Email Preview URL] ${previewUrl}`);
    }

    cachedSmtpVerify = { checkedAt: Date.now(), ok: true };

    return {
      success: true,
      messageId: info.messageId,
      previewUrl: previewUrl || undefined,
      simulated: !cachedTransportIsLive,
    };
  } catch (err: any) {
    cachedTransporter = null;
    cachedTransportIsLive = false;
    const friendlyMsg = formatSmtpError(err);
    cachedSmtpVerify = { checkedAt: Date.now(), ok: false, error: friendlyMsg };

    console.log(`[Email Delivery Rejected] ${options.to}: ${friendlyMsg}`);
    return {
      success: false,
      error: friendlyMsg,
    };
  }
}

export function buildFallbackAlertEmailHtml(params: {
  eventType: string;
  rawText: string;
  dispatchScore: number;
  notificationId: string;
  timestamp: string;
}): string {
  const { eventType, rawText, dispatchScore, notificationId, timestamp } = params;
  const isCritical = dispatchScore >= 0.9;
  const accentColor = isCritical ? '#f43f5e' : '#6366f1';
  const safeEventType = escapeHtml(eventType);
  const safeRawText = escapeHtml(rawText);
  const safeNotificationId = escapeHtml(notificationId);
  const safeTimestamp = escapeHtml(timestamp);
  const safeScore = escapeHtml(dispatchScore);
  const safePercent = escapeHtml((dispatchScore * 100).toFixed(0));

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f8fafc; margin: 0; padding: 24px; }
    .container { max-width: 580px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 16px; overflow: hidden; }
    .header { background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%); padding: 24px 32px; }
    .header h1 { margin: 0; font-size: 20px; font-weight: 700; color: #ffffff; letter-spacing: -0.02em; }
    .header p { margin: 6px 0 0; font-size: 13px; color: rgba(255,255,255,0.85); }
    .body { padding: 32px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; background: ${accentColor}25; color: ${accentColor}; border: 1px solid ${accentColor}40; margin-bottom: 16px; }
    .message-box { background: #0b0f19; border: 1px solid #1f2937; border-left: 4px solid ${accentColor}; border-radius: 8px; padding: 16px 20px; margin: 20px 0; font-size: 14px; line-height: 1.6; color: #e2e8f0; }
    .meta-table { width: 100%; border-collapse: collapse; margin-top: 24px; font-size: 12px; }
    .meta-table td { padding: 8px 0; border-top: 1px solid #1f2937; color: #94a3b8; }
    .meta-table td.val { text-align: right; color: #f1f5f9; font-family: monospace; }
    .footer { padding: 20px 32px; background: #0b0f19; border-top: 1px solid #1f2937; font-size: 11px; color: #64748b; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Aegis Security Notification</h1>
      <p>Automated Secondary Escalation (ACK Timeout Fallback)</p>
    </div>
    <div class="body">
      <div class="badge">${safeEventType} · Weight W=${safeScore}</div>
      <p style="margin: 0; font-size: 15px; color: #cbd5e1;">A critical notification dispatched via WebSocket was not acknowledged within the 3,000ms SLA window. This email escalation has been triggered automatically.</p>
      
      <div class="message-box">
        ${safeRawText}
      </div>

      <table class="meta-table">
        <tr>
          <td>Notification ID</td>
          <td class="val">${safeNotificationId}</td>
        </tr>
        <tr>
          <td>Calculated Risk Score</td>
          <td class="val">${safePercent}% (W=${safeScore})</td>
        </tr>
        <tr>
          <td>Dispatched Timestamp</td>
          <td class="val">${safeTimestamp}</td>
        </tr>
        <tr>
          <td>Delivery SLA</td>
          <td class="val">Zero-Trust WebSocket &rarr; Fallback Escalation</td>
        </tr>
      </table>
    </div>
    <div class="footer">
      Delivered via Aegis Nodemailer Ingress Service · Ed25519-Signed Real-Time Pipeline
    </div>
  </div>
</body>
</html>
  `;
}
