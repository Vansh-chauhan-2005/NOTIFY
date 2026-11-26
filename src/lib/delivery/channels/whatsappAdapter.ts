import { buildEphemeralGenericAlertText } from '../../ephemeral/constants.js';
import type { ChannelAdapter, ChannelSendResult, DeliveryJobRecord } from './types.js';

const E164_REGEX = /^\+[1-9]\d{6,14}$/;

export function isWhatsappConfigured(): boolean {
  return Boolean(
    process.env.WHATSAPP_ACCESS_TOKEN?.trim() &&
      process.env.WHATSAPP_PHONE_NUMBER_ID?.trim()
  );
}

export function formatE164Phone(raw?: string | null): {
  valid: boolean;
  e164?: string;
  digitsOnly?: string;
  error?: string;
} {
  const cleaned = String(raw || '')
    .trim()
    .replace(/[\s\-().]/g, '');

  if (!cleaned) {
    return { valid: false, error: 'Recipient WhatsApp phone number is required.' };
  }

  let normalized = cleaned;
  if (/^[6-9]\d{9}$/.test(cleaned)) {
    normalized = `+91${cleaned}`;
  } else if (!normalized.startsWith('+') && /^[1-9]\d{7,14}$/.test(cleaned)) {
    normalized = `+${cleaned}`;
  }

  if (!E164_REGEX.test(normalized)) {
    return {
      valid: false,
      error: 'WhatsApp number must use E.164 format (e.g. +919876543210).',
    };
  }

  return {
    valid: true,
    e164: normalized,
    digitsOnly: normalized.slice(1),
  };
}

export async function sendWhatsappCloudMessage(params: {
  to: string;
  bodyText: string;
  templateName?: string;
}): Promise<ChannelSendResult & { recipient?: string }> {
  const phoneCheck = formatE164Phone(params.to);
  if (!phoneCheck.valid || !phoneCheck.e164 || !phoneCheck.digitsOnly) {
    return {
      ok: false,
      retryable: false,
      error: phoneCheck.error || 'Invalid recipient WhatsApp phone number.',
    };
  }

  if (!isWhatsappConfigured()) {
    return {
      ok: true,
      recipient: phoneCheck.e164,
      providerId: `mock-wa-${Date.now()}`,
      retryable: false,
      mockDelivered: true,
      detail: 'WhatsApp Cloud API credentials unconfigured (dry-run simulated delivery).',
    };
  }

  const accessToken = process.env.WHATSAPP_ACCESS_TOKEN!.trim();
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID!.trim();
  const templateName = (params.templateName || process.env.WHATSAPP_TEMPLATE_NAME || '').trim();

  const endpoint = `https://graph.facebook.com/v21.0/${encodeURIComponent(phoneNumberId)}/messages`;
  const payload = templateName
    ? {
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: phoneCheck.digitsOnly,
        type: 'template',
        template: {
          name: templateName,
          language: { code: 'en_US' },
          components: [
            {
              type: 'body',
              parameters: [{ type: 'text', text: params.bodyText.slice(0, 900) }],
            },
          ],
        },
      }
    : {
        messaging_product: 'whatsapp',
        recipient_type: 'individual',
        to: phoneCheck.digitsOnly,
        type: 'text',
        text: {
          preview_url: false,
          body: params.bodyText.slice(0, 1024),
        },
      };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const data: any = await res.json().catch(() => ({}));

    if (!res.ok) {
      const apiErr = data?.error?.message || `Meta Graph API HTTP ${res.status}`;
      const isRetryable = res.status === 429 || res.status >= 500;
      return {
        ok: false,
        recipient: phoneCheck.e164,
        retryable: isRetryable,
        error: res.status === 429 ? `throttled by WhatsApp Cloud API (${apiErr})` : apiErr,
      };
    }

    const msgId = data?.messages?.[0]?.id || `wa-${Date.now()}`;
    return {
      ok: true,
      recipient: phoneCheck.e164,
      providerId: msgId,
      retryable: false,
      mockDelivered: false,
      detail: 'Delivered via Meta WhatsApp Cloud API v21.0',
    };
  } catch (err: any) {
    return {
      ok: false,
      recipient: phoneCheck.e164,
      retryable: true,
      error:
        err?.name === 'AbortError'
          ? 'WhatsApp Cloud API request timed out.'
          : err?.message || 'WhatsApp Cloud API network error.',
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * WhatsApp Business Cloud API v21.0 channel adapter.
 *
 * STRICT EPHEMERAL RULE:
 * Ephemeral notifications NEVER include plaintext or ciphertext.
 */
export const whatsappChannelAdapter: ChannelAdapter = {
  channel: 'whatsapp',
  async send(job: DeliveryJobRecord, ackUrl: string): Promise<ChannelSendResult> {
    if (job.isDemoJob) {
      if (job.demoFaults?.forceAllDown || job.demoFaults?.forceWhatsappFail) {
        return {
          ok: false,
          retryable: true,
          error: 'Simulated WhatsApp Cloud API failure (Demo Mode).',
        };
      }
      return {
        ok: true,
        providerId: `mock-wa-${job.id}-a${job.attempt}`,
        retryable: false,
        mockDelivered: true,
        detail: 'mock-delivered',
      };
    }

    if (!isWhatsappConfigured()) {
      return {
        ok: true,
        providerId: `mock-wa-${Date.now()}`,
        retryable: false,
        mockDelivered: true,
        detail: 'WhatsApp Cloud API unconfigured (dry-run simulated)',
      };
    }

    const rawPhone = job.recipientWhatsappPhone?.trim() || job.recipientPhone?.trim();
    if (!rawPhone) {
      return {
        ok: false,
        retryable: false,
        error: 'No WhatsApp phone number configured on user profile.',
      };
    }

    const bodyText = job.isEphemeral
      ? `AegisNotify: ${buildEphemeralGenericAlertText(job.ephemeralTtlSeconds || 300)} Ack: ${ackUrl}`
      : `AegisNotify [${job.priority}]${job.sourceApp ? ` (${job.sourceApp})` : ''}: ${
          job.title ? job.title.slice(0, 140) : `New ${job.priority} security alert`
        }. Ack: ${ackUrl}`;

    return await sendWhatsappCloudMessage({
      to: rawPhone,
      bodyText,
    });
  },
};
