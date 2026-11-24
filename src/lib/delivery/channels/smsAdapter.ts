import twilio from 'twilio';
import {
  getSmsProviderMode,
  getTwilioCredentials,
  validateAndNormalizePhone,
} from '../../integrations/smsService.js';
import { buildEphemeralGenericAlertText } from '../../ephemeral/constants.js';
import type { ChannelAdapter, ChannelSendResult, DeliveryJobRecord } from './types.js';

/**
 * SMS channel adapter respecting SMS_PROVIDER (mock vs twilio).
 *
 * STRICT PRIVACY RULE:
 * SMS MUST NEVER contain decrypted notification message content.
 * Only a generic priority notice + short signed ACK link is sent.
 */
export const smsChannelAdapter: ChannelAdapter = {
  channel: 'sms',
  async send(job: DeliveryJobRecord, ackUrl: string): Promise<ChannelSendResult> {
    if (job.isDemoJob) {
      if (job.demoFaults?.forceAllDown || job.demoFaults?.forceSmsFail) {
        return {
          ok: false,
          retryable: true,
          error: 'Simulated SMS gateway failure (Demo Mode).',
        };
      }
      return {
        ok: true,
        providerId: `mock-sms-${job.id}-a${job.attempt}`,
        retryable: false,
        mockDelivered: true,
        detail: 'mock-delivered',
      };
    }

    const mode = getSmsProviderMode();
    // Privacy-preserving generic alert body (never contains message plaintext)
    const genericAlertBody = job.isEphemeral
      ? `AegisNotify: ${buildEphemeralGenericAlertText(job.ephemeralTtlSeconds || 300)} Ack: ${ackUrl}`
      : `AegisNotify: You have a new ${job.priority} notification. Open AegisNotify to read it. Ack: ${ackUrl}`;

    if (mode === 'mock') {
      // Do NOT call Twilio in mock mode; mark mock-delivered
      return {
        ok: true,
        providerId: `mock-sms-${Date.now()}`,
        retryable: false,
        mockDelivered: true,
        detail: 'mock-delivered',
      };
    }

    // Live Twilio SMS mode
    const rawPhone = job.recipientPhone?.trim();
    if (!rawPhone) {
      return {
        ok: false,
        retryable: false,
        error: 'No verified recipient phone number configured for SMS fallback.',
      };
    }

    const phoneCheck = validateAndNormalizePhone(rawPhone);
    if (!phoneCheck.valid || !phoneCheck.e164) {
      return {
        ok: false,
        retryable: false,
        error: phoneCheck.message || 'Recipient phone number failed E.164 validation.',
      };
    }

    const { accountSid, authToken } = getTwilioCredentials();
    const fromNumber = String(process.env.TWILIO_FROM_NUMBER || '').trim();
    if (!accountSid || !authToken || !fromNumber) {
      return {
        ok: false,
        retryable: false,
        error: 'Live Twilio SMS requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER.',
      };
    }

    try {
      const client = twilio(accountSid, authToken);
      const msg = await client.messages.create({
        to: phoneCheck.e164,
        from: fromNumber,
        body: genericAlertBody,
      });
      return {
        ok: true,
        providerId: msg.sid,
        retryable: false,
        detail: 'Delivered via Twilio SMS gateway',
      };
    } catch (err: any) {
      const isRateLimited =
        err?.status === 429 ||
        err?.code === 20429 ||
        /rate.?limit|429|throttl/i.test(String(err?.message || ''));
      return {
        ok: false,
        retryable: true,
        error: isRateLimited
          ? `throttled by Twilio SMS provider (code=${err?.code || 429})`
          : `Twilio SMS dispatch error (code=${err?.code || 'UNKNOWN'})`,
      };
    }
  },
};
