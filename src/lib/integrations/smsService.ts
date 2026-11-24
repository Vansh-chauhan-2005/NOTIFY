import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import twilio from 'twilio';
import { connectToDatabase } from '../db/mongoose.js';
import { User, inMemoryUsers } from '../../models/User.js';
import {
  logSecurityEvent,
  maskPhone as maskPhoneTelemetry,
} from '../telemetry/securityLogger.js';

export type SmsProviderMode = 'twilio' | 'mock';

export interface SmsRequestContext {
  ipAddress?: string;
  userAgent?: string;
  namespace?: 'live' | 'sim';
}

export interface VerifiedPhoneLinkRecord {
  phoneHash: string;
  maskedPhone: string;
  phoneVerified: boolean;
  userId: string;
  email?: string;
  displayName?: string;
  role: string;
  linkedAt: string;
}

interface PhoneAbuseState {
  lastSentAt: number;
  dailyDateKey: string;
  dailySendCount: number;
  wrongAttempts: number;
  lockedUntil: number;
}

interface IpAbuseState {
  sendTimestamps: number[];
}

interface SmsProtectionStore {
  phones: Map<string, PhoneAbuseState>;
  ips: Map<string, IpAbuseState>;
}

const PHONE_COOLDOWN_MS = 60 * 1000; // 60 seconds
const PHONE_DAILY_SEND_LIMIT = 5;
const IP_HOURLY_SEND_LIMIT = 10;
const IP_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_WRONG_ATTEMPTS = 5;
const PHONE_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const MOCK_DEMO_CODE = '123456';
const DEFAULT_MOCK_ALLOWLIST = ['+919876543210', '+919000000001'];
const SIM_BRUTE_FORCE_PHONE = '+919000000091';
const SIM_FLOOD_PHONE = '+919000000092';

const PHONE_LINKS_PATH = path.resolve(process.cwd(), 'sms-phone-links.json');

declare global {
  var __aegisSmsLiveStore: SmsProtectionStore | undefined;
  var __aegisSmsSimStore: SmsProtectionStore | undefined;
  var __aegisVerifiedPhoneLinks: Map<string, VerifiedPhoneLinkRecord> | undefined;
  var __aegisVerifiedPhoneLinksHydrated: boolean | undefined;
}

function getProtectionStore(namespace: 'live' | 'sim' = 'live'): SmsProtectionStore {
  if (namespace === 'sim') {
    if (!global.__aegisSmsSimStore) {
      global.__aegisSmsSimStore = { phones: new Map(), ips: new Map() };
    }
    return global.__aegisSmsSimStore;
  }
  if (!global.__aegisSmsLiveStore) {
    global.__aegisSmsLiveStore = { phones: new Map(), ips: new Map() };
  }
  return global.__aegisSmsLiveStore;
}

function getPhoneLinkStore(): Map<string, VerifiedPhoneLinkRecord> {
  if (!global.__aegisVerifiedPhoneLinks) {
    global.__aegisVerifiedPhoneLinks = new Map();
  }
  if (!global.__aegisVerifiedPhoneLinksHydrated) {
    global.__aegisVerifiedPhoneLinksHydrated = true;
    try {
      if (fs.existsSync(PHONE_LINKS_PATH)) {
        const raw = fs.readFileSync(PHONE_LINKS_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          for (const row of parsed) {
            if (row?.phoneHash && row?.userId) {
              global.__aegisVerifiedPhoneLinks.set(String(row.phoneHash), row as VerifiedPhoneLinkRecord);
            }
          }
        }
      }
    } catch {
      // Non-fatal if persistence file is not present yet
    }
  }
  return global.__aegisVerifiedPhoneLinks;
}

function persistPhoneLinkStore(store: Map<string, VerifiedPhoneLinkRecord>) {
  try {
    const records = Array.from(store.values());
    fs.writeFileSync(PHONE_LINKS_PATH, JSON.stringify(records, null, 2), 'utf8');
  } catch {
    // Keep in-memory store operational even on read-only disk
  }
}

export function isProductionEnv(): boolean {
  return String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
}

export function getSmsProviderMode(): SmsProviderMode {
  // Security guardrail: mock mode MUST be impossible in production
  if (isProductionEnv()) {
    return 'twilio';
  }
  const configured = String(process.env.SMS_PROVIDER || 'mock').trim().toLowerCase();
  return configured === 'twilio' ? 'twilio' : 'mock';
}

export function getTwilioCredentials() {
  const accountSid = String(process.env.TWILIO_ACCOUNT_SID || '').trim();
  const authToken = String(process.env.TWILIO_AUTH_TOKEN || '').trim();
  const verifyServiceSid = String(process.env.TWILIO_VERIFY_SERVICE_SID || '').trim();
  return { accountSid, authToken, verifyServiceSid };
}

export function isTwilioConfigured(): boolean {
  const { accountSid, authToken, verifyServiceSid } = getTwilioCredentials();
  return Boolean(accountSid && authToken && verifyServiceSid);
}

export function isSmsConfigured(): boolean {
  const mode = getSmsProviderMode();
  if (mode === 'mock') {
    return !isProductionEnv();
  }
  return isTwilioConfigured();
}

export function getAllowedCountries(): string[] {
  const raw = String(process.env.SMS_ALLOWED_COUNTRIES || '+91').trim();
  const items = raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => (item.startsWith('+') ? item : `+${item.replace(/\D/g, '')}`))
    .filter((item) => /^\+\d{1,4}$/.test(item));
  return items.length > 0 ? Array.from(new Set(items)) : ['+91'];
}

export function getMockAllowlist(): string[] {
  if (isProductionEnv()) {
    return [];
  }
  const raw = String(process.env.MOCK_SMS_NUMBERS || '').trim();
  const list = raw
    ? raw
        .split(',')
        .map((n) => normalizeRawToE164(n))
        .filter((n): n is string => Boolean(n))
    : DEFAULT_MOCK_ALLOWLIST;
  return Array.from(new Set(list));
}

export function maskPhone(rawPhone: string): string {
  return maskPhoneTelemetry(rawPhone);
}

export function hashPhone(e164Phone: string): string {
  return crypto.createHash('sha256').update(e164Phone.trim()).digest('hex');
}

function normalizeRawToE164(raw: string): string | null {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return null;
  const compact = trimmed.replace(/[\s\-()]/g, '');
  if (compact.startsWith('+')) {
    return /^\+[1-9]\d{6,14}$/.test(compact) ? compact : null;
  }
  const digits = compact.replace(/\D/g, '');
  if (digits.length === 10) {
    return `+91${digits}`;
  }
  return null;
}

export function validateAndNormalizePhone(rawPhone: string): {
  valid: boolean;
  e164?: string;
  masked?: string;
  message?: string;
} {
  const trimmed = String(rawPhone || '').trim();
  if (!trimmed) {
    return { valid: false, message: 'Phone number is required.' };
  }

  const compact = trimmed.replace(/[\s\-()]/g, '');
  const candidate = compact.startsWith('+')
    ? compact
    : /^\d{10}$/.test(compact)
    ? `+91${compact}`
    : compact;

  if (!/^\+[1-9]\d{7,14}$/.test(candidate)) {
    return {
      valid: false,
      message: 'Please enter a valid phone number in E.164 format (for example +919876543210).',
    };
  }

  const allowedCountries = getAllowedCountries();
  const sortedPrefixes = [...allowedCountries].sort((a, b) => b.length - a.length);
  const matchedPrefix = sortedPrefixes.find((prefix) => candidate.startsWith(prefix));

  if (!matchedPrefix) {
    return {
      valid: false,
      message: `Country code is not on the allowed list (${allowedCountries.join(', ')}).`,
    };
  }

  if (matchedPrefix === '+91' && candidate.length !== 13) {
    return {
      valid: false,
      message: 'Indian mobile numbers (+91) must have exactly 10 digits after +91.',
    };
  }

  return {
    valid: true,
    e164: candidate,
    masked: maskPhone(candidate),
  };
}

function getUtcDateKey(now: number): string {
  return new Date(now).toISOString().slice(0, 10);
}

function getPhoneAbuseState(store: SmsProtectionStore, phoneKey: string, now: number): PhoneAbuseState {
  const today = getUtcDateKey(now);
  let state = store.phones.get(phoneKey);
  if (!state) {
    state = {
      lastSentAt: 0,
      dailyDateKey: today,
      dailySendCount: 0,
      wrongAttempts: 0,
      lockedUntil: 0,
    };
    store.phones.set(phoneKey, state);
    return state;
  }
  if (state.dailyDateKey !== today) {
    state.dailyDateKey = today;
    state.dailySendCount = 0;
  }
  if (state.lockedUntil > 0 && now >= state.lockedUntil) {
    state.lockedUntil = 0;
    state.wrongAttempts = 0;
  }
  return state;
}

function getIpSendCountLastHour(store: SmsProtectionStore, ipKey: string, now: number): number {
  const state = store.ips.get(ipKey);
  if (!state) return 0;
  const cutoff = now - IP_WINDOW_MS;
  state.sendTimestamps = state.sendTimestamps.filter((ts) => ts > cutoff);
  return state.sendTimestamps.length;
}

function recordIpSend(store: SmsProtectionStore, ipKey: string, now: number) {
  let state = store.ips.get(ipKey);
  if (!state) {
    state = { sendTimestamps: [] };
    store.ips.set(ipKey, state);
  }
  const cutoff = now - IP_WINDOW_MS;
  state.sendTimestamps = state.sendTimestamps.filter((ts) => ts > cutoff);
  state.sendTimestamps.push(now);
}

export function mapTwilioError(err: any): {
  status: number;
  code: number | string | null;
  message: string;
  lockoutTriggered?: boolean;
  rateLimited?: boolean;
} {
  const rawCode = err?.code ?? err?.status ?? null;
  const code = typeof rawCode === 'string' && /^\d+$/.test(rawCode) ? Number(rawCode) : rawCode;

  switch (code) {
    case 21608:
      return {
        status: 400,
        code,
        message:
          'This phone number is not verified on your Twilio trial account. Verify it in the Twilio Console or switch SMS_PROVIDER to mock for testing.',
      };
    case 21211:
    case 21614:
    case 60200:
      return {
        status: 400,
        code,
        message: 'Invalid phone number. Please enter a valid E.164 mobile number.',
      };
    case 60201:
    case 20404:
      return {
        status: 400,
        code,
        message: 'Invalid or expired verification code. Please request a new SMS code.',
      };
    case 60202:
    case 60203:
      return {
        status: 429,
        code,
        lockoutTriggered: true,
        message:
          'Maximum verification check attempts reached. Please wait 15 minutes and request a new code.',
      };
    case 20429:
    case 60205:
      return {
        status: 429,
        code,
        rateLimited: true,
        message: 'Too many SMS requests sent to Twilio. Please wait before trying again.',
      };
    case 60628:
    case 20008:
    case 21606:
      return {
        status: 402,
        code,
        message:
          'Twilio trial account expired or free SMS units have been used up. Upgrade your Twilio account or switch to mock mode.',
      };
    default:
      return {
        status: 502,
        code,
        message: 'Unable to reach SMS verification service right now. Please try again shortly.',
      };
  }
}

export interface SendSmsOtpResult {
  success: boolean;
  status: number;
  message: string;
  mode: SmsProviderMode;
  demoMode: boolean;
  maskedPhone?: string;
  cooldownSeconds?: number;
  lockoutSeconds?: number;
  dailyRemaining?: number;
}

export async function sendSmsOtp(
  rawPhone: string,
  context: SmsRequestContext = {}
): Promise<SendSmsOtpResult> {
  const mode = getSmsProviderMode();
  const demoMode = mode === 'mock';
  const ipAddress = String(context.ipAddress || 'local').trim() || 'local';
  const userAgent = String(context.userAgent || 'unknown').trim() || 'unknown';
  const store = getProtectionStore(context.namespace || 'live');

  const phoneCheck = validateAndNormalizePhone(rawPhone);
  if (!phoneCheck.valid || !phoneCheck.e164 || !phoneCheck.masked) {
    logSecurityEvent({
      eventType: 'SMS_OTP_FAILED',
      severity: 'warning',
      result: 'failed',
      destination: rawPhone,
      ipAddress,
      userAgent,
      details: phoneCheck.message || 'Invalid phone number rejected before SMS send.',
    });
    return {
      success: false,
      status: 400,
      message: phoneCheck.message || 'Invalid phone number.',
      mode,
      demoMode,
    };
  }

  const normalizedPhone = phoneCheck.e164;
  const maskedPhone = phoneCheck.masked;
  const phoneKey = hashPhone(normalizedPhone);
  const now = Date.now();
  const phoneState = getPhoneAbuseState(store, phoneKey, now);

  // 1. Active lockout check (15 mins after 5 wrong attempts)
  if (phoneState.lockedUntil > now) {
    const lockoutSeconds = Math.ceil((phoneState.lockedUntil - now) / 1000);
    const lockoutMinutes = Math.ceil(lockoutSeconds / 60);
    const msg = `Too many wrong code attempts. Locked for ${lockoutMinutes} minute(s) (${lockoutSeconds}s remaining).`;
    logSecurityEvent({
      eventType: 'SMS_OTP_LOCKED',
      severity: 'critical',
      result: 'blocked',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Blocked SMS send to locked number ${maskedPhone} (${lockoutSeconds}s left).`,
    });
    return {
      success: false,
      status: 429,
      message: msg,
      mode,
      demoMode,
      maskedPhone,
      lockoutSeconds,
    };
  }

  // 2. 60-second resend cooldown per phone
  if (phoneState.lastSentAt > 0 && now - phoneState.lastSentAt < PHONE_COOLDOWN_MS) {
    const cooldownSeconds = Math.ceil((PHONE_COOLDOWN_MS - (now - phoneState.lastSentAt)) / 1000);
    const msg = `Please wait ${cooldownSeconds}s before requesting another SMS code.`;
    logSecurityEvent({
      eventType: 'SMS_RATE_LIMIT_HIT',
      severity: 'warning',
      result: 'blocked',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `60s SMS resend cooldown hit for ${maskedPhone} (${cooldownSeconds}s left).`,
    });
    return {
      success: false,
      status: 429,
      message: msg,
      mode,
      demoMode,
      maskedPhone,
      cooldownSeconds,
    };
  }

  // 3. Max 5 sends per phone per day
  if (phoneState.dailySendCount >= PHONE_DAILY_SEND_LIMIT) {
    const msg = `Daily SMS limit reached (${PHONE_DAILY_SEND_LIMIT} per phone per day). Please try again tomorrow.`;
    logSecurityEvent({
      eventType: 'SMS_RATE_LIMIT_HIT',
      severity: 'warning',
      result: 'blocked',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Daily SMS limit (${PHONE_DAILY_SEND_LIMIT}/day) reached for ${maskedPhone}.`,
    });
    return {
      success: false,
      status: 429,
      message: msg,
      mode,
      demoMode,
      maskedPhone,
      dailyRemaining: 0,
    };
  }

  // 4. Max 10 sends per IP per hour
  const ipCount = getIpSendCountLastHour(store, ipAddress, now);
  if (ipCount >= IP_HOURLY_SEND_LIMIT) {
    const msg = 'Hourly SMS send limit reached for your IP address. Please wait and try again later.';
    logSecurityEvent({
      eventType: 'SMS_RATE_LIMIT_HIT',
      severity: 'warning',
      result: 'blocked',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `IP hourly SMS rate limit (${IP_HOURLY_SEND_LIMIT}/hr) reached for ${maskedPhone}.`,
    });
    return {
      success: false,
      status: 429,
      message: msg,
      mode,
      demoMode,
      maskedPhone,
    };
  }

  // Mock provider path (impossible in production for live traffic; always isolated for simulator)
  if (mode === 'mock' || context.namespace === 'sim') {
    const allowlist = getMockAllowlist();
    const simAllowed = context.namespace === 'sim' && (normalizedPhone === SIM_BRUTE_FORCE_PHONE || normalizedPhone === SIM_FLOOD_PHONE);
    if (!simAllowed && !allowlist.includes(normalizedPhone)) {
      logSecurityEvent({
        eventType: 'SMS_OTP_FAILED',
        severity: 'warning',
        result: 'blocked',
        userId: maskedPhone,
        ipAddress,
        userAgent,
        details: `Demo mode rejected non-allowlisted phone ${maskedPhone}.`,
      });
      return {
        success: false,
        status: 403,
        message: `Demo mode only sends to numbers in MOCK_SMS_NUMBERS. Add ${normalizedPhone} to MOCK_SMS_NUMBERS or configure Twilio.`,
        mode,
        demoMode: true,
        maskedPhone,
      };
    }

    phoneState.lastSentAt = now;
    phoneState.dailySendCount += 1;
    recordIpSend(store, ipAddress, now);
    const dailyRemaining = Math.max(0, PHONE_DAILY_SEND_LIMIT - phoneState.dailySendCount);

    logSecurityEvent({
      eventType: 'SMS_MOCK_USED',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Demo Mode SMS OTP simulated for allowlisted number ${maskedPhone} (no Twilio call made).`,
    });
    logSecurityEvent({
      eventType: 'SMS_OTP_SENT',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `SMS OTP dispatched in Demo Mode to ${maskedPhone}.`,
    });

    return {
      success: true,
      status: 200,
      message: `Demo Mode: Verification SMS ready for ${maskedPhone}. Enter the demo code to verify.`,
      mode: 'mock',
      demoMode: true,
      maskedPhone,
      cooldownSeconds: 60,
      dailyRemaining,
    };
  }

  // Live Twilio Verify path
  const { accountSid, authToken, verifyServiceSid } = getTwilioCredentials();
  if (!accountSid || !authToken || !verifyServiceSid) {
    return {
      success: false,
      status: 503,
      message:
        'Twilio Verify is not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_VERIFY_SERVICE_SID.',
      mode: 'twilio',
      demoMode: false,
      maskedPhone,
    };
  }

  try {
    const client = twilio(accountSid, authToken);
    await client.verify.v2.services(verifyServiceSid).verifications.create({
      to: normalizedPhone,
      channel: 'sms',
    });

    phoneState.lastSentAt = now;
    phoneState.dailySendCount += 1;
    recordIpSend(store, ipAddress, now);
    const dailyRemaining = Math.max(0, PHONE_DAILY_SEND_LIMIT - phoneState.dailySendCount);

    logSecurityEvent({
      eventType: 'SMS_OTP_SENT',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Twilio Verify SMS OTP dispatched to ${maskedPhone}.`,
    });

    return {
      success: true,
      status: 200,
      message: `Verification code sent to ${maskedPhone} via Twilio Verify.`,
      mode: 'twilio',
      demoMode: false,
      maskedPhone,
      cooldownSeconds: 60,
      dailyRemaining,
    };
  } catch (err: any) {
    const mapped = mapTwilioError(err);
    // Log sanitized failure only (never log Twilio auth token or raw phone)
    logSecurityEvent({
      eventType: mapped.rateLimited ? 'SMS_RATE_LIMIT_HIT' : 'SMS_OTP_FAILED',
      severity: 'warning',
      result: mapped.rateLimited ? 'blocked' : 'failed',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Twilio Verify send error (${mapped.code || 'UNKNOWN'}) for ${maskedPhone}.`,
    });
    return {
      success: false,
      status: mapped.status,
      message: mapped.message,
      mode: 'twilio',
      demoMode: false,
      maskedPhone,
    };
  }
}

export interface CheckSmsOtpResult {
  success: boolean;
  approved: boolean;
  status: number;
  message: string;
  mode: SmsProviderMode;
  demoMode: boolean;
  normalizedPhone?: string;
  maskedPhone?: string;
  phoneHash?: string;
  locked?: boolean;
  lockoutSeconds?: number;
  attemptsRemaining?: number;
}

export async function checkSmsOtp(
  rawPhone: string,
  rawCode: string,
  context: SmsRequestContext = {}
): Promise<CheckSmsOtpResult> {
  const mode = getSmsProviderMode();
  const demoMode = mode === 'mock';
  const ipAddress = String(context.ipAddress || 'local').trim() || 'local';
  const userAgent = String(context.userAgent || 'unknown').trim() || 'unknown';
  const store = getProtectionStore(context.namespace || 'live');

  const phoneCheck = validateAndNormalizePhone(rawPhone);
  if (!phoneCheck.valid || !phoneCheck.e164 || !phoneCheck.masked) {
    return {
      success: false,
      approved: false,
      status: 400,
      message: phoneCheck.message || 'Invalid phone number.',
      mode,
      demoMode,
    };
  }

  const normalizedPhone = phoneCheck.e164;
  const maskedPhone = phoneCheck.masked;
  const phoneKey = hashPhone(normalizedPhone);
  const now = Date.now();
  const phoneState = getPhoneAbuseState(store, phoneKey, now);

  // Enforce 15-minute lockout
  if (phoneState.lockedUntil > now) {
    const lockoutSeconds = Math.ceil((phoneState.lockedUntil - now) / 1000);
    const lockoutMinutes = Math.ceil(lockoutSeconds / 60);
    logSecurityEvent({
      eventType: 'SMS_OTP_LOCKED',
      severity: 'critical',
      result: 'blocked',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Blocked SMS verification for locked phone ${maskedPhone} (${lockoutSeconds}s left).`,
    });
    return {
      success: false,
      approved: false,
      status: 429,
      message: `Too many wrong attempts. Phone verification locked for ${lockoutMinutes} minute(s) (${lockoutSeconds}s remaining).`,
      mode,
      demoMode,
      maskedPhone,
      locked: true,
      lockoutSeconds,
      attemptsRemaining: 0,
    };
  }

  const cleanCode = String(rawCode || '').trim();
  if (!/^\d{6}$/.test(cleanCode)) {
    return {
      success: false,
      approved: false,
      status: 400,
      message: 'Please enter the exact 6-digit verification code.',
      mode,
      demoMode,
      maskedPhone,
    };
  }

  const recordFailureAndCheckLock = (customMsg?: string): CheckSmsOtpResult => {
    phoneState.wrongAttempts += 1;
    const remaining = Math.max(0, MAX_WRONG_ATTEMPTS - phoneState.wrongAttempts);
    if (phoneState.wrongAttempts >= MAX_WRONG_ATTEMPTS) {
      phoneState.lockedUntil = now + PHONE_LOCKOUT_MS;
      const lockoutSeconds = Math.floor(PHONE_LOCKOUT_MS / 1000);
      logSecurityEvent({
        eventType: 'SMS_OTP_LOCKED',
        severity: 'critical',
        result: 'blocked',
        userId: maskedPhone,
        ipAddress,
        userAgent,
        details: `SMS OTP locked for 15 minutes after ${MAX_WRONG_ATTEMPTS} failed attempts on ${maskedPhone}.`,
      });
      return {
        success: false,
        approved: false,
        status: 429,
        message: 'Too many wrong attempts (5/5). Phone verification locked for 15 minutes.',
        mode,
        demoMode,
        maskedPhone,
        locked: true,
        lockoutSeconds,
        attemptsRemaining: 0,
      };
    }

    logSecurityEvent({
      eventType: 'SMS_OTP_FAILED',
      severity: 'warning',
      result: 'failed',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Incorrect SMS OTP attempt (${phoneState.wrongAttempts}/${MAX_WRONG_ATTEMPTS}) for ${maskedPhone}.`,
    });

    return {
      success: false,
      approved: false,
      status: 400,
      message: customMsg || `Invalid verification code. ${remaining} attempt(s) remaining before lockout.`,
      mode,
      demoMode,
      maskedPhone,
      attemptsRemaining: remaining,
    };
  };

  // Mock verification path (impossible in production for live traffic; always isolated for simulator)
  if (mode === 'mock' || context.namespace === 'sim') {
    const allowlist = getMockAllowlist();
    const simAllowed = context.namespace === 'sim' && (normalizedPhone === SIM_BRUTE_FORCE_PHONE || normalizedPhone === SIM_FLOOD_PHONE);
    if (!simAllowed && !allowlist.includes(normalizedPhone)) {
      logSecurityEvent({
        eventType: 'SMS_OTP_FAILED',
        severity: 'warning',
        result: 'blocked',
        userId: maskedPhone,
        ipAddress,
        userAgent,
        details: `Demo mode verify rejected non-allowlisted phone ${maskedPhone}.`,
      });
      return {
        success: false,
        approved: false,
        status: 403,
        message: 'This phone number is not allowlisted for Demo Mode verification.',
        mode: 'mock',
        demoMode: true,
        maskedPhone,
      };
    }

    const expectedBuf = Buffer.from(MOCK_DEMO_CODE, 'utf8');
    const providedBuf = Buffer.from(cleanCode, 'utf8');
    const isMatch =
      expectedBuf.length === providedBuf.length &&
      crypto.timingSafeEqual(expectedBuf, providedBuf);

    if (!isMatch) {
      return recordFailureAndCheckLock();
    }

    phoneState.wrongAttempts = 0;
    phoneState.lockedUntil = 0;

    logSecurityEvent({
      eventType: 'SMS_MOCK_USED',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Demo Mode SMS code verified for allowlisted number ${maskedPhone}.`,
    });
    logSecurityEvent({
      eventType: 'SMS_OTP_VERIFIED',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `SMS OTP verified in Demo Mode for ${maskedPhone}.`,
    });

    return {
      success: true,
      approved: true,
      status: 200,
      message: 'Demo Mode SMS code verified.',
      mode: 'mock',
      demoMode: true,
      normalizedPhone,
      maskedPhone,
      phoneHash: phoneKey,
    };
  }

  // Live Twilio Verify check path
  const { accountSid, authToken, verifyServiceSid } = getTwilioCredentials();
  if (!accountSid || !authToken || !verifyServiceSid) {
    return {
      success: false,
      approved: false,
      status: 503,
      message: 'Twilio Verify is not configured on the server.',
      mode: 'twilio',
      demoMode: false,
      maskedPhone,
    };
  }

  try {
    const client = twilio(accountSid, authToken);
    const check = await client.verify.v2
      .services(verifyServiceSid)
      .verificationChecks.create({
        to: normalizedPhone,
        code: cleanCode,
      });

    if (check.status !== 'approved') {
      return recordFailureAndCheckLock();
    }

    phoneState.wrongAttempts = 0;
    phoneState.lockedUntil = 0;

    logSecurityEvent({
      eventType: 'SMS_OTP_VERIFIED',
      severity: 'info',
      result: 'success',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Twilio Verify SMS OTP approved for ${maskedPhone}.`,
    });

    return {
      success: true,
      approved: true,
      status: 200,
      message: 'SMS verification approved.',
      mode: 'twilio',
      demoMode: false,
      normalizedPhone,
      maskedPhone,
      phoneHash: phoneKey,
    };
  } catch (err: any) {
    const mapped = mapTwilioError(err);
    if (mapped.lockoutTriggered) {
      phoneState.lockedUntil = now + PHONE_LOCKOUT_MS;
      const lockoutSeconds = Math.floor(PHONE_LOCKOUT_MS / 1000);
      logSecurityEvent({
        eventType: 'SMS_OTP_LOCKED',
        severity: 'critical',
        result: 'blocked',
        userId: maskedPhone,
        ipAddress,
        userAgent,
        details: `Twilio Verify max check attempts reached (${mapped.code}) for ${maskedPhone}.`,
      });
      return {
        success: false,
        approved: false,
        status: 429,
        message: mapped.message,
        mode: 'twilio',
        demoMode: false,
        maskedPhone,
        locked: true,
        lockoutSeconds,
      };
    }

    logSecurityEvent({
      eventType: mapped.rateLimited ? 'SMS_RATE_LIMIT_HIT' : 'SMS_OTP_FAILED',
      severity: 'warning',
      result: mapped.rateLimited ? 'blocked' : 'failed',
      userId: maskedPhone,
      ipAddress,
      userAgent,
      details: `Twilio Verify check error (${mapped.code || 'UNKNOWN'}) for ${maskedPhone}.`,
    });

    return {
      success: false,
      approved: false,
      status: mapped.status,
      message: mapped.message,
      mode: 'twilio',
      demoMode: false,
      maskedPhone,
    };
  }
}

export async function linkVerifiedPhoneToUser(params: {
  normalizedPhone: string;
  userId: string;
  email?: string;
  displayName?: string;
  role?: string;
}): Promise<VerifiedPhoneLinkRecord> {
  const phoneHash = hashPhone(params.normalizedPhone);
  const maskedPhone = maskPhone(params.normalizedPhone);
  const store = getPhoneLinkStore();

  const record: VerifiedPhoneLinkRecord = {
    phoneHash,
    maskedPhone,
    phoneVerified: true,
    userId: String(params.userId),
    ...(params.email ? { email: String(params.email).toLowerCase() } : {}),
    ...(params.displayName ? { displayName: String(params.displayName) } : {}),
    role: String(params.role || 'ADMIN').toUpperCase(),
    linkedAt: new Date().toISOString(),
  };

  store.set(phoneHash, record);
  persistPhoneLinkStore(store);

  // Sync in-memory user map
  for (const [k, u] of inMemoryUsers.entries()) {
    if (String((u as any)._id) === record.userId || (record.email && u.email?.toLowerCase() === record.email)) {
      (u as any).phoneVerified = true;
      (u as any).maskedPhone = maskedPhone;
      (u as any).phoneHash = phoneHash;
      inMemoryUsers.set(k, u);
    }
  }

  // Best-effort sync to MongoDB if connected
  try {
    const conn = await connectToDatabase();
    if (conn && record.userId) {
      await User.findByIdAndUpdate(record.userId, {
        $set: { phoneNumber: maskedPhone },
      }).catch(() => {});
    }
  } catch {
    // Non-fatal in sandbox mode
  }

  return record;
}

export async function findUserByVerifiedPhone(
  normalizedPhone: string
): Promise<VerifiedPhoneLinkRecord | null> {
  const phoneHash = hashPhone(normalizedPhone);
  const maskedPhone = maskPhone(normalizedPhone);
  const store = getPhoneLinkStore();

  const linked = store.get(phoneHash);
  if (linked && linked.phoneVerified) {
    return linked;
  }

  // Fallback check against inMemoryUsers
  for (const u of inMemoryUsers.values()) {
    const storedHash = (u as any).phoneHash;
    const rawUserPhone = u.phoneNumber ? normalizeRawToE164(u.phoneNumber) : null;
    if (storedHash === phoneHash || (rawUserPhone && hashPhone(rawUserPhone) === phoneHash)) {
      return {
        phoneHash,
        maskedPhone,
        phoneVerified: true,
        userId: String((u as any)._id),
        email: u.email,
        role: String(u.role || 'ADMIN').toUpperCase(),
        linkedAt: new Date().toISOString(),
      };
    }
  }

  // Fallback check against MongoDB if connected
  try {
    const conn = await connectToDatabase();
    if (conn) {
      const dbUser = await User.findOne({ phoneNumber: normalizedPhone }).lean();
      if (dbUser) {
        return {
          phoneHash,
          maskedPhone,
          phoneVerified: true,
          userId: String((dbUser as any)._id),
          email: dbUser.email,
          role: String(dbUser.role || 'ADMIN').toUpperCase(),
          linkedAt: new Date().toISOString(),
        };
      }
    }
  } catch {
    // Ignore DB errors
  }

  return null;
}

export async function runSmsBruteForceSimulation(context: {
  ipAddress?: string;
  userAgent?: string;
}) {
  const simStore = getProtectionStore('sim');
  const simPhoneHash = hashPhone(SIM_BRUTE_FORCE_PHONE);
  simStore.phones.delete(simPhoneHash);

  const ipAddress = context.ipAddress || '198.51.100.91';
  const userAgent = context.userAgent || 'Aegis-Attack-Simulator/1.0';
  const simCtx: SmsRequestContext = { ipAddress, userAgent, namespace: 'sim' };

  const attemptResults: Array<{ attempt: number; status: number; locked: boolean; message: string }> = [];

  for (let i = 1; i <= 6; i++) {
    const wrongCode = String(900000 + i);
    const res = await checkSmsOtp(SIM_BRUTE_FORCE_PHONE, wrongCode, simCtx);
    attemptResults.push({
      attempt: i,
      status: res.status,
      locked: Boolean(res.locked),
      message: res.message,
    });
  }

  const finalAttempt = attemptResults[attemptResults.length - 1];
  return {
    simulation: 'SMS_BRUTE_FORCE',
    targetMasked: maskPhone(SIM_BRUTE_FORCE_PHONE),
    totalAttempts: attemptResults.length,
    lockedTriggered: Boolean(finalAttempt?.locked && finalAttempt?.status === 429),
    finalStatus: finalAttempt?.status,
    attempts: attemptResults,
  };
}

export async function runSmsSendFloodSimulation(context: {
  ipAddress?: string;
  userAgent?: string;
}) {
  const simStore = getProtectionStore('sim');
  const simPhoneHash = hashPhone(SIM_FLOOD_PHONE);
  simStore.phones.delete(simPhoneHash);

  const ipAddress = context.ipAddress || '198.51.100.92';
  const userAgent = context.userAgent || 'Aegis-Attack-Simulator/1.0';
  const simCtx: SmsRequestContext = { ipAddress, userAgent, namespace: 'sim' };

  const first = await sendSmsOtp(SIM_FLOOD_PHONE, simCtx);
  const second = await sendSmsOtp(SIM_FLOOD_PHONE, simCtx);
  const third = await sendSmsOtp(SIM_FLOOD_PHONE, simCtx);

  return {
    simulation: 'SMS_SEND_FLOOD',
    targetMasked: maskPhone(SIM_FLOOD_PHONE),
    firstSendStatus: first.status,
    floodBlocked: second.status === 429 && third.status === 429,
    cooldownSeconds: second.cooldownSeconds || 60,
    attempts: [
      { request: 1, status: first.status, success: first.success, message: first.message },
      { request: 2, status: second.status, success: second.success, message: second.message },
      { request: 3, status: third.status, success: third.success, message: third.message },
    ],
  };
}
