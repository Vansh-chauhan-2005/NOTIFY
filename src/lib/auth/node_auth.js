/**
 * node_auth.js — Hardened Node.js Cryptographic OTP, Lockout, Rate-Limit, Audit Log & Auth Engine
 *
 * Security controls:
 * 1. 6-digit OTP generated exclusively via `crypto.randomInt` (never `Math.random`).
 * 2. Stored strictly as a salted SHA-256 hash (`crypto.randomBytes(16)` + SHA-256), never plain text.
 * 3. Expires in 5 minutes (`OTP_TTL_MS`) and enforced as single-use (`used` flag + immediate deletion).
 * 4. Maximum 5 wrong attempts (`MAX_OTP_ATTEMPTS`), then locks the destination for 15 minutes (`OTP_LOCKOUT_MS`).
 * 5. 60-second resend cooldown (`OTP_COOLDOWN_MS`) and daily limit per email/destination (`MAX_DAILY_OTPS_PER_EMAIL`).
 * 6. Constant-time digest verification using `crypto.timingSafeEqual`.
 * 7. Tamper-evident append-only audit log (`otp-audit.log` + in-memory cache) for every OTP request and verification.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import {
  sendFast2Sms,
  isFast2SmsConfigured,
  setFast2SmsTargetPhone,
} from '../integrations/fast2smsService.js';
import {
  sendEmailNotification,
  isLiveSmtpConfigured,
} from '../integrations/emailService.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';
import { getJwtSecret } from './jwtSecret.js';

export const OTP_LENGTH = 6;
export const OTP_TTL_MS = 5 * 60 * 1000; // 5 minutes
export const OTP_COOLDOWN_MS = 60 * 1000; // 60 seconds
export const OTP_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes after 5 wrong attempts
export const MAX_OTP_ATTEMPTS = 5;
export const MAX_DAILY_OTPS_PER_EMAIL = Math.max(
  1,
  parseInt(process.env.OTP_DAILY_LIMIT || '10', 10) || 10
);

const AUDIT_LOG_PATH = path.resolve(process.cwd(), 'otp-audit.log');
const MAX_IN_MEMORY_AUDIT_LOGS = 1000;

const GOOGLE_SECURETOKEN_CERTS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/** @type {{ certs: Record<string, string>, expiresAt: number } | null} */
let cachedGoogleCerts = null;

/**
 * @typedef {Object} OtpChallengeRecord
 * @property {string} salt
 * @property {Buffer} codeHash
 * @property {number} expiresAt
 * @property {number} attempts
 * @property {boolean} used
 * @property {number} createdAt
 * @property {'FAST2SMS' | 'EMAIL'} channel
 * @property {string} purpose
 */

/**
 * @typedef {Object} OtpSecurityState
 * @property {number} lastRequestedAt
 * @property {string} dailyDateKey
 * @property {number} dailyCount
 * @property {number} lockedUntil
 */

/**
 * @typedef {Object} OtpAuditEntry
 * @property {string} id
 * @property {string} timestamp
 * @property {'OTP_REQUEST' | 'OTP_VERIFY'} eventType
 * @property {string} action
 * @property {'SUCCESS' | 'FAILURE' | 'BLOCKED'} outcome
 * @property {string} destination
 * @property {string} destinationHash
 * @property {string} channel
 * @property {string} purpose
 * @property {string} reason
 * @property {string} ip
 * @property {string} userAgent
 * @property {string} integrityHash
 */

/** @type {Map<string, OtpChallengeRecord>} */
const otpChallengeStore = new Map();

/** @type {Map<string, OtpSecurityState>} */
const otpSecurityStateStore = new Map();

/** @type {Map<string, number>} */
const consumedTwoFactorChallengeIds = new Map();

/** @type {OtpAuditEntry[]} */
const otpAuditLogMemory = [];
let lastAuditIntegrityHash = 'GENESIS';

// Hydrate recent audit log entries from disk if present
(function hydrateAuditLogsFromDisk() {
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) return;
    const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
    const lines = raw.split('\n').filter((line) => line.trim().length > 0);
    const recent = lines.slice(-MAX_IN_MEMORY_AUDIT_LOGS);
    for (const line of recent) {
      try {
        const parsed = /** @type {any} */ (JSON.parse(line));
        if (parsed?.recordKind === 'SECURITY_TELEMETRY') continue;
        otpAuditLogMemory.push(parsed);
        if (parsed.integrityHash) {
          lastAuditIntegrityHash = parsed.integrityHash;
        }
      } catch {
        // Ignore malformed historical line
      }
    }
  } catch {
    // Non-fatal if audit file is unavailable
  }
})();

/**
 * Hash a destination identifier for privacy-safe correlation in audit logs.
 * @param {string} value
 * @returns {string}
 */
function hashDestination(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex').slice(0, 16);
}

/**
 * Append a structured, tamper-evident entry to the OTP audit log (memory + otp-audit.log).
 * Never stores plain-text OTP codes, salts, or code hashes.
 *
 * @param {{
 *   eventType: 'OTP_REQUEST' | 'OTP_VERIFY',
 *   action: string,
 *   outcome: 'SUCCESS' | 'FAILURE' | 'BLOCKED',
 *   destination: string,
 *   channel: string,
 *   purpose: string,
 *   reason: string,
 *   auditContext?: { ip?: string, userAgent?: string }
 * }} entry
 * @returns {OtpAuditEntry}
 */
export function recordOtpAuditEvent(entry) {
  const timestamp = new Date().toISOString();
  const id = crypto.randomUUID();
  const ip = String(entry.auditContext?.ip || 'unknown').slice(0, 100);
  const userAgent = String(entry.auditContext?.userAgent || 'unknown').slice(0, 200);
  const cleanDest = String(entry.destination || 'unknown').trim();

  const body = {
    id,
    timestamp,
    eventType: entry.eventType,
    action: entry.action,
    outcome: entry.outcome,
    destination: cleanDest,
    destinationHash: hashDestination(cleanDest),
    channel: entry.channel || 'UNKNOWN',
    purpose: entry.purpose || 'LOGIN_OTP',
    reason: entry.reason,
    ip,
    userAgent,
  };

  const integrityHash = crypto
    .createHash('sha256')
    .update(`${lastAuditIntegrityHash}:${JSON.stringify(body)}`)
    .digest('hex');

  lastAuditIntegrityHash = integrityHash;
  const fullEntry = { ...body, integrityHash };

  otpAuditLogMemory.push(fullEntry);
  if (otpAuditLogMemory.length > MAX_IN_MEMORY_AUDIT_LOGS) {
    otpAuditLogMemory.shift();
  }

  try {
    fs.appendFileSync(AUDIT_LOG_PATH, `${JSON.stringify(fullEntry)}\n`, 'utf8');
  } catch {
    // Keep memory audit log operational even if filesystem is read-only
  }

  // Forward OTP & rate-limit audit actions to central security telemetry logger
  try {
    const act = String(entry.action || '');
    if (act === 'OTP_SENT') {
      logSecurityEvent({
        eventType: 'OTP_SENT',
        severity: 'info',
        result: 'success',
        destination: cleanDest,
        ipAddress: ip,
        userAgent,
        details: `OTP dispatched via ${entry.channel || 'UNKNOWN'} (${entry.purpose || 'LOGIN_OTP'}).`,
      });
    } else if (act === 'OTP_VERIFY_SUCCESS' || act === 'FIREBASE_VERIFY_SUCCESS') {
      logSecurityEvent({
        eventType: 'OTP_VERIFIED',
        severity: 'info',
        result: 'success',
        destination: cleanDest,
        ipAddress: ip,
        userAgent,
        details: `OTP verification succeeded via ${entry.channel || 'UNKNOWN'}.`,
      });
    } else if (
      act === 'OTP_LOCKED_MAX_ATTEMPTS' ||
      act === 'OTP_REQUEST_BLOCKED_LOCKED' ||
      act === 'OTP_VERIFY_BLOCKED_LOCKED'
    ) {
      logSecurityEvent({
        eventType: 'OTP_LOCKED',
        severity: 'critical',
        result: 'blocked',
        destination: cleanDest,
        ipAddress: ip,
        userAgent,
        details: entry.reason || 'Destination locked after maximum failed OTP attempts.',
      });
    } else if (
      act === 'OTP_REQUEST_BLOCKED_COOLDOWN' ||
      act === 'OTP_REQUEST_BLOCKED_DAILY_LIMIT'
    ) {
      logSecurityEvent({
        eventType: 'RATE_LIMIT_HIT',
        severity: 'warning',
        result: 'blocked',
        destination: cleanDest,
        ipAddress: ip,
        userAgent,
        details: entry.reason || 'OTP rate limit or cooldown triggered.',
      });
    } else if (act !== 'FIREBASE_GOOGLE_SIGNIN' && act !== 'FIREBASE_GOOGLE_SIGNIN_FAILED') {
      logSecurityEvent({
        eventType: 'OTP_FAILED',
        severity: 'warning',
        result: entry.outcome === 'BLOCKED' ? 'blocked' : 'failed',
        destination: cleanDest,
        ipAddress: ip,
        userAgent,
        details: entry.reason || `OTP check failed (${act}).`,
      });
    }
  } catch {
    // Telemetry logging must never interrupt OTP auth flow
  }

  return fullEntry;
}

/**
 * Retrieve recent OTP audit log entries (most recent first).
 * @param {{ limit?: number, destination?: string, eventType?: string }} [filters]
 * @returns {OtpAuditEntry[]}
 */
export function getOtpAuditLogs(filters = {}) {
  const limit = Math.min(200, Math.max(1, Number(filters.limit) || 50));
  const destFilter = filters.destination ? String(filters.destination).trim().toLowerCase() : '';
  const typeFilter = filters.eventType ? String(filters.eventType).trim().toUpperCase() : '';

  let items = [...otpAuditLogMemory];
  if (destFilter) {
    items = items.filter((item) => item.destination.toLowerCase() === destFilter);
  }
  if (typeFilter) {
    items = items.filter((item) => item.eventType === typeFilter);
  }

  return items.reverse().slice(0, limit);
}

/**
 * Return the active OTP hardening policy constants for diagnostics/UI.
 */
export function getOtpSecurityPolicy() {
  return {
    otpDigits: OTP_LENGTH,
    generator: 'crypto.randomInt',
    hashAlgorithm: 'SHA-256 + 16-byte random salt',
    comparison: 'crypto.timingSafeEqual',
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    singleUse: true,
    maxWrongAttempts: MAX_OTP_ATTEMPTS,
    lockoutSeconds: Math.floor(OTP_LOCKOUT_MS / 1000),
    resendCooldownSeconds: Math.floor(OTP_COOLDOWN_MS / 1000),
    dailyLimitPerEmail: MAX_DAILY_OTPS_PER_EMAIL,
    auditLogging: true,
  };
}

/**
 * Get UTC YYYY-MM-DD key for enforcing daily OTP limits.
 * @param {number} now
 * @returns {string}
 */
function getUtcDateKey(now) {
  return new Date(now).toISOString().slice(0, 10);
}

/**
 * Fetch or initialize per-destination security state (lockout, cooldown, daily count).
 * Automatically rolls over daily counters on a new UTC day and clears expired lockouts.
 * @param {string} identityKey
 * @param {number} now
 * @returns {OtpSecurityState}
 */
function getSecurityState(identityKey, now) {
  const todayKey = getUtcDateKey(now);
  let state = otpSecurityStateStore.get(identityKey);

  if (!state) {
    state = {
      lastRequestedAt: 0,
      dailyDateKey: todayKey,
      dailyCount: 0,
      lockedUntil: 0,
    };
    otpSecurityStateStore.set(identityKey, state);
    return state;
  }

  if (state.dailyDateKey !== todayKey) {
    state.dailyDateKey = todayKey;
    state.dailyCount = 0;
  }

  if (state.lockedUntil > 0 && now >= state.lockedUntil) {
    state.lockedUntil = 0;
  }

  return state;
}

/**
 * Load Firebase projectId from firebase-applet-config.json.
 * @returns {string}
 */
export function getFirebaseProjectId() {
  try {
    const configPath = path.resolve(process.cwd(), 'firebase-applet-config.json');
    const raw = fs.readFileSync(configPath, 'utf8');
    const parsed = JSON.parse(raw);
    return String(parsed.projectId || '').trim();
  } catch {
    return (process.env.FIREBASE_PROJECT_ID || '').trim();
  }
}

/**
 * Fetch and cache Google's official Firebase Auth public X.509 certificates.
 * @returns {Promise<Record<string, string>>}
 */
async function getGoogleSecureTokenCerts() {
  const now = Date.now();
  if (cachedGoogleCerts && now < cachedGoogleCerts.expiresAt) {
    return cachedGoogleCerts.certs;
  }

  const response = await fetch(GOOGLE_SECURETOKEN_CERTS_URL);
  if (!response.ok) {
    throw new Error(`Failed to fetch Firebase public certificates (HTTP ${response.status}).`);
  }

  const certs = /** @type {Record<string, string>} */ (await response.json());
  const cacheControl = response.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const maxAgeSeconds = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 3600;

  cachedGoogleCerts = {
    certs,
    expiresAt: now + maxAgeSeconds * 1000,
  };

  return certs;
}

/**
 * Cryptographically verify a Firebase Phone Auth ID token on the Node.js backend.
 * Validates RS256 signature, issuer, audience (`projectId`), expiry, and verified phone number.
 *
 * @param {string} firebaseIdToken
 * @param {{ ip?: string, userAgent?: string }} [auditContext]
 * @returns {Promise<{ valid: boolean, uid?: string, phoneNumber?: string, error?: string }>}
 */
export async function verifyFirebasePhoneIdToken(firebaseIdToken, auditContext) {
  try {
    const projectId = getFirebaseProjectId();
    if (!projectId) {
      recordOtpAuditEvent({
        eventType: 'OTP_VERIFY',
        action: 'FIREBASE_VERIFY_FAILED',
        outcome: 'FAILURE',
        destination: 'firebase_phone',
        channel: 'FIREBASE_PHONE',
        purpose: 'LOGIN_OTP',
        reason: 'Firebase projectId is not configured on the server.',
        auditContext,
      });
      return { valid: false, error: 'Firebase projectId is not configured on the server.' };
    }

    const decodedHeader = jwt.decode(firebaseIdToken, { complete: true });
    if (!decodedHeader || typeof decodedHeader === 'string' || !decodedHeader.header?.kid) {
      recordOtpAuditEvent({
        eventType: 'OTP_VERIFY',
        action: 'FIREBASE_VERIFY_FAILED',
        outcome: 'FAILURE',
        destination: 'firebase_phone',
        channel: 'FIREBASE_PHONE',
        purpose: 'LOGIN_OTP',
        reason: 'Malformed Firebase ID token header.',
        auditContext,
      });
      return { valid: false, error: 'Malformed Firebase ID token header.' };
    }

    const certs = await getGoogleSecureTokenCerts();
    let certPem = certs[decodedHeader.header.kid];

    if (!certPem) {
      cachedGoogleCerts = null;
      const refreshedCerts = await getGoogleSecureTokenCerts();
      certPem = refreshedCerts[decodedHeader.header.kid];
    }

    if (!certPem) {
      recordOtpAuditEvent({
        eventType: 'OTP_VERIFY',
        action: 'FIREBASE_VERIFY_FAILED',
        outcome: 'FAILURE',
        destination: 'firebase_phone',
        channel: 'FIREBASE_PHONE',
        purpose: 'LOGIN_OTP',
        reason: 'Unable to find matching Firebase signing certificate.',
        auditContext,
      });
      return { valid: false, error: 'Unable to find matching Firebase signing certificate.' };
    }

    const payload = /** @type {any} */ (
      jwt.verify(firebaseIdToken, certPem, {
        algorithms: ['RS256'],
        audience: projectId,
        issuer: `https://securetoken.google.com/${projectId}`,
      })
    );

    if (!payload?.sub || typeof payload.sub !== 'string') {
      return { valid: false, error: 'Firebase token is missing user subject (uid).' };
    }

    const verifiedPhone =
      payload.phone_number ||
      payload.firebase?.identities?.phone?.[0];

    if (!verifiedPhone || typeof verifiedPhone !== 'string') {
      return {
        valid: false,
        error: 'Firebase ID token does not contain a verified phone number.',
      };
    }

    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'FIREBASE_VERIFY_SUCCESS',
      outcome: 'SUCCESS',
      destination: verifiedPhone,
      channel: 'FIREBASE_PHONE',
      purpose: 'LOGIN_OTP',
      reason: 'Firebase Phone ID token verified via RS256.',
      auditContext,
    });

    return {
      valid: true,
      uid: payload.sub,
      phoneNumber: verifiedPhone,
    };
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'FIREBASE_VERIFY_FAILED',
      outcome: 'FAILURE',
      destination: 'firebase_phone',
      channel: 'FIREBASE_PHONE',
      purpose: 'LOGIN_OTP',
      reason: `Firebase token verification failed: ${errMsg}`,
      auditContext,
    });
    return {
      valid: false,
      error: `Firebase token verification failed: ${errMsg}`,
    };
  }
}

/**
 * Normalize an email address or mobile number into a canonical lookup key.
 * @param {string} destination
 * @returns {{ isEmail: boolean, identityKey: string }}
 */
export function normalizeDestination(destination) {
  const clean = String(destination || '').trim();
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(clean);
  const identityKey = isEmail
    ? clean.toLowerCase()
    : clean.replace(/[\s\-\(\)]/g, '');
  return { isEmail, identityKey };
}

/**
 * Generate a cryptographically secure 6-digit numeric OTP using `crypto.randomInt`.
 * Pads with leading zeros (`000000`–`999999`) for full 1,000,000-code entropy.
 * Never uses `Math.random`.
 *
 * @param {number} [length=6]
 * @returns {string}
 */
export function generateOtp(length = OTP_LENGTH) {
  const upperBound = Math.pow(10, length);
  return crypto.randomInt(0, upperBound).toString().padStart(length, '0');
}

/**
 * Compute salted SHA-256 digest for an OTP code.
 * @param {string} code
 * @param {string} salt
 * @returns {Buffer}
 */
function hashOtpCode(code, salt) {
  return crypto.createHash('sha256').update(`${salt}:${code}`).digest();
}

/**
 * Generate a 6-digit cryptographic OTP, store its salted SHA-256 hash, enforce
 * 15-minute lockouts, 60-second resend cooldowns, and daily per-email quotas,
 * deliver via live Nodemailer SMTP / Fast2SMS, and record an audit log entry.
 *
 * @param {string} targetDestination
 * @param {Object} [options]
 * @param {'LOGIN_OTP' | 'LOGIN_2FA'} [options.purpose='LOGIN_OTP']
 * @param {{ ip?: string, userAgent?: string }} [options.auditContext]
 * @returns {Promise<Record<string, any>>}
 */
export async function generateAndSendOtp(targetDestination, options = {}) {
  const { purpose = 'LOGIN_OTP', auditContext } = options;
  const { isEmail, identityKey } = normalizeDestination(targetDestination);
  const channel = isEmail ? 'EMAIL' : 'FAST2SMS';

  if (!identityKey) {
    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_REQUEST_INVALID',
      outcome: 'FAILURE',
      destination: String(targetDestination || ''),
      channel,
      purpose,
      reason: 'Empty or invalid destination.',
      auditContext,
    });
    return {
      success: false,
      error: 'Please provide a valid mobile number or email address.',
    };
  }

  if (!isEmail) {
    const digits = identityKey.replace(/\D/g, '');
    if (digits.length < 8) {
      recordOtpAuditEvent({
        eventType: 'OTP_REQUEST',
        action: 'OTP_REQUEST_INVALID',
        outcome: 'FAILURE',
        destination: identityKey,
        channel,
        purpose,
        reason: 'Invalid phone format (< 8 digits).',
        auditContext,
      });
      return {
        success: false,
        error: 'Invalid phone format. Please enter a valid mobile number.',
      };
    }
  }

  const now = Date.now();
  const state = getSecurityState(identityKey, now);

  // 1. Check active 15-minute lockout after 5 wrong attempts
  if (state.lockedUntil > now) {
    const lockoutSeconds = Math.ceil((state.lockedUntil - now) / 1000);
    const lockoutMinutes = Math.ceil(lockoutSeconds / 60);
    const reason = `Too many wrong OTP attempts. Locked for ${lockoutMinutes} minute(s) (${lockoutSeconds}s remaining).`;
    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_REQUEST_BLOCKED_LOCKED',
      outcome: 'BLOCKED',
      destination: identityKey,
      channel,
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      locked: true,
      lockoutSeconds,
      error: reason,
    };
  }

  // 2. Enforce 60-second resend cooldown
  if (state.lastRequestedAt > 0 && now - state.lastRequestedAt < OTP_COOLDOWN_MS) {
    const cooldownSeconds = Math.ceil((OTP_COOLDOWN_MS - (now - state.lastRequestedAt)) / 1000);
    const reason = `Resend cooldown active. Please wait ${cooldownSeconds}s before requesting a new code.`;
    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_REQUEST_BLOCKED_COOLDOWN',
      outcome: 'BLOCKED',
      destination: identityKey,
      channel,
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      cooldownSeconds,
      error: reason,
    };
  }

  // 3. Enforce daily limit per email/destination
  if (state.dailyCount >= MAX_DAILY_OTPS_PER_EMAIL) {
    const reason = `Daily OTP limit reached (${MAX_DAILY_OTPS_PER_EMAIL} per day for ${identityKey}). Please try again tomorrow.`;
    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_REQUEST_BLOCKED_DAILY_LIMIT',
      outcome: 'BLOCKED',
      destination: identityKey,
      channel,
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      dailyLimitReached: true,
      dailyLimit: MAX_DAILY_OTPS_PER_EMAIL,
      dailyRemaining: 0,
      error: reason,
    };
  }

  // 4. Generate 6-digit OTP via crypto.randomInt and store salted SHA-256 hash only
  const code = generateOtp(OTP_LENGTH);
  const salt = crypto.randomBytes(16).toString('hex');
  const codeHash = hashOtpCode(code, salt);
  const expiresAt = now + OTP_TTL_MS;

  otpChallengeStore.set(identityKey, {
    salt,
    codeHash,
    expiresAt,
    attempts: 0,
    used: false,
    createdAt: now,
    channel,
    purpose,
  });

  if (isEmail) {
    const isTwoFactor = purpose === 'LOGIN_2FA';
    const subject = isTwoFactor
      ? `[Aegis Security] Two-Factor Login Code: ${code}`
      : `[Aegis Security] Verification Code: ${code}`;

    const emailResult = await sendEmailNotification({
      to: identityKey,
      subject,
      requireLiveTransport: true,
      text: `Your Aegis Sentinel ${isTwoFactor ? '2FA login' : 'verification'} code is: ${code}. Valid for 5 minutes. Do not share this code.`,
      html: `
        <div style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; max-width: 480px;">
          <h2 style="color: #6366f1; margin-top: 0;">Aegis Sentinel ${isTwoFactor ? 'Two-Factor Login' : 'Verification'}</h2>
          <p style="color: #94a3b8; font-size: 14px;">Your one-time authentication code is:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #e2e8f0; background: #1e293b; padding: 14px 20px; border-radius: 8px; text-align: center; margin: 16px 0; font-family: monospace;">
            ${code}
          </div>
          <p style="color: #64748b; font-size: 12px;">Valid for 5 minutes and single-use only. If you did not request this code, ignore this email.</p>
        </div>
      `,
    });

    if (!emailResult.success) {
      otpChallengeStore.delete(identityKey);
      const reason = emailResult.error || 'Failed to send verification email via SMTP.';
      recordOtpAuditEvent({
        eventType: 'OTP_REQUEST',
        action: 'OTP_DELIVERY_FAILED',
        outcome: 'FAILURE',
        destination: identityKey,
        channel: 'EMAIL',
        purpose,
        reason,
        auditContext,
      });
      return {
        success: false,
        channel: 'EMAIL',
        destination: identityKey,
        emailConfigured: isLiveSmtpConfigured(),
        error: reason,
      };
    }

    state.lastRequestedAt = now;
    state.dailyCount += 1;
    const dailyRemaining = Math.max(0, MAX_DAILY_OTPS_PER_EMAIL - state.dailyCount);

    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_SENT',
      outcome: 'SUCCESS',
      destination: identityKey,
      channel: 'EMAIL',
      purpose,
      reason: `6-digit salted SHA-256 OTP dispatched via SMTP (${state.dailyCount}/${MAX_DAILY_OTPS_PER_EMAIL} today).`,
      auditContext,
    });

    return {
      success: true,
      channel: 'EMAIL',
      destination: identityKey,
      emailConfigured: isLiveSmtpConfigured(),
      serviceConfigured: isLiveSmtpConfigured(),
      messageId: emailResult.messageId,
      expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
      cooldownSeconds: Math.floor(OTP_COOLDOWN_MS / 1000),
      dailyLimit: MAX_DAILY_OTPS_PER_EMAIL,
      dailyRemaining,
      note: `Verification code sent to ${identityKey} via SMTP.`,
    };
  }

  // Mobile destination (direct Fast2SMS fallback path if invoked)
  setFast2SmsTargetPhone(identityKey);
  const fast2SmsResult = await sendFast2Sms(
    identityKey,
    `Your Aegis Sentinel verification code is ${code}. Valid for 5 minutes.`,
    code
  );

  if (!fast2SmsResult.success) {
    otpChallengeStore.delete(identityKey);
    const reason = fast2SmsResult.error || 'SMS delivery failed via Fast2SMS.';
    recordOtpAuditEvent({
      eventType: 'OTP_REQUEST',
      action: 'OTP_DELIVERY_FAILED',
      outcome: 'FAILURE',
      destination: identityKey,
      channel: 'FAST2SMS',
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      channel: 'FAST2SMS',
      destination: identityKey,
      phoneNumber: identityKey,
      fast2smsConfigured: isFast2SmsConfigured(),
      error: reason,
    };
  }

  state.lastRequestedAt = now;
  state.dailyCount += 1;
  const dailyRemaining = Math.max(0, MAX_DAILY_OTPS_PER_EMAIL - state.dailyCount);

  recordOtpAuditEvent({
    eventType: 'OTP_REQUEST',
    action: 'OTP_SENT',
    outcome: 'SUCCESS',
    destination: identityKey,
    channel: 'FAST2SMS',
    purpose,
    reason: `6-digit salted SHA-256 OTP dispatched via Fast2SMS (${state.dailyCount}/${MAX_DAILY_OTPS_PER_EMAIL} today).`,
    auditContext,
  });

  return {
    success: true,
    channel: 'FAST2SMS',
    destination: identityKey,
    phoneNumber: identityKey,
    messageId: fast2SmsResult.messageId,
    fast2smsConfigured: isFast2SmsConfigured(),
    serviceConfigured: isFast2SmsConfigured(),
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    cooldownSeconds: Math.floor(OTP_COOLDOWN_MS / 1000),
    dailyLimit: MAX_DAILY_OTPS_PER_EMAIL,
    dailyRemaining,
    note: `Verification code sent to ${identityKey} via Fast2SMS.`,
  };
}

/**
 * Verify a user-submitted 6-digit OTP against the salted SHA-256 hash using
 * `crypto.timingSafeEqual`. Enforces 5-minute expiry, single-use consumption,
 * 5 max wrong attempts with a 15-minute lockout, and audit logging.
 *
 * @param {string} destination
 * @param {string} inputCode
 * @param {{ purpose?: string, auditContext?: { ip?: string, userAgent?: string } }} [options]
 * @returns {{
 *   success: boolean,
 *   error?: string,
 *   locked?: boolean,
 *   lockoutSeconds?: number,
 *   attemptsRemaining?: number,
 *   destination?: string,
 *   phoneNumber?: string,
 *   email?: string,
 *   channel?: string
 * }}
 */
export function verifyOtp(destination, inputCode, options = {}) {
  const { purpose = 'LOGIN_OTP', auditContext } = options;
  const { isEmail, identityKey } = normalizeDestination(destination);
  const cleanCode = String(inputCode || '').trim();
  const now = Date.now();
  const state = getSecurityState(identityKey || 'unknown', now);

  // 1. Check active 15-minute lockout
  if (state.lockedUntil > now) {
    const lockoutSeconds = Math.ceil((state.lockedUntil - now) / 1000);
    const lockoutMinutes = Math.ceil(lockoutSeconds / 60);
    const reason = `Too many incorrect attempts. Account locked for ${lockoutMinutes} minute(s) (${lockoutSeconds}s remaining).`;
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_VERIFY_BLOCKED_LOCKED',
      outcome: 'BLOCKED',
      destination: identityKey || String(destination || ''),
      channel: isEmail ? 'EMAIL' : 'FAST2SMS',
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      locked: true,
      lockoutSeconds,
      error: reason,
    };
  }

  if (!/^\d{6}$/.test(cleanCode)) {
    const reason = 'Verification code must be exactly 6 digits.';
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_VERIFY_INVALID_FORMAT',
      outcome: 'FAILURE',
      destination: identityKey || String(destination || ''),
      channel: isEmail ? 'EMAIL' : 'FAST2SMS',
      purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      error: reason,
    };
  }

  const record = otpChallengeStore.get(identityKey);

  if (!record || record.used) {
    const reason = 'No active verification code found for this destination. Please request a new OTP.';
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_VERIFY_NO_ACTIVE_CODE',
      outcome: 'FAILURE',
      destination: identityKey,
      channel: record?.channel || (isEmail ? 'EMAIL' : 'FAST2SMS'),
      purpose: record?.purpose || purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      error: reason,
    };
  }

  if (now > record.expiresAt) {
    otpChallengeStore.delete(identityKey);
    const reason = 'The verification code has expired (5-minute limit). Please request a new OTP.';
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_VERIFY_EXPIRED',
      outcome: 'FAILURE',
      destination: identityKey,
      channel: record.channel,
      purpose: record.purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      error: reason,
    };
  }

  if (record.attempts >= MAX_OTP_ATTEMPTS) {
    otpChallengeStore.delete(identityKey);
    state.lockedUntil = now + OTP_LOCKOUT_MS;
    const lockoutSeconds = Math.floor(OTP_LOCKOUT_MS / 1000);
    const reason = 'Maximum 5 wrong attempts exceeded. Locked for 15 minutes.';
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_LOCKED_MAX_ATTEMPTS',
      outcome: 'BLOCKED',
      destination: identityKey,
      channel: record.channel,
      purpose: record.purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      locked: true,
      lockoutSeconds,
      error: reason,
    };
  }

  // Timing-safe SHA-256 comparison
  const candidateHash = hashOtpCode(cleanCode, record.salt);
  const isMatch =
    candidateHash.length === record.codeHash.length &&
    crypto.timingSafeEqual(candidateHash, record.codeHash);

  if (!isMatch) {
    record.attempts += 1;
    const remaining = MAX_OTP_ATTEMPTS - record.attempts;

    if (remaining <= 0) {
      otpChallengeStore.delete(identityKey);
      state.lockedUntil = now + OTP_LOCKOUT_MS;
      const lockoutSeconds = Math.floor(OTP_LOCKOUT_MS / 1000);
      const reason = 'Maximum 5 wrong attempts reached. Destination locked for 15 minutes.';
      recordOtpAuditEvent({
        eventType: 'OTP_VERIFY',
        action: 'OTP_LOCKED_MAX_ATTEMPTS',
        outcome: 'BLOCKED',
        destination: identityKey,
        channel: record.channel,
        purpose: record.purpose,
        reason,
        auditContext,
      });
      return {
        success: false,
        locked: true,
        lockoutSeconds,
        attemptsRemaining: 0,
        error: reason,
      };
    }

    const reason = `Incorrect verification code (attempt ${record.attempts}/${MAX_OTP_ATTEMPTS}). ${remaining} attempt(s) remaining.`;
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'OTP_VERIFY_WRONG_CODE',
      outcome: 'FAILURE',
      destination: identityKey,
      channel: record.channel,
      purpose: record.purpose,
      reason,
      auditContext,
    });
    return {
      success: false,
      attemptsRemaining: remaining,
      error: `Incorrect verification code. ${remaining} attempt(s) remaining.`,
    };
  }

  // Single-use enforcement: mark used and immediately remove from challenge store
  record.used = true;
  otpChallengeStore.delete(identityKey);

  recordOtpAuditEvent({
    eventType: 'OTP_VERIFY',
    action: 'OTP_VERIFY_SUCCESS',
    outcome: 'SUCCESS',
    destination: identityKey,
    channel: record.channel,
    purpose: record.purpose,
    reason: '6-digit OTP verified with timing-safe comparison and consumed (single-use).',
    auditContext,
  });

  return {
    success: true,
    destination: identityKey,
    phoneNumber: isEmail ? undefined : identityKey,
    email: isEmail ? identityKey : undefined,
    channel: record.channel,
  };
}

/**
 * Issue a signed JWT session token for an authenticated user.
 * @param {Record<string, any>} claims
 * @param {string} [expiresIn='7d']
 * @returns {string}
 */
export function mintSessionToken(claims, expiresIn = '7d') {
  return jwt.sign(claims, getJwtSecret(), /** @type {jwt.SignOptions} */ ({ expiresIn }));
}

/**
 * Create a short-lived signed 2FA challenge token binding verified password credentials
 * to a specific OTP destination before a full session JWT is issued.
 *
 * @param {{ id: string, email: string, role: string, phoneNumber?: string, preferences?: any }} user
 * @param {string} otpDestination
 * @returns {string}
 */
export function createTwoFactorChallenge(user, otpDestination) {
  return jwt.sign(
    {
      purpose: '2FA_CHALLENGE',
      challengeId: crypto.randomUUID(),
      userId: String(user.id),
      email: user.email,
      role: user.role,
      phoneNumber: user.phoneNumber,
      preferences: user.preferences,
      otpDestination,
    },
    getJwtSecret(),
    { expiresIn: '5m' }
  );
}

/**
 * Verify a pending 2FA login challenge token and ensure it hasn't been consumed.
 * @param {string} challengeToken
 * @returns {{ valid: boolean, payload?: any, error?: string }}
 */
export function verifyTwoFactorChallenge(challengeToken) {
  try {
    const decoded = /** @type {any} */ (jwt.verify(challengeToken, getJwtSecret()));
    if (!decoded || decoded.purpose !== '2FA_CHALLENGE' || !decoded.otpDestination) {
      return { valid: false, error: 'Invalid 2FA challenge token.' };
    }
    if (decoded.challengeId && consumedTwoFactorChallengeIds.has(decoded.challengeId)) {
      return { valid: false, error: 'This 2FA challenge has already been used. Please sign in again.' };
    }
    return { valid: true, payload: decoded };
  } catch {
    return { valid: false, error: 'Your 2FA login session expired. Please sign in again.' };
  }
}

/**
 * Mark a 2FA challenge ID as consumed so it cannot be replayed.
 * @param {string | undefined} challengeId
 */
function markChallengeConsumed(challengeId) {
  if (!challengeId) return;
  const now = Date.now();
  consumedTwoFactorChallengeIds.set(challengeId, now + OTP_TTL_MS);
  if (consumedTwoFactorChallengeIds.size > 500) {
    for (const [id, exp] of consumedTwoFactorChallengeIds.entries()) {
      if (now > exp) consumedTwoFactorChallengeIds.delete(id);
    }
  }
}

/**
 * Complete Email/Destination OTP login authentication via node_auth.js.
 *
 * @param {{ destination: string, code: string, role?: string, auditContext?: { ip?: string, userAgent?: string } }} params
 * @returns {{ success: boolean, error?: string, locked?: boolean, lockoutSeconds?: number, attemptsRemaining?: number, token?: string, user?: any }}
 */
export function authenticateWithOtp({ destination, code, role = 'USER', auditContext }) {
  const verification = verifyOtp(destination, code, { purpose: 'LOGIN_OTP', auditContext });
  if (!verification.success) {
    return {
      success: false,
      locked: verification.locked,
      lockoutSeconds: verification.lockoutSeconds,
      attemptsRemaining: verification.attemptsRemaining,
      error: verification.error,
    };
  }

  const normalizedDest = verification.destination;
  const isPhone = Boolean(verification.phoneNumber);
  const userId = `usr_${Buffer.from(normalizedDest).toString('hex').slice(0, 16)}`;

  if (isPhone && verification.phoneNumber) {
    setFast2SmsTargetPhone(verification.phoneNumber);
  }

  const token = mintSessionToken(
    {
      userId,
      ...(isPhone ? { phoneNumber: normalizedDest } : { email: normalizedDest }),
      role,
      authMethod: isPhone ? 'NODE_AUTH_SMS_OTP' : 'NODE_AUTH_EMAIL_OTP',
    },
    '7d'
  );

  const user = {
    id: userId,
    ...(isPhone ? { phoneNumber: normalizedDest } : { email: normalizedDest }),
    role,
    authenticatedAt: new Date().toISOString(),
    channels: isPhone ? ['WEBSOCKET', 'SMS'] : ['WEBSOCKET', 'EMAIL'],
    authEngine: 'node_auth.js',
  };

  return {
    success: true,
    token,
    user,
  };
}

/**
 * Complete Firebase Phone Auth OTP login on the Node.js backend via node_auth.js.
 *
 * @param {{ firebaseIdToken: string, role?: string, auditContext?: { ip?: string, userAgent?: string } }} params
 * @returns {Promise<{ success: boolean, error?: string, token?: string, user?: any }>}
 */
export async function authenticateWithFirebasePhone({ firebaseIdToken, role = 'USER', auditContext }) {
  const verification = await verifyFirebasePhoneIdToken(firebaseIdToken, auditContext);
  if (!verification.valid || !verification.phoneNumber || !verification.uid) {
    return {
      success: false,
      error: verification.error || 'Firebase Phone verification failed.',
    };
  }

  const normalizedPhone = verification.phoneNumber;
  setFast2SmsTargetPhone(normalizedPhone);
  const userId = `usr_fb_${verification.uid.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24)}`;

  const token = mintSessionToken(
    {
      userId,
      firebaseUid: verification.uid,
      phoneNumber: normalizedPhone,
      role,
      authMethod: 'NODE_AUTH_FIREBASE_PHONE',
    },
    '7d'
  );

  const user = {
    id: userId,
    firebaseUid: verification.uid,
    phoneNumber: normalizedPhone,
    role,
    authenticatedAt: new Date().toISOString(),
    channels: ['WEBSOCKET', 'SMS'],
    authEngine: 'node_auth.js + Firebase Phone Auth',
  };

  return {
    success: true,
    token,
    user,
  };
}

/**
 * Complete Step 2 of Password + 2FA Login using node_auth.js (supports Email OTP or Firebase Phone ID token).
 *
 * @param {{ challengeToken: string, otpCode?: string, firebaseIdToken?: string, auditContext?: { ip?: string, userAgent?: string } }} params
 * @returns {Promise<{ success: boolean, error?: string, locked?: boolean, lockoutSeconds?: number, token?: string, user?: any }>}
 */
export async function authenticateTwoFactorLogin({ challengeToken, otpCode, firebaseIdToken, auditContext }) {
  const challenge = verifyTwoFactorChallenge(challengeToken);
  if (!challenge.valid || !challenge.payload) {
    return {
      success: false,
      error: challenge.error || 'Invalid 2FA challenge.',
    };
  }

  const { challengeId, userId, email, role, phoneNumber, preferences, otpDestination } = challenge.payload;

  if (firebaseIdToken) {
    const fbCheck = await verifyFirebasePhoneIdToken(firebaseIdToken, auditContext);
    if (!fbCheck.valid || !fbCheck.phoneNumber) {
      return {
        success: false,
        error: fbCheck.error || 'Firebase 2FA phone verification failed.',
      };
    }

    const expectedDigits = String(otpDestination || '').replace(/\D/g, '').slice(-10);
    const actualDigits = fbCheck.phoneNumber.replace(/\D/g, '').slice(-10);
    if (expectedDigits && actualDigits !== expectedDigits) {
      return {
        success: false,
        error: 'Verified Firebase phone number does not match the 2FA destination.',
      };
    }

    markChallengeConsumed(challengeId);
    setFast2SmsTargetPhone(fbCheck.phoneNumber);
    const token = mintSessionToken(
      {
        userId,
        email,
        phoneNumber: fbCheck.phoneNumber,
        firebaseUid: fbCheck.uid,
        role,
        authMethod: 'NODE_AUTH_PASSWORD_FIREBASE_2FA',
      },
      '24h'
    );

    return {
      success: true,
      token,
      user: {
        id: userId,
        email,
        phoneNumber: fbCheck.phoneNumber,
        role,
        preferences,
        authenticatedAt: new Date().toISOString(),
        authEngine: 'node_auth.js + Firebase Phone Auth',
      },
    };
  }

  const otpVerification = verifyOtp(otpDestination, otpCode || '', {
    purpose: 'LOGIN_2FA',
    auditContext,
  });
  if (!otpVerification.success) {
    return {
      success: false,
      locked: otpVerification.locked,
      lockoutSeconds: otpVerification.lockoutSeconds,
      error: otpVerification.error,
    };
  }

  markChallengeConsumed(challengeId);

  const token = mintSessionToken(
    {
      userId,
      email,
      ...(phoneNumber ? { phoneNumber } : {}),
      role,
      authMethod: 'NODE_AUTH_PASSWORD_2FA',
    },
    '24h'
  );

  return {
    success: true,
    token,
    user: {
      id: userId,
      email,
      ...(phoneNumber ? { phoneNumber } : {}),
      role,
      preferences,
      authenticatedAt: new Date().toISOString(),
      authEngine: 'node_auth.js',
    },
  };
}

/**
 * Cryptographically verify a Firebase Google Sign-In ID token on the Node.js backend.
 *
 * @param {string} firebaseIdToken
 * @param {{ ip?: string, userAgent?: string }} [auditContext]
 * @returns {Promise<{ valid: boolean, uid?: string, email?: string, name?: string, picture?: string, error?: string }>}
 */
export async function verifyFirebaseGoogleIdToken(firebaseIdToken, auditContext) {
  try {
    const projectId = getFirebaseProjectId();
    if (!projectId) {
      return { valid: false, error: 'Firebase projectId is not configured on the server.' };
    }

    const decodedHeader = jwt.decode(firebaseIdToken, { complete: true });
    if (!decodedHeader || typeof decodedHeader === 'string' || !decodedHeader.header?.kid) {
      return { valid: false, error: 'Malformed Firebase ID token header.' };
    }

    const certs = await getGoogleSecureTokenCerts();
    let certPem = certs[decodedHeader.header.kid];
    if (!certPem) {
      cachedGoogleCerts = null;
      const refreshedCerts = await getGoogleSecureTokenCerts();
      certPem = refreshedCerts[decodedHeader.header.kid];
    }

    if (!certPem) {
      return { valid: false, error: 'Unable to find matching Firebase signing certificate.' };
    }

    const payload = /** @type {any} */ (
      jwt.verify(firebaseIdToken, certPem, {
        algorithms: ['RS256'],
        audience: projectId,
        issuer: `https://securetoken.google.com/${projectId}`,
      })
    );

    if (!payload?.sub || typeof payload.sub !== 'string') {
      return { valid: false, error: 'Firebase token is missing user subject (uid).' };
    }

    if (!payload.email || payload.email_verified !== true) {
      return { valid: false, error: 'Google Sign-In requires a verified email address.' };
    }

    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'FIREBASE_GOOGLE_SIGNIN',
      outcome: 'SUCCESS',
      destination: String(payload.email).toLowerCase(),
      channel: 'FIREBASE_GOOGLE',
      purpose: 'LOGIN_GOOGLE',
      reason: 'Firebase Google Sign-In ID token verified via RS256.',
      auditContext,
    });

    return {
      valid: true,
      uid: payload.sub,
      email: String(payload.email).toLowerCase(),
      name: typeof payload.name === 'string' ? payload.name : undefined,
      picture: typeof payload.picture === 'string' ? payload.picture : undefined,
    };
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    recordOtpAuditEvent({
      eventType: 'OTP_VERIFY',
      action: 'FIREBASE_GOOGLE_SIGNIN_FAILED',
      outcome: 'FAILURE',
      destination: 'firebase_google',
      channel: 'FIREBASE_GOOGLE',
      purpose: 'LOGIN_GOOGLE',
      reason: `Firebase Google verification failed: ${errMsg}`,
      auditContext,
    });
    return {
      valid: false,
      error: `Firebase Google verification failed: ${errMsg}`,
    };
  }
}

/**
 * Exchange a verified Firebase Google Sign-In ID token for an Aegis session JWT.
 *
 * @param {{ firebaseIdToken: string, role?: string, auditContext?: { ip?: string, userAgent?: string } }} params
 * @returns {Promise<{ success: boolean, error?: string, token?: string, user?: any }>}
 */
export async function authenticateWithFirebaseGoogle({ firebaseIdToken, role = 'USER', auditContext }) {
  const verification = await verifyFirebaseGoogleIdToken(firebaseIdToken, auditContext);
  if (!verification.valid || !verification.email || !verification.uid) {
    return {
      success: false,
      error: verification.error || 'Firebase Google Sign-In verification failed.',
    };
  }

  const userId = verification.uid;
  const token = mintSessionToken(
    {
      userId,
      firebaseUid: verification.uid,
      email: verification.email,
      role,
      authMethod: 'NODE_AUTH_FIREBASE_GOOGLE',
    },
    '7d'
  );

  const user = {
    id: userId,
    firebaseUid: verification.uid,
    email: verification.email,
    displayName: verification.name,
    photoURL: verification.picture,
    role,
    authenticatedAt: new Date().toISOString(),
    channels: ['WEBSOCKET', 'EMAIL'],
    authEngine: 'node_auth.js + Firebase Google Auth',
  };

  return {
    success: true,
    token,
    user,
  };
}
