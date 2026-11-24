import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { logSecurityEvent } from '../telemetry/securityLogger.js';
import { sendEmailNotification, escapeHtml } from '../integrations/emailService.js';
import { getCoarseDeviceType } from './deviceMemory.js';
import { User, inMemoryUsers } from '../../models/User.js';
import { connectToDatabase } from '../db/mongoose.js';

export const GENERIC_LOGIN_ERROR = 'Email or password is incorrect.';

// Pre-computed dummy bcrypt hash so unknown-email requests pay comparable CPU cost
const DUMMY_BCRYPT_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

const GOOGLE_SECURETOKEN_CERTS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

let cachedCerts: { certs: Record<string, string>; expiresAt: number } | null = null;
let cachedFirebaseProjectId: string | null = null;

export interface StoredEncryptedKeyBackup {
  v: 1;
  userId: string;
  kdf: 'PBKDF2-HMAC-SHA256';
  iterations: number;
  cipher: 'AES-256-GCM';
  salt: string;
  iv: string;
  encryptedPrivateKeysBundle: string;
  ed25519PublicKey: string;
  ed25519Kid: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  ecdhPublicJwk: Record<string, unknown>;
  ecdsaPublicJwk: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface LoginAuditRecord {
  id: string;
  userId: string;
  timestamp: string;
  deviceType: 'Mobile' | 'Tablet' | 'Desktop';
  browserSummary: string;
  ipPrefixHash: string;
  deviceIdHash: string;
  method: string;
  isNewDevice: boolean;
}

export interface UserSecurityAccountRecord {
  userId: string;
  firebaseUid?: string;
  email?: string;
  phoneNumber?: string;
  displayName?: string;
  role: string;
  sessionVersion: number;
  inactivityTimeoutDays: number;
  onboardingCompleted: boolean;
  keySetupCompleted: boolean;
  emailVerified: boolean;
  authMethods: string[];
  knownDeviceHashes: Set<string>;
  loginAudits: LoginAuditRecord[];
  keyBackup?: StoredEncryptedKeyBackup;
  createdAt: string;
  updatedAt: string;
}

declare global {
  var __aegisSmartAuthStore: Map<string, UserSecurityAccountRecord> | undefined;
}

function getSecurityStore(): Map<string, UserSecurityAccountRecord> {
  if (!globalThis.__aegisSmartAuthStore) {
    globalThis.__aegisSmartAuthStore = new Map();
  }
  return globalThis.__aegisSmartAuthStore;
}

export function getFirebaseProjectIdFromConfig(): string {
  if (cachedFirebaseProjectId) return cachedFirebaseProjectId;
  if (process.env.FIREBASE_PROJECT_ID) {
    cachedFirebaseProjectId = process.env.FIREBASE_PROJECT_ID.trim();
    return cachedFirebaseProjectId;
  }
  try {
    const cfgPath = resolve(process.cwd(), 'firebase-applet-config.json');
    const parsed = JSON.parse(readFileSync(cfgPath, 'utf8'));
    if (parsed?.projectId) {
      cachedFirebaseProjectId = String(parsed.projectId).trim();
      return cachedFirebaseProjectId;
    }
  } catch {
    // Ignore missing config
  }
  return '';
}

async function fetchGoogleSecureTokenCerts(): Promise<Record<string, string>> {
  const now = Date.now();
  if (cachedCerts && now < cachedCerts.expiresAt) {
    return cachedCerts.certs;
  }
  const res = await fetch(GOOGLE_SECURETOKEN_CERTS_URL);
  if (!res.ok) {
    throw new Error(`Unable to fetch Firebase verification certificates (${res.status}).`);
  }
  const certs = (await res.json()) as Record<string, string>;
  const cc = res.headers.get('cache-control') || '';
  const match = cc.match(/max-age=(\d+)/i);
  const maxAgeMs = match ? Math.max(60, parseInt(match[1], 10)) * 1000 : 3600 * 1000;
  cachedCerts = { certs, expiresAt: now + maxAgeMs };
  return certs;
}

export interface VerifiedFirebaseIdTokenResult {
  valid: boolean;
  uid?: string;
  email?: string;
  emailVerified?: boolean;
  phoneNumber?: string;
  name?: string;
  picture?: string;
  signInProvider?: string;
  providers?: string[];
  error?: string;
}

/**
 * Verifies any RS256 Firebase ID token (Google, Email/Password verified or unverified signup,
 * Phone, or linked account) without forcing Google-only checks.
 */
export async function verifyFirebaseIdTokenGeneral(
  firebaseIdToken: string
): Promise<VerifiedFirebaseIdTokenResult> {
  try {
    const projectId = getFirebaseProjectIdFromConfig();
    if (!projectId) {
      return { valid: false, error: 'Firebase projectId is not configured on the server.' };
    }

    const decodedHeader = jwt.decode(firebaseIdToken, { complete: true });
    if (!decodedHeader || typeof decodedHeader === 'string' || !decodedHeader.header?.kid) {
      return { valid: false, error: 'Malformed Firebase ID token header.' };
    }

    const certs = await fetchGoogleSecureTokenCerts();
    let certPem = certs[decodedHeader.header.kid];
    if (!certPem) {
      cachedCerts = null;
      const refreshed = await fetchGoogleSecureTokenCerts();
      certPem = refreshed[decodedHeader.header.kid];
    }

    if (!certPem) {
      return { valid: false, error: 'Unable to verify Firebase signing certificate.' };
    }

    const payload = jwt.verify(firebaseIdToken, certPem, {
      algorithms: ['RS256'],
      audience: projectId,
      issuer: `https://securetoken.google.com/${projectId}`,
    }) as Record<string, any>;

    if (!payload?.sub || typeof payload.sub !== 'string') {
      return { valid: false, error: 'Firebase token is missing user subject.' };
    }

    const identities =
      payload.firebase?.identities && typeof payload.firebase.identities === 'object'
        ? Object.keys(payload.firebase.identities)
        : [];

    return {
      valid: true,
      uid: payload.sub,
      email: typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : undefined,
      emailVerified: Boolean(payload.email_verified),
      phoneNumber: typeof payload.phone_number === 'string' ? payload.phone_number : undefined,
      name: typeof payload.name === 'string' ? payload.name : undefined,
      picture: typeof payload.picture === 'string' ? payload.picture : undefined,
      signInProvider:
        typeof payload.firebase?.sign_in_provider === 'string'
          ? payload.firebase.sign_in_provider
          : undefined,
      providers: identities,
    };
  } catch (err: any) {
    return {
      valid: false,
      error: err?.message || 'Firebase ID token verification failed.',
    };
  }
}

export function getOrCreateUserSecurityRecord(
  userId: string,
  defaults?: Partial<{
    firebaseUid: string;
    email: string;
    phoneNumber: string;
    displayName: string;
    role: string;
    emailVerified: boolean;
    authMethods: string[];
  }>
): UserSecurityAccountRecord {
  const store = getSecurityStore();
  let rec = store.get(userId);
  const nowIso = new Date().toISOString();

  if (!rec) {
    rec = {
      userId,
      firebaseUid: defaults?.firebaseUid,
      email: defaults?.email,
      phoneNumber: defaults?.phoneNumber,
      displayName: defaults?.displayName,
      role: defaults?.role || 'USER',
      sessionVersion: 1,
      inactivityTimeoutDays: 14,
      onboardingCompleted: false,
      keySetupCompleted: false,
      emailVerified: Boolean(defaults?.emailVerified),
      authMethods: defaults?.authMethods ? [...new Set(defaults.authMethods)] : [],
      knownDeviceHashes: new Set<string>(),
      loginAudits: [],
      createdAt: nowIso,
      updatedAt: nowIso,
    };
    store.set(userId, rec);
  } else if (defaults) {
    if (defaults.firebaseUid) rec.firebaseUid = defaults.firebaseUid;
    if (defaults.email) rec.email = defaults.email;
    if (defaults.phoneNumber) rec.phoneNumber = defaults.phoneNumber;
    if (defaults.displayName) rec.displayName = defaults.displayName;
    if (defaults.role) rec.role = defaults.role;
    if (typeof defaults.emailVerified === 'boolean') rec.emailVerified = defaults.emailVerified;
    if (Array.isArray(defaults.authMethods) && defaults.authMethods.length > 0) {
      rec.authMethods = [...new Set([...rec.authMethods, ...defaults.authMethods])];
    }
    rec.updatedAt = nowIso;
  }

  return rec;
}

export function getUserSecurityRecord(userId: string): UserSecurityAccountRecord | null {
  return getSecurityStore().get(userId) || null;
}

export function getUserSessionVersion(userId: string): number {
  return getSecurityStore().get(userId)?.sessionVersion ?? 1;
}

export function incrementUserSessionVersion(userId: string): number {
  const rec = getOrCreateUserSecurityRecord(userId);
  rec.sessionVersion += 1;
  rec.updatedAt = new Date().toISOString();
  return rec.sessionVersion;
}

export function updateUserSecurityPreferences(
  userId: string,
  updates: Partial<{
    inactivityTimeoutDays: number;
    onboardingCompleted: boolean;
    keySetupCompleted: boolean;
    authMethods: string[];
    email: string;
    emailVerified: boolean;
  }>
): UserSecurityAccountRecord {
  const rec = getOrCreateUserSecurityRecord(userId);
  if (typeof updates.inactivityTimeoutDays === 'number' && Number.isFinite(updates.inactivityTimeoutDays)) {
    rec.inactivityTimeoutDays = Math.max(1, Math.min(90, Math.round(updates.inactivityTimeoutDays)));
  }
  if (typeof updates.onboardingCompleted === 'boolean') {
    rec.onboardingCompleted = updates.onboardingCompleted;
  }
  if (typeof updates.keySetupCompleted === 'boolean') {
    rec.keySetupCompleted = updates.keySetupCompleted;
  }
  if (Array.isArray(updates.authMethods)) {
    rec.authMethods = [...new Set(updates.authMethods.map((m) => String(m).trim()).filter(Boolean))].slice(0, 8);
  }
  if (updates.email) rec.email = updates.email.trim().toLowerCase();
  if (typeof updates.emailVerified === 'boolean') rec.emailVerified = updates.emailVerified;
  rec.updatedAt = new Date().toISOString();
  return rec;
}

export function saveServerKeyBackup(userId: string, backup: StoredEncryptedKeyBackup): StoredEncryptedKeyBackup {
  const raw = JSON.stringify(backup).toLowerCase();
  if (
    raw.includes('passphrase') ||
    raw.includes('ed25519seed') ||
    raw.includes('ecdhprivatejwk') ||
    raw.includes('ecdsaprivatejwk')
  ) {
    throw new Error('Encrypted key backup must never contain passphrase or plaintext private keys.');
  }

  const rec = getOrCreateUserSecurityRecord(userId);
  const nowIso = new Date().toISOString();
  const sanitized: StoredEncryptedKeyBackup = {
    v: 1,
    userId,
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: Math.max(100_000, Math.min(1_000_000, Math.floor(backup.iterations || 150_000))),
    cipher: 'AES-256-GCM',
    salt: String(backup.salt),
    iv: String(backup.iv),
    encryptedPrivateKeysBundle: String(backup.encryptedPrivateKeysBundle),
    ed25519PublicKey: String(backup.ed25519PublicKey),
    ed25519Kid: String(backup.ed25519Kid),
    fingerprintHex: String(backup.fingerprintHex || ''),
    fingerprintWords: Array.isArray(backup.fingerprintWords)
      ? backup.fingerprintWords.slice(0, 12).map(String)
      : [],
    ecdhPublicJwk: backup.ecdhPublicJwk,
    ecdsaPublicJwk: backup.ecdsaPublicJwk,
    createdAt: backup.createdAt || nowIso,
    updatedAt: nowIso,
  };
  rec.keyBackup = sanitized;
  rec.keySetupCompleted = true;
  rec.updatedAt = nowIso;
  return sanitized;
}

export function getServerKeyBackup(userId: string): StoredEncryptedKeyBackup | null {
  return getSecurityStore().get(userId)?.keyBackup || null;
}

export function deleteServerUserSecurityAccount(userId: string): void {
  const store = getSecurityStore();
  const rec = store.get(userId);
  if (rec?.email) {
    inMemoryUsers.delete(rec.email.toLowerCase());
  }
  inMemoryUsers.delete(userId);
  store.delete(userId);
}

export function hashIpPrefix(ipAddress: string): string {
  const clean = String(ipAddress || '0.0.0.0').trim();
  let prefix = clean;
  if (clean.includes('.')) {
    const parts = clean.split('.');
    if (parts.length === 4) {
      prefix = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
  } else if (clean.includes(':')) {
    const parts = clean.split(':').slice(0, 4);
    prefix = `${parts.join(':')}::/64`;
  }
  return crypto.createHash('sha256').update(`ip_prefix:${prefix}`).digest('hex').slice(0, 16);
}

export function hashDeviceIdentifier(deviceId: string | undefined, userAgent: string): string {
  const raw =
    deviceId && /^[a-zA-Z0-9_-]{8,128}$/.test(deviceId)
      ? `dev:${deviceId}`
      : `ua:${String(userAgent || 'unknown').slice(0, 160)}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24);
}

export function summarizeBrowser(userAgent: string): string {
  const ua = String(userAgent || '');
  if (!ua || ua === 'unknown') return 'Unknown browser';
  if (/Edg\//i.test(ua)) return 'Microsoft Edge';
  if (/Chrome\//i.test(ua) && !/Edg\//i.test(ua)) return 'Chrome / Chromium';
  if (/Firefox\//i.test(ua)) return 'Mozilla Firefox';
  if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) return 'Apple Safari';
  return 'Web Client';
}

export async function recordLoginAuditAndDetectNewDevice(params: {
  userId: string;
  email?: string;
  displayName?: string;
  deviceId?: string;
  ipAddress: string;
  userAgent: string;
  method: string;
  isFirstSignup?: boolean;
  sendAlertEmail?: boolean;
}): Promise<{
  audit: LoginAuditRecord;
  isNewDevice: boolean;
}> {
  const rec = getOrCreateUserSecurityRecord(params.userId, {
    email: params.email,
    displayName: params.displayName,
  });

  const deviceIdHash = hashDeviceIdentifier(params.deviceId, params.userAgent);
  const ipPrefixHash = hashIpPrefix(params.ipAddress);
  const deviceType = getCoarseDeviceType(params.userAgent);
  const browserSummary = summarizeBrowser(params.userAgent);

  const hadExistingDevices = rec.knownDeviceHashes.size > 0;
  const isNewDevice = !rec.knownDeviceHashes.has(deviceIdHash);
  rec.knownDeviceHashes.add(deviceIdHash);

  const audit: LoginAuditRecord = {
    id: `aud_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
    userId: params.userId,
    timestamp: new Date().toISOString(),
    deviceType,
    browserSummary,
    ipPrefixHash,
    deviceIdHash,
    method: params.method,
    isNewDevice,
  };

  rec.loginAudits.unshift(audit);
  if (rec.loginAudits.length > 30) {
    rec.loginAudits.length = 30;
  }
  rec.updatedAt = audit.timestamp;

  if (isNewDevice && !params.isFirstSignup && hadExistingDevices) {
    logSecurityEvent({
      eventType: 'NEW_DEVICE_LOGIN',
      severity: 'warning',
      result: 'success',
      userId: params.userId,
      email: params.email,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `New ${deviceType} device (${browserSummary}) signed in via ${params.method}.`,
    });

    if (params.sendAlertEmail !== false && params.email) {
      const safeDevice = escapeHtml(`${deviceType} (${browserSummary})`);
      const safeMethod = escapeHtml(params.method);
      const safeTime = escapeHtml(audit.timestamp);
      const safePrefix = escapeHtml(ipPrefixHash);
      void sendEmailNotification({
        to: params.email,
        subject: 'AegisNotify Security Alert: New Device Sign-In',
        text: `A new ${deviceType} (${browserSummary}) signed into your AegisNotify account via ${params.method} at ${audit.timestamp}. Network prefix hash: ${ipPrefixHash}. If this was not you, open Settings -> Sign out of all devices immediately.`,
        html: `
          <div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#16161D;color:#FAF6F0;border-radius:14px;">
            <h2 style="margin:0 0 12px;color:#F472B6;">New Device Sign-In Detected</h2>
            <p style="font-size:14px;line-height:1.6;color:#E5E2DC;">
              We noticed a sign-in to your AegisNotify account from a new device:
            </p>
            <ul style="font-size:13px;line-height:1.7;color:#D6D2C9;">
              <li><strong>Device:</strong> ${safeDevice}</li>
              <li><strong>Method:</strong> ${safeMethod}</li>
              <li><strong>Time (UTC):</strong> ${safeTime}</li>
              <li><strong>Network Hash:</strong> ${safePrefix}</li>
            </ul>
            <p style="font-size:13px;line-height:1.6;color:#C4C0B8;">
              Your encrypted message keys remain locked until your local passphrase is entered.
              If this wasn't you, click <strong>Sign out of all devices</strong> in Settings immediately and rotate your passphrase.
            </p>
          </div>
        `,
      }).catch(() => {
        // Non-fatal if SMTP is unavailable
      });
    }
  } else if (!isNewDevice) {
    logSecurityEvent({
      eventType: 'RETURNING_DEVICE_DETECTED',
      severity: 'info',
      result: 'success',
      userId: params.userId,
      email: params.email,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      details: `Recognized returning ${deviceType} device (${browserSummary}) via ${params.method}.`,
    });
  }

  return { audit, isNewDevice };
}

export async function enforceMinimumAuthDelay(
  startedAtMs: number,
  targetMinMs: number = 220
): Promise<void> {
  const elapsed = Date.now() - startedAtMs;
  const remaining = targetMinMs - elapsed;
  if (remaining > 0) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, remaining));
  }
}

/**
 * Constant-timing email + password verifier that never leaks whether an account exists.
 * Always runs a bcrypt comparison (against DUMMY_BCRYPT_HASH when user doesn't exist)
 * and enforces a minimum floor delay before returning GENERIC_LOGIN_ERROR.
 */
export async function verifyEmailPasswordWithConstantTiming(params: {
  email: string;
  password: string;
  minDelayMs?: number;
}): Promise<{
  success: boolean;
  message: string;
  user?: any;
}> {
  const startedAt = Date.now();
  const minDelayMs = params.minDelayMs ?? 200;
  const normalizedEmail = String(params.email || '').trim().toLowerCase();

  let user: any = null;
  const mongooseConn = await connectToDatabase().catch(() => null);
  if (mongooseConn) {
    user = await User.findOne({ email: normalizedEmail });
  } else {
    user = inMemoryUsers.get(normalizedEmail) || null;
  }

  const hashToCompare = user?.passwordHash || DUMMY_BCRYPT_HASH;
  const passwordOk = await bcrypt.compare(String(params.password || ''), hashToCompare);

  await enforceMinimumAuthDelay(startedAt, minDelayMs);

  if (!user || !user.passwordHash || !passwordOk) {
    return {
      success: false,
      message: GENERIC_LOGIN_ERROR,
    };
  }

  return {
    success: true,
    message: 'Signed in successfully.',
    user,
  };
}
