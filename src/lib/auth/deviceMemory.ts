export const DEVICE_HINT_STORAGE_KEY = 'aegis_device_hint_v1';
export const DEVICE_ID_STORAGE_KEY = 'aegis_device_id_v1';
export const LAST_ACTIVITY_STORAGE_KEY = 'aegis_last_activity_at_v1';
export const KEEP_SIGNED_IN_STORAGE_KEY = 'aegis_keep_signed_in_v1';
export const DEFAULT_INACTIVITY_TIMEOUT_DAYS = 14;

export type DeviceAuthMethod = 'google' | 'email' | 'sms';
export type InitialAuthTab = 'login' | 'signup';
export type PostAuthDestination =
  | 'verify_email'
  | 'key_setup'
  | 'unlock_keys'
  | 'onboarding'
  | 'dashboard';

export interface DeviceMemoryHint {
  v: 1;
  returning: boolean;
  lastMethod?: DeviceAuthMethod;
  lastLoginAt?: string;
  rememberEmail?: boolean;
  maskedEmail?: string;
}

export interface PasswordStrengthResult {
  valid: boolean;
  score: 0 | 1 | 2 | 3 | 4;
  label: 'Too Short' | 'Weak' | 'Fair' | 'Good' | 'Strong';
  feedback: string[];
}

const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password12',
  'password123',
  'password1234',
  '1234567890',
  '123456789012',
  'qwerty1234',
  'qwertyuiop',
  'admin12345',
  'administrator',
  'letmein123',
  'welcome123',
  'iloveyou12',
  'abc1234567',
  'changeme12',
  'aegisnotify',
  'aegis12345',
  'passw0rd12',
  '1111111111',
  '0000000000',
]);

function getSafeStorage(kind: 'local' | 'session' = 'local'): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return kind === 'local' ? window.localStorage : window.sessionStorage;
  } catch {
    return null;
  }
}

export function maskEmailForDeviceHint(rawEmail: string): string {
  const clean = String(rawEmail || '').trim().toLowerCase();
  const atIndex = clean.indexOf('@');
  if (atIndex <= 0) return '';
  const local = clean.slice(0, atIndex);
  const domain = clean.slice(atIndex + 1);
  if (!domain || !domain.includes('.')) return '';
  const head = local[0] || '*';
  return `${head}***@${domain}`;
}

export function readDeviceHint(): DeviceMemoryHint | null {
  const storage = getSafeStorage('local');
  if (!storage) return null;
  try {
    const raw = storage.getItem(DEVICE_HINT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || parsed.v !== 1) {
      return null;
    }
    const hint: DeviceMemoryHint = {
      v: 1,
      returning: Boolean(parsed.returning),
      ...(parsed.lastMethod === 'google' ||
      parsed.lastMethod === 'email' ||
      parsed.lastMethod === 'sms'
        ? { lastMethod: parsed.lastMethod }
        : {}),
      ...(typeof parsed.lastLoginAt === 'string' && parsed.lastLoginAt.length <= 64
        ? { lastLoginAt: parsed.lastLoginAt }
        : {}),
      ...(typeof parsed.rememberEmail === 'boolean'
        ? { rememberEmail: parsed.rememberEmail }
        : {}),
      ...(typeof parsed.maskedEmail === 'string' &&
      parsed.maskedEmail.includes('***@') &&
      parsed.maskedEmail.length <= 120
        ? { maskedEmail: parsed.maskedEmail }
        : {}),
    };
    return hint;
  } catch {
    return null;
  }
}

export function writeDeviceHint(params: {
  returning?: boolean;
  lastMethod?: DeviceAuthMethod;
  lastLoginAt?: string;
  rememberEmail?: boolean;
  emailForMasking?: string;
}): DeviceMemoryHint | null {
  const storage = getSafeStorage('local');
  const existing = readDeviceHint();

  const rememberEmail =
    typeof params.rememberEmail === 'boolean'
      ? params.rememberEmail
      : Boolean(existing?.rememberEmail);

  let maskedEmail = existing?.maskedEmail;
  if (!rememberEmail) {
    maskedEmail = undefined;
  } else if (params.emailForMasking) {
    maskedEmail = maskEmailForDeviceHint(params.emailForMasking) || maskedEmail;
  }

  const nextHint: DeviceMemoryHint = {
    v: 1,
    returning: typeof params.returning === 'boolean' ? params.returning : existing?.returning ?? true,
    ...(params.lastMethod || existing?.lastMethod
      ? { lastMethod: params.lastMethod || existing?.lastMethod }
      : {}),
    lastLoginAt: params.lastLoginAt || new Date().toISOString(),
    rememberEmail,
    ...(rememberEmail && maskedEmail ? { maskedEmail } : {}),
  };

  if (!storage) return nextHint;
  try {
    storage.setItem(DEVICE_HINT_STORAGE_KEY, JSON.stringify(nextHint));
  } catch {
    // Non-fatal if storage is blocked or full
  }
  return nextHint;
}

export function forgetDeviceHint(): void {
  const storage = getSafeStorage('local');
  if (!storage) return;
  try {
    storage.removeItem(DEVICE_HINT_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function getOrCreateDeviceId(): string {
  const fallbackId = 'ephemeral_device_session';
  const storage = getSafeStorage('local');
  if (!storage) return fallbackId;
  try {
    const existing = storage.getItem(DEVICE_ID_STORAGE_KEY);
    if (existing && /^[a-zA-Z0-9_-]{8,128}$/.test(existing)) {
      return existing;
    }
    const generated =
      typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.randomUUID === 'function'
        ? `dev_${globalThis.crypto.randomUUID().replace(/-/g, '')}`
        : `dev_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
    storage.setItem(DEVICE_ID_STORAGE_KEY, generated);
    return generated;
  } catch {
    return fallbackId;
  }
}

export function determineInitialAuthTab(hint: DeviceMemoryHint | null): InitialAuthTab {
  return hint?.returning ? 'login' : 'signup';
}

export function getCoarseDeviceType(userAgent?: string): 'Mobile' | 'Tablet' | 'Desktop' {
  const ua = String(
    userAgent || (typeof navigator !== 'undefined' ? navigator.userAgent : '')
  ).toLowerCase();
  if (!ua) return 'Desktop';
  if (/(ipad|tablet|playbook|silk)|(android(?!.*mobile))/i.test(ua)) {
    return 'Tablet';
  }
  if (/(mobi|iphone|ipod|android|blackberry|opera mini|iemobile)/i.test(ua)) {
    return 'Mobile';
  }
  return 'Desktop';
}

export function readKeepSignedInPreference(): boolean {
  const storage = getSafeStorage('local');
  if (!storage) return true;
  try {
    const raw = storage.getItem(KEEP_SIGNED_IN_STORAGE_KEY);
    if (raw === 'false') return false;
    return true;
  } catch {
    return true;
  }
}

export function writeKeepSignedInPreference(keepSignedIn: boolean): void {
  const storage = getSafeStorage('local');
  if (!storage) return;
  try {
    storage.setItem(KEEP_SIGNED_IN_STORAGE_KEY, keepSignedIn ? 'true' : 'false');
  } catch {
    // Non-fatal
  }
}

export function touchLastActivity(nowMs: number = Date.now()): void {
  const storage = getSafeStorage('local');
  if (!storage) return;
  try {
    storage.setItem(LAST_ACTIVITY_STORAGE_KEY, String(nowMs));
  } catch {
    // Non-fatal
  }
}

export function clearLastActivity(): void {
  const storage = getSafeStorage('local');
  if (!storage) return;
  try {
    storage.removeItem(LAST_ACTIVITY_STORAGE_KEY);
  } catch {
    // Non-fatal
  }
}

export function isSessionInactiveExceeded(
  inactivityTimeoutDays: number = DEFAULT_INACTIVITY_TIMEOUT_DAYS,
  nowMs: number = Date.now()
): boolean {
  const storage = getSafeStorage('local');
  if (!storage) return false;
  try {
    const raw = storage.getItem(LAST_ACTIVITY_STORAGE_KEY);
    if (!raw) return false;
    const lastMs = Number(raw);
    if (!Number.isFinite(lastMs) || lastMs <= 0) return false;
    const clampedDays = Math.max(1, Math.min(90, Math.floor(inactivityTimeoutDays || 14)));
    return nowMs - lastMs > clampedDays * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

export function validatePasswordStrength(password: string): PasswordStrengthResult {
  const raw = String(password || '');
  const trimmedLower = raw.trim().toLowerCase();
  const feedback: string[] = [];

  if (raw.length < 10) {
    feedback.push('Use at least 10 characters.');
  }

  const normalizedForCommonCheck = trimmedLower.replace(/[\s._-]+/g, '');
  if (
    COMMON_PASSWORDS.has(trimmedLower) ||
    COMMON_PASSWORDS.has(normalizedForCommonCheck) ||
    /^(.)\1{7,}$/.test(trimmedLower)
  ) {
    feedback.push('Avoid common or repeated passwords.');
  }

  const hasLower = /[a-z]/.test(raw);
  const hasUpper = /[A-Z]/.test(raw);
  const hasDigit = /\d/.test(raw);
  const hasSymbol = /[^a-zA-Z0-9]/.test(raw);
  const classCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  if (classCount < 3 && raw.length < 16) {
    feedback.push('Mix uppercase, lowercase, numbers, or symbols (or use a 16+ char passphrase).');
  }

  let scoreNum = 0;
  if (raw.length >= 10) scoreNum += 1;
  if (raw.length >= 14) scoreNum += 1;
  if (classCount >= 3) scoreNum += 1;
  if (classCount === 4 || raw.length >= 18) scoreNum += 1;

  if (feedback.some((f) => f.includes('common'))) {
    scoreNum = 1;
  }
  if (raw.length < 10) {
    scoreNum = Math.min(scoreNum, 1);
  }
  const score = Math.min(4, Math.max(0, scoreNum)) as 0 | 1 | 2 | 3 | 4;

  const labelMap: Record<0 | 1 | 2 | 3 | 4, PasswordStrengthResult['label']> = {
    0: 'Too Short',
    1: 'Weak',
    2: 'Fair',
    3: 'Good',
    4: 'Strong',
  };

  return {
    valid: raw.length >= 10 && feedback.length === 0,
    score,
    label: labelMap[score],
    feedback,
  };
}

export function resolvePostAuthDestination(params: {
  isNewUser: boolean;
  requiresEmailVerification: boolean;
  emailVerified: boolean;
  hasKeyBackup: boolean;
  keysUnlocked: boolean;
  onboardingCompleted: boolean;
}): PostAuthDestination {
  if (params.requiresEmailVerification && !params.emailVerified) {
    return 'verify_email';
  }
  if (!params.hasKeyBackup) {
    return 'key_setup';
  }
  if (!params.keysUnlocked) {
    return 'unlock_keys';
  }
  if (params.isNewUser || !params.onboardingCompleted) {
    return 'onboarding';
  }
  return 'dashboard';
}
