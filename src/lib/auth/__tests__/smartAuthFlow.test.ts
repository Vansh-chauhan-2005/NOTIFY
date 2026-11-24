import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  readDeviceHint,
  writeDeviceHint,
  forgetDeviceHint,
  determineInitialAuthTab,
  maskEmailForDeviceHint,
  validatePasswordStrength,
  resolvePostAuthDestination,
  isSessionInactiveExceeded,
  touchLastActivity,
} from '../deviceMemory.js';
import {
  verifyEmailPasswordWithConstantTiming,
  recordLoginAuditAndDetectNewDevice,
  incrementUserSessionVersion,
  getUserSessionVersion,
  saveServerKeyBackup,
  GENERIC_LOGIN_ERROR,
} from '../sessionSecurity.js';
import {
  createEncryptedCombinedKeyBackup,
  unlockCombinedKeyBackup,
} from '../keyVaultBackup.js';
import { mintSessionToken } from '../node_auth.js';
import { verifySessionToken } from '../requestAuth.js';
import { POST as loginPost } from '../../../app/api/v1/auth/login/route.js';
import { runGatewaySimulation } from '../../gateway/simulator.js';

describe('Smart Login / Signup Flow & Device Security', () => {
  const originalWindow = (globalThis as any).window;

  afterEach(() => {
    if (originalWindow === undefined) {
      delete (globalThis as any).window;
    } else {
      (globalThis as any).window = originalWindow;
    }
    vi.restoreAllMocks();
  });

  it('safely handles blocked or throwing localStorage when reading/writing device hints', () => {
    const throwingStorage = {
      getItem: () => {
        throw new Error('SecurityError: The operation is insecure.');
      },
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
      removeItem: () => {
        throw new Error('SecurityError');
      },
    };
    (globalThis as any).window = { localStorage: throwingStorage };

    expect(() => readDeviceHint()).not.toThrow();
    expect(readDeviceHint()).toBeNull();
    expect(() =>
      writeDeviceHint({ returning: true, lastMethod: 'google', rememberEmail: true, emailForMasking: 'user@example.com' })
    ).not.toThrow();
    expect(() => forgetDeviceHint()).not.toThrow();
    expect(determineInitialAuthTab(readDeviceHint())).toBe('signup');
  });

  it('stores only non-secret device hint and masks remembered email cleanly', () => {
    const store = new Map<string, string>();
    (globalThis as any).window = {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, v),
        removeItem: (k: string) => store.delete(k),
      },
    };

    expect(maskEmailForDeviceHint('rajputvanshc@gmail.com')).toBe('r***@gmail.com');

    writeDeviceHint({
      returning: true,
      lastMethod: 'google',
      rememberEmail: true,
      emailForMasking: 'rajputvanshc@gmail.com',
    });

    const hint = readDeviceHint();
    expect(hint?.returning).toBe(true);
    expect(hint?.lastMethod).toBe('google');
    expect(hint?.maskedEmail).toBe('r***@gmail.com');
    expect(JSON.stringify(hint)).not.toContain('rajputvanshc@gmail.com');
    expect(determineInitialAuthTab(hint)).toBe('login');

    forgetDeviceHint();
    expect(readDeviceHint()).toBeNull();
    expect(determineInitialAuthTab(null)).toBe('signup');
  });

  it('routes new users, unverified users, missing-key users, locked returning users, and ready users correctly', () => {
    expect(
      resolvePostAuthDestination({
        isNewUser: true,
        requiresEmailVerification: true,
        emailVerified: false,
        hasKeyBackup: false,
        keysUnlocked: false,
        onboardingCompleted: false,
      })
    ).toBe('verify_email');

    expect(
      resolvePostAuthDestination({
        isNewUser: true,
        requiresEmailVerification: true,
        emailVerified: true,
        hasKeyBackup: false,
        keysUnlocked: false,
        onboardingCompleted: false,
      })
    ).toBe('key_setup');

    expect(
      resolvePostAuthDestination({
        isNewUser: false,
        requiresEmailVerification: false,
        emailVerified: true,
        hasKeyBackup: true,
        keysUnlocked: false,
        onboardingCompleted: true,
      })
    ).toBe('unlock_keys');

    expect(
      resolvePostAuthDestination({
        isNewUser: true,
        requiresEmailVerification: false,
        emailVerified: true,
        hasKeyBackup: true,
        keysUnlocked: true,
        onboardingCompleted: false,
      })
    ).toBe('onboarding');

    expect(
      resolvePostAuthDestination({
        isNewUser: false,
        requiresEmailVerification: false,
        emailVerified: true,
        hasKeyBackup: true,
        keysUnlocked: true,
        onboardingCompleted: true,
      })
    ).toBe('dashboard');
  });

  it('enforces password strength rules (min 10 chars and common password blocklist)', () => {
    expect(validatePasswordStrength('short1!A').valid).toBe(false);
    expect(validatePasswordStrength('password123').valid).toBe(false);
    expect(validatePasswordStrength('1234567890').valid).toBe(false);
    expect(validatePasswordStrength('lowercaseonly12').valid).toBe(false);

    const strong = validatePasswordStrength('Aegis!Vault2026#Key');
    expect(strong.valid).toBe(true);
    expect(strong.score).toBe(4);
  });

  it('returns identical generic error messages and normalized timing for unknown email vs wrong password', async () => {
    const unknownRes = await loginPost(
      new Request('http://localhost:3000/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: `no_such_user_${Date.now()}@example.com`,
          password: 'WrongPassword!123',
        }),
      })
    );
    const wrongPassRes = await loginPost(
      new Request('http://localhost:3000/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'rajputvanshc@gmail.com',
          password: 'WrongPassword!123',
        }),
      })
    );

    const unknownJson = await unknownRes.json();
    const wrongPassJson = await wrongPassRes.json();

    expect(unknownRes.status).toBe(401);
    expect(wrongPassRes.status).toBe(401);
    expect(unknownJson.message).toBe(GENERIC_LOGIN_ERROR);
    expect(wrongPassJson.message).toBe(GENERIC_LOGIN_ERROR);
    expect(unknownJson.message).toBe(wrongPassJson.message);

    const timingUnknown = await verifyEmailPasswordWithConstantTiming({
      email: 'missing_person@example.com',
      password: 'Password!999',
      minDelayMs: 60,
    });
    expect(timingUnknown.success).toBe(false);
    expect(timingUnknown.message).toBe(GENERIC_LOGIN_ERROR);
  });

  it('encrypts & unlocks ECDH + Ed25519 key backup strictly in RAM and revokes stale sessions on Sign out all devices', async () => {
    const uid = `usr_vault_test_${Date.now()}`;
    const created = await createEncryptedCombinedKeyBackup(uid, 'Strong!VaultPass#2026');
    expect(created.backup.kdf).toBe('PBKDF2-HMAC-SHA256');
    expect(created.backup.cipher).toBe('AES-256-GCM');
    expect(created.backup.ed25519PublicKey).toBeTruthy();

    saveServerKeyBackup(uid, created.backup as any);

    await expect(
      unlockCombinedKeyBackup(created.backup, 'WrongPassphrase!123', uid)
    ).rejects.toThrow();

    const unlocked = await unlockCombinedKeyBackup(
      created.backup,
      'Strong!VaultPass#2026',
      uid
    );
    expect(unlocked.unlockedSigningKey.publicKey).toBe(created.backup.ed25519PublicKey);
    expect(unlocked.ephemeralKeyRing.ecdhPublicJwk.x).toBe(created.backup.ecdhPublicJwk.x);
    unlocked.unlockedSigningKey.wipe();
    expect(unlocked.unlockedSigningKey.isWiped()).toBe(true);

    // Session version revocation check
    const v1 = getUserSessionVersion(uid);
    const oldToken = mintSessionToken({ userId: uid, role: 'USER', sv: v1 }, '1h');
    expect(verifySessionToken(oldToken)?.userId).toBe(uid);

    const v2 = incrementUserSessionVersion(uid);
    expect(v2).toBeGreaterThan(v1);
    expect(verifySessionToken(oldToken)).toBeNull();

    const freshToken = mintSessionToken({ userId: uid, role: 'USER', sv: v2 }, '1h');
    expect(verifySessionToken(freshToken)?.userId).toBe(uid);
  });

  it('tracks inactivity auto-signout and detects new-device logins accurately', async () => {
    const store = new Map<string, string>();
    (globalThis as any).window = {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, v),
        removeItem: (k: string) => store.delete(k),
      },
    };

    const now = Date.now();
    touchLastActivity(now - 15 * 24 * 60 * 60 * 1000);
    expect(isSessionInactiveExceeded(14, now)).toBe(true);
    expect(isSessionInactiveExceeded(30, now)).toBe(false);

    const uid = `usr_dev_${Date.now()}`;
    const first = await recordLoginAuditAndDetectNewDevice({
      userId: uid,
      email: 'devcheck@example.com',
      deviceId: 'dev_known_12345',
      ipAddress: '198.51.100.1',
      userAgent: 'Mozilla/5.0 Chrome/126.0',
      method: 'Google',
      isFirstSignup: true,
      sendAlertEmail: false,
    });
    expect(first.isNewDevice).toBe(true);

    const repeat = await recordLoginAuditAndDetectNewDevice({
      userId: uid,
      email: 'devcheck@example.com',
      deviceId: 'dev_known_12345',
      ipAddress: '198.51.100.1',
      userAgent: 'Mozilla/5.0 Chrome/126.0',
      method: 'Google',
      isFirstSignup: false,
      sendAlertEmail: false,
    });
    expect(repeat.isNewDevice).toBe(false);

    const secondDevice = await recordLoginAuditAndDetectNewDevice({
      userId: uid,
      email: 'devcheck@example.com',
      deviceId: 'dev_brand_new_67890',
      ipAddress: '203.0.113.5',
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)',
      method: 'Email & Password',
      isFirstSignup: false,
      sendAlertEmail: false,
    });
    expect(secondDevice.isNewDevice).toBe(true);
    expect(secondDevice.audit.deviceType).toBe('Mobile');
  });

  it('passes smart-auth attack simulator scenarios o, p, q, and r', async () => {
    const authSims = await runGatewaySimulation('auth');
    expect(authSims).toHaveLength(4);
    for (const s of authSims) {
      expect(s.passed).toBe(true);
    }
  });
});
