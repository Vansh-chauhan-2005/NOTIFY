'use client';

import React, { useState, useEffect } from 'react';
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  KeyRound,
  User as UserIcon,
  Sparkles,
  Smartphone,
} from 'lucide-react';
import { AegisGlyphLogo } from './NothingLogos.js';
import LoginPage from './LoginPage.js';
import {
  auth,
  googleAuthProvider,
  signInWithPopup,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  getAdditionalUserInfo,
  getMultiFactorResolver,
  TotpMultiFactorGenerator,
  applyFirebaseAuthPersistence,
  saveSmartSecuritySettingsToFirestore,
  saveEncryptedKeyBackupToFirestore,
  loadEncryptedKeyBackupFromFirestore,
  loadSmartAccountStateFromFirestore,
  recordLoginAuditToFirestore,
} from '../lib/firebase/client.js';
import {
  readDeviceHint,
  writeDeviceHint,
  forgetDeviceHint,
  getOrCreateDeviceId,
  determineInitialAuthTab,
  readKeepSignedInPreference,
  writeKeepSignedInPreference,
  touchLastActivity,
  validatePasswordStrength,
  type DeviceMemoryHint,
  type DeviceAuthMethod,
} from '../lib/auth/deviceMemory.js';
import {
  createEncryptedCombinedKeyBackup,
  type EncryptedCombinedKeyBackup,
} from '../lib/auth/keyVaultBackup.js';
import type { UnlockedSigningKey } from '../lib/provenance/browserCrypto.js';
import type { EphemeralSessionKeyRing } from '../lib/ephemeral/crypto.js';
import { safeReadJson } from '../lib/http/safeJson.js';

export interface SmartAuthCompletedPayload {
  user: {
    id: string;
    firebaseUid?: string;
    phoneNumber?: string;
    email?: string;
    displayName?: string;
    emailVerified?: boolean;
    role: string;
  };
  token: string;
  isNewUser: boolean;
  isNewDevice: boolean;
  onboardingCompleted: boolean;
  emailVerified: boolean;
  requiresEmailVerification: boolean;
  inactivityTimeoutDays: number;
  hasKeyBackup: boolean;
  keyBackup: EncryptedCombinedKeyBackup | null;
  unlockedSigningKey: UnlockedSigningKey | null;
  ephemeralKeyRing: EphemeralSessionKeyRing | null;
}

interface SmartAuthFlowProps {
  onAuthComplete: (payload: SmartAuthCompletedPayload) => void;
  initialStep?: 'auth' | 'verify_email' | 'key_setup';
  pendingContext?: SmartAuthCompletedPayload | null;
}

type AuthTab = 'login' | 'signup' | 'otp_legacy';
type FlowStep = 'auth' | 'verify_email' | 'key_setup';

const GENERIC_LOGIN_ERROR = 'Email or password is incorrect.';
const RESET_CONFIRMATION_MSG =
  'If an account exists for that address, we sent a password reset email.';

export default function SmartAuthFlow({
  onAuthComplete,
  initialStep = 'auth',
  pendingContext = null,
}: SmartAuthFlowProps) {
  const [deviceHint, setDeviceHint] = useState<DeviceMemoryHint | null>(null);
  const [activeTab, setActiveTab] = useState<AuthTab>('signup');
  const [step, setStep] = useState<FlowStep>(initialStep);
  const [sessionState, setSessionState] = useState<SmartAuthCompletedPayload | null>(
    pendingContext
  );

  // Common preferences
  const [keepSignedIn, setKeepSignedIn] = useState<boolean>(true);
  const [rememberEmail, setRememberEmail] = useState<boolean>(false);

  // Login fields
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [showLoginPass, setShowLoginPass] = useState(false);

  // Signup fields
  const [signupName, setSignupName] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupConfirm, setSignupConfirm] = useState('');
  const [showSignupPass, setShowSignupPass] = useState(false);
  const [acceptedTerms, setAcceptedTerms] = useState(false);

  // Forgot password drawer
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [resetEmail, setResetEmail] = useState('');

  // TOTP Multi-Factor prompt (if enabled on account)
  const [mfaResolver, setMfaResolver] = useState<any>(null);
  const [totpCode, setTotpCode] = useState('');

  // Email verification resend cooldown (60s)
  const [verifyCooldown, setVerifyCooldown] = useState(0);

  // Key setup fields
  const [keyPassphrase, setKeyPassphrase] = useState('');
  const [keyPassConfirm, setKeyPassConfirm] = useState('');
  const [showKeyPass, setShowKeyPass] = useState(false);

  // UI feedback
  const [isBusy, setIsBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);

  useEffect(() => {
    const hint = readDeviceHint();
    setDeviceHint(hint);
    setActiveTab(determineInitialAuthTab(hint));
    setRememberEmail(Boolean(hint?.rememberEmail));
    setKeepSignedIn(readKeepSignedInPreference());

    if (hint?.returning) {
      void fetch('/api/v1/auth/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventType: 'RETURNING_DEVICE_DETECTED',
          method: hint.lastMethod || 'unknown',
          details: `Returning device hint detected (${hint.lastMethod || 'saved'}).`,
        }),
      }).catch(() => null);
    }
  }, []);

  useEffect(() => {
    if (verifyCooldown <= 0) return;
    const t = setInterval(() => {
      setVerifyCooldown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(t);
  }, [verifyCooldown]);

  const signupStrength = validatePasswordStrength(signupPassword);
  const keyPassStrength = validatePasswordStrength(keyPassphrase);

  const handleForgetDevice = () => {
    forgetDeviceHint();
    setDeviceHint(null);
    setRememberEmail(false);
    setActiveTab('signup');
    setInfoMsg('Device memory cleared.');
    setErrorMsg(null);
  };

  const logAuthTelemetry = async (
    eventType: 'SIGNUP_STARTED' | 'SIGNUP_COMPLETED' | 'LOGIN_FAILED',
    method: string,
    details: string
  ) => {
    try {
      await fetch('/api/v1/auth/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eventType, method, details }),
      });
    } catch {
      // Non-fatal
    }
  };

  const finalizeFirebaseExchange = async (params: {
    firebaseIdToken: string;
    isNewUser: boolean;
    method: DeviceAuthMethod;
    methodLabel: string;
    emailForHint?: string;
    requireVerificationForPassword?: boolean;
  }) => {
    const deviceId = getOrCreateDeviceId();
    const res = await fetch('/api/v1/auth/firebase/session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Aegis-Device-Id': deviceId,
      },
      body: JSON.stringify({
        firebaseIdToken: params.firebaseIdToken,
        isNewUser: params.isNewUser,
        method: params.methodLabel,
        deviceId,
        keepSignedIn,
      }),
    });

    const json = await safeReadJson(res);
    if (!res.ok || !json?.success || !json?.data?.token || !json?.data?.user) {
      throw new Error(json?.message || 'Unable to verify authentication session.');
    }

    const data = json.data;
    const fbUser = auth.currentUser;

    // Persist non-secret device hint & token
    writeKeepSignedInPreference(keepSignedIn);
    writeDeviceHint({
      returning: true,
      lastMethod: params.method,
      rememberEmail,
      emailForMasking: params.emailForHint || data.user.email,
    });
    touchLastActivity();

    try {
      localStorage.setItem('aegis_auth_token', data.token);
      localStorage.setItem('aegis_user', JSON.stringify(data.user));
    } catch {
      // Ignore restricted storage
    }

    // Check Firestore for persistent state (keyBackup + onboardingCompleted)
    let firestoreAccountState = null;
    let firestoreBackup: EncryptedCombinedKeyBackup | null = null;
    if (fbUser) {
      [firestoreAccountState, firestoreBackup] = await Promise.all([
        loadSmartAccountStateFromFirestore(fbUser.uid).catch(() => null),
        loadEncryptedKeyBackupFromFirestore(fbUser.uid).catch(() => null),
      ]);

      await saveSmartSecuritySettingsToFirestore(fbUser.uid, {
        authProvider: params.method === 'google' ? 'google' : params.method === 'sms' ? 'phone' : 'password',
        authMethods: data.authMethods,
        emailVerified: Boolean(data.emailVerified),
        ...(data.user.email ? { email: data.user.email } : {}),
        ...(data.user.displayName ? { displayName: data.user.displayName } : {}),
      }).catch(() => {});

      if (data.loginAudit) {
        await recordLoginAuditToFirestore(fbUser.uid, data.loginAudit).catch(() => {});
      }
    }

    const effectiveKeyBackup: EncryptedCombinedKeyBackup | null =
      (data.keyBackup as EncryptedCombinedKeyBackup | null) || firestoreBackup;

    const payload: SmartAuthCompletedPayload = {
      user: data.user,
      token: data.token,
      isNewUser: Boolean(data.isNewUser || params.isNewUser),
      isNewDevice: Boolean(data.isNewDevice),
      onboardingCompleted: Boolean(
        data.onboardingCompleted || firestoreAccountState?.onboardingCompleted
      ),
      emailVerified: Boolean(data.emailVerified),
      requiresEmailVerification: Boolean(
        params.requireVerificationForPassword && !data.emailVerified
      ),
      inactivityTimeoutDays: Number(
        firestoreAccountState?.inactivityTimeoutDays || data.inactivityTimeoutDays || 14
      ),
      hasKeyBackup: Boolean(effectiveKeyBackup),
      keyBackup: effectiveKeyBackup,
      unlockedSigningKey: null,
      ephemeralKeyRing: null,
    };

    setSessionState(payload);

    if (payload.requiresEmailVerification) {
      setStep('verify_email');
      return;
    }

    if (!payload.hasKeyBackup) {
      setStep('key_setup');
      return;
    }

    onAuthComplete(payload);
  };

  const handleGoogleAuth = async (intent: 'login' | 'signup') => {
    if (isBusy) return;
    setErrorMsg(null);
    setInfoMsg(null);
    setIsBusy(true);

    if (intent === 'signup') {
      void logAuthTelemetry('SIGNUP_STARTED', 'google', 'Google signup initiated.');
    }

    try {
      await applyFirebaseAuthPersistence(keepSignedIn);
      const cred = await signInWithPopup(auth, googleAuthProvider);
      const extra = getAdditionalUserInfo(cred);
      const isNewUser = Boolean(extra?.isNewUser);
      const idToken = await cred.user.getIdToken(true);

      await finalizeFirebaseExchange({
        firebaseIdToken: idToken,
        isNewUser,
        method: 'google',
        methodLabel: 'Google',
        emailForHint: cred.user.email || undefined,
      });
    } catch (err: any) {
      const code = String(err?.code || '');
      if (code === 'auth/account-exists-with-different-credential') {
        setErrorMsg(
          'An account with this email already exists using another sign-in method. Sign in with your original method first, then link Google from Settings.'
        );
      } else if (code === 'auth/popup-closed-by-user') {
        setErrorMsg('Google sign-in popup was closed before completing.');
      } else {
        setErrorMsg(err?.message || 'Google sign-in failed.');
      }
      void logAuthTelemetry('LOGIN_FAILED', 'google', 'Google sign-in did not complete.');
    } finally {
      setIsBusy(false);
    }
  };

  const handleEmailSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isBusy) return;
    setErrorMsg(null);
    setInfoMsg(null);

    const cleanName = signupName.trim();
    const cleanEmail = signupEmail.trim().toLowerCase();
    if (cleanName.length < 2) {
      setErrorMsg('Please enter your full name.');
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setErrorMsg('Please enter a valid email address.');
      return;
    }
    if (!signupStrength.valid) {
      setErrorMsg(signupStrength.feedback[0] || 'Please choose a stronger password.');
      return;
    }
    if (signupPassword !== signupConfirm) {
      setErrorMsg('Passwords do not match.');
      return;
    }
    if (!acceptedTerms) {
      setErrorMsg('Please accept the Terms & Zero-Trust Privacy Policy to create an account.');
      return;
    }

    setIsBusy(true);
    void logAuthTelemetry('SIGNUP_STARTED', 'email_password', 'Email & password signup started.');

    try {
      await applyFirebaseAuthPersistence(keepSignedIn);
      const cred = await createUserWithEmailAndPassword(auth, cleanEmail, signupPassword);
      await updateProfile(cred.user, { displayName: cleanName }).catch(() => {});
      await sendEmailVerification(cred.user).catch(() => {});
      setVerifyCooldown(60);

      const idToken = await cred.user.getIdToken(true);
      await finalizeFirebaseExchange({
        firebaseIdToken: idToken,
        isNewUser: true,
        method: 'email',
        methodLabel: 'Email & Password',
        emailForHint: cleanEmail,
        requireVerificationForPassword: true,
      });
    } catch (err: any) {
      const code = String(err?.code || '');
      if (
        code === 'auth/email-already-in-use' ||
        code === 'auth/account-exists-with-different-credential'
      ) {
        // Generic / non-enumerating actionable message without auto-merging
        setErrorMsg(
          'Unable to complete signup with those details. If you already have an account, switch to Log in or use your original sign-in method.'
        );
      } else if (code === 'auth/operation-not-allowed') {
        setErrorMsg(
          'Email/Password sign-up is disabled in Firebase Console. Enable Email/Password under Authentication → Sign-in method, or use Google / Email OTP.'
        );
      } else {
        setErrorMsg(err?.message || 'Unable to create account.');
      }
    } finally {
      setIsBusy(false);
    }
  };

  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isBusy) return;
    setErrorMsg(null);
    setInfoMsg(null);

    const startedAt = Date.now();
    const cleanEmail = loginEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || !loginPassword) {
      setErrorMsg(GENERIC_LOGIN_ERROR);
      return;
    }

    setIsBusy(true);
    try {
      await applyFirebaseAuthPersistence(keepSignedIn);
      try {
        const cred = await signInWithEmailAndPassword(auth, cleanEmail, loginPassword);
        const idToken = await cred.user.getIdToken(true);
        await finalizeFirebaseExchange({
          firebaseIdToken: idToken,
          isNewUser: false,
          method: 'email',
          methodLabel: 'Email & Password',
          emailForHint: cleanEmail,
          requireVerificationForPassword: true,
        });
        return;
      } catch (fbErr: any) {
        const code = String(fbErr?.code || '');
        if (code === 'auth/multi-factor-auth-required') {
          const resolver = getMultiFactorResolver(auth, fbErr);
          setMfaResolver(resolver);
          setInfoMsg('Enter the 6-digit code from your authenticator app to continue.');
          return;
        }
        if (code === 'auth/too-many-requests') {
          setErrorMsg('Too many failed attempts. Please wait before trying again.');
          return;
        }

        // Fall back to existing backend credential check (e.g., admin / node_auth seeded accounts)
        const deviceId = getOrCreateDeviceId();
        const backendRes = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Aegis-Device-Id': deviceId,
          },
          body: JSON.stringify({ email: cleanEmail, password: loginPassword }),
        });
        const backendJson = await safeReadJson(backendRes);

        if (backendRes.ok && backendJson?.success && backendJson?.token && backendJson?.user) {
          writeKeepSignedInPreference(keepSignedIn);
          writeDeviceHint({
            returning: true,
            lastMethod: 'email',
            rememberEmail,
            emailForMasking: cleanEmail,
          });
          touchLastActivity();
          try {
            localStorage.setItem('aegis_auth_token', backendJson.token);
            localStorage.setItem('aegis_user', JSON.stringify(backendJson.user));
          } catch {}

          // Check if server has an encrypted key backup
          let keyBackup: EncryptedCombinedKeyBackup | null = null;
          try {
            const kbRes = await fetch('/api/v1/auth/keys-backup', {
              headers: { Authorization: `Bearer ${backendJson.token}` },
            });
            const kbJson = await safeReadJson(kbRes);
            if (kbJson?.success && kbJson?.data?.backup) {
              keyBackup = kbJson.data.backup;
            }
          } catch {}

          const payload: SmartAuthCompletedPayload = {
            user: backendJson.user,
            token: backendJson.token,
            isNewUser: false,
            isNewDevice: Boolean(backendJson?.data?.isNewDevice),
            onboardingCompleted: true,
            emailVerified: true,
            requiresEmailVerification: false,
            inactivityTimeoutDays: 14,
            hasKeyBackup: Boolean(keyBackup),
            keyBackup,
            unlockedSigningKey: null,
            ephemeralKeyRing: null,
          };
          setSessionState(payload);
          if (!payload.hasKeyBackup) {
            setStep('key_setup');
          } else {
            onAuthComplete(payload);
          }
          return;
        }

        if (backendRes.status === 429) {
          setErrorMsg(backendJson?.message || 'Too many failed attempts. Please wait and retry.');
          return;
        }

        // Normalize timing floor so unknown email and wrong password behave identically
        const elapsed = Date.now() - startedAt;
        if (elapsed < 220) {
          await new Promise((r) => setTimeout(r, 220 - elapsed));
        }

        void logAuthTelemetry('LOGIN_FAILED', 'email_password', 'Generic login rejection issued.');
        setErrorMsg(GENERIC_LOGIN_ERROR);
      }
    } finally {
      setIsBusy(false);
    }
  };

  const handleVerifyTotpChallenge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaResolver || isBusy) return;
    setErrorMsg(null);
    setIsBusy(true);
    try {
      const totpHint = mfaResolver.hints.find(
        (h: any) => h.factorId === TotpMultiFactorGenerator.FACTOR_ID
      );
      if (!totpHint) {
        throw new Error('No TOTP authenticator factor found for this account.');
      }
      const assertion = TotpMultiFactorGenerator.assertionForSignIn(
        totpHint.uid,
        totpCode.trim()
      );
      const cred = await mfaResolver.resolveSignIn(assertion);
      const idToken = await cred.user.getIdToken(true);
      setMfaResolver(null);
      setTotpCode('');
      await finalizeFirebaseExchange({
        firebaseIdToken: idToken,
        isNewUser: false,
        method: 'email',
        methodLabel: 'Email + TOTP',
        emailForHint: cred.user.email || undefined,
        requireVerificationForPassword: true,
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Invalid authenticator code.');
    } finally {
      setIsBusy(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isBusy) return;
    setErrorMsg(null);
    setInfoMsg(null);

    const target = resetEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) {
      setErrorMsg('Enter a valid email address.');
      return;
    }

    setIsBusy(true);
    try {
      await sendPasswordResetEmail(auth, target).catch(() => {});
      // Always show identical generic confirmation to prevent account enumeration
      setInfoMsg(RESET_CONFIRMATION_MSG);
      setShowForgotPassword(false);
    } finally {
      setIsBusy(false);
    }
  };

  const handleCheckEmailVerified = async () => {
    if (isBusy || !auth.currentUser) return;
    setIsBusy(true);
    setErrorMsg(null);
    setInfoMsg(null);

    try {
      await auth.currentUser.reload();
      if (!auth.currentUser.emailVerified) {
        setErrorMsg('Your email is not verified yet. Check your inbox and spam folder, then try again.');
        return;
      }

      const freshToken = await auth.currentUser.getIdToken(true);
      await finalizeFirebaseExchange({
        firebaseIdToken: freshToken,
        isNewUser: Boolean(sessionState?.isNewUser),
        method: 'email',
        methodLabel: 'Email & Password',
        emailForHint: auth.currentUser.email || undefined,
        requireVerificationForPassword: true,
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Unable to check verification status.');
    } finally {
      setIsBusy(false);
    }
  };

  const handleResendVerification = async () => {
    if (verifyCooldown > 0 || !auth.currentUser || isBusy) return;
    setIsBusy(true);
    setErrorMsg(null);
    setInfoMsg(null);
    try {
      await sendEmailVerification(auth.currentUser);
      setVerifyCooldown(60);
      setInfoMsg('Verification email sent. Please click the link inside your inbox.');
    } catch (err: any) {
      setErrorMsg(err?.message || 'Unable to resend verification email right now.');
    } finally {
      setIsBusy(false);
    }
  };

  const handleCompleteKeySetup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isBusy || !sessionState) return;
    setErrorMsg(null);
    setInfoMsg(null);

    if (!keyPassStrength.valid) {
      setErrorMsg(keyPassStrength.feedback[0] || 'Choose a stronger encryption passphrase.');
      return;
    }
    if (keyPassphrase !== keyPassConfirm) {
      setErrorMsg('Encryption passphrases do not match.');
      return;
    }

    setIsBusy(true);
    try {
      const uid = sessionState.user.id;
      const created = await createEncryptedCombinedKeyBackup(uid, keyPassphrase);

      const backupRes = await fetch('/api/v1/auth/keys-backup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${sessionState.token}`,
        },
        body: JSON.stringify(created.backup),
      });
      const backupJson = await safeReadJson(backupRes);
      if (!backupRes.ok || !backupJson?.success) {
        throw new Error(backupJson?.message || 'Unable to store encrypted key backup.');
      }

      // Register public keys with server provenance + ephemeral key directory
      await Promise.all([
        fetch('/api/v1/provenance/keys', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${sessionState.token}`,
          },
          body: JSON.stringify({
            publicKey: created.backup.ed25519PublicKey,
            kid: created.backup.ed25519Kid,
            label: 'Primary Browser Key',
          }),
        }).catch(() => null),
        fetch('/api/v1/ephemeral/public-key', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${sessionState.token}`,
          },
          body: JSON.stringify({
            ecdhPublicJwk: created.backup.ecdhPublicJwk,
            ecdsaPublicJwk: created.backup.ecdsaPublicJwk,
          }),
        }).catch(() => null),
      ]);

      if (auth.currentUser && auth.currentUser.uid === uid) {
        await saveEncryptedKeyBackupToFirestore(uid, created.backup).catch(() => {});
        await saveSmartSecuritySettingsToFirestore(uid, { keySetupCompleted: true }).catch(
          () => {}
        );
      }

      setKeyPassphrase('');
      setKeyPassConfirm('');

      onAuthComplete({
        ...sessionState,
        hasKeyBackup: true,
        keyBackup: created.backup,
        unlockedSigningKey: created.unlockedSigningKey,
        ephemeralKeyRing: created.ephemeralKeyRing,
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Unable to set up encryption keys.');
    } finally {
      setIsBusy(false);
    }
  };

  // Legacy Email OTP / SMS OTP / Admin Key wrapper
  if (activeTab === 'otp_legacy' && step === 'auth') {
    return (
      <div className="min-h-screen bg-[#0D0D14]">
        <div className="max-w-5xl mx-auto px-4 pt-5 flex items-center justify-between">
          <button
            type="button"
            onClick={() => setActiveTab(deviceHint?.returning ? 'login' : 'signup')}
            className="px-4 py-2 rounded-xl bg-[#16161D] border border-[#2C2B38] text-xs font-semibold text-[#FAF6F0] hover:border-[#D9468F]"
          >
            ← Back to Smart Login / Signup
          </button>
          <span className="text-xs text-[#9A96A6]">OTP &amp; Admin Gateway Mode</span>
        </div>
        <LoginPage
          onLoginSuccess={(legacyUser) => {
            const token = localStorage.getItem('aegis_auth_token') || '';
            writeDeviceHint({
              returning: true,
              lastMethod: legacyUser.phoneNumber ? 'sms' : 'email',
              rememberEmail,
              emailForMasking: legacyUser.email,
            });
            touchLastActivity();
            onAuthComplete({
              user: legacyUser,
              token,
              isNewUser: false,
              isNewDevice: false,
              onboardingCompleted: true,
              emailVerified: true,
              requiresEmailVerification: false,
              inactivityTimeoutDays: 14,
              hasKeyBackup: false,
              keyBackup: null,
              unlockedSigningKey: null,
              ephemeralKeyRing: null,
            });
          }}
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0D0D14] text-[#FAF6F0] flex flex-col items-center justify-center px-4 py-8 sm:py-12 font-sans">
      <div className="w-full max-w-md rounded-3xl bg-[#16161D] border border-[#2C2B38] shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Brand Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AegisGlyphLogo className="w-9 h-9 text-[#D9468F]" />
            <div>
              <h1 className="font-display text-lg font-bold tracking-tight text-[#FAF6F0]">
                AegisNotify
              </h1>
              <p className="text-[11px] text-[#9A96A6]">
                Zero-Trust Encrypted Notification Engine
              </p>
            </div>
          </div>
          {step === 'auth' && (
            <button
              type="button"
              onClick={() => setActiveTab('otp_legacy')}
              className="text-[11px] font-semibold text-[#F472B6] hover:text-[#F9A8D4] px-2.5 py-1.5 rounded-lg bg-[#1E1E28] border border-[#2C2B38] flex items-center space-x-1"
            >
              <Smartphone className="w-3 h-3" />
              <span>OTP / Admin</span>
            </button>
          )}
        </div>

        {/* Step 2A: Email Verification Gate */}
        {step === 'verify_email' && (
          <div className="space-y-5">
            <div className="rounded-2xl bg-[#1E1E28] border border-[#2C2B38] p-4 space-y-2">
              <div className="flex items-center space-x-2 text-[#F472B6]">
                <Mail className="w-4 h-4" />
                <h2 className="font-display text-sm font-bold text-[#FAF6F0]">
                  Verify your email address
                </h2>
              </div>
              <p className="text-xs text-[#C6C3D0] leading-relaxed">
                We sent a verification link to{' '}
                <span className="font-semibold text-[#FAF6F0]">
                  {sessionState?.user.email || 'your email'}
                </span>
                . Email verification is required before creating encryption keys or reading encrypted messages.
              </p>
            </div>

            {errorMsg && (
              <div
                role="alert"
                aria-live="polite"
                className="rounded-2xl bg-red-950/60 border border-red-700/70 px-4 py-3 text-xs text-red-200 flex items-start space-x-2"
              >
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            {infoMsg && (
              <div
                role="status"
                aria-live="polite"
                className="rounded-2xl bg-emerald-950/50 border border-emerald-700/60 px-4 py-3 text-xs text-emerald-200 flex items-start space-x-2"
              >
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
                <span>{infoMsg}</span>
              </div>
            )}

            <button
              type="button"
              disabled={isBusy}
              onClick={() => void handleCheckEmailVerified()}
              className="w-full py-3 px-4 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {isBusy ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <CheckCircle2 className="w-4 h-4" />
              )}
              <span>I&apos;ve verified — Continue</span>
            </button>

            <button
              type="button"
              disabled={isBusy || verifyCooldown > 0}
              onClick={() => void handleResendVerification()}
              className="w-full py-2.5 px-4 rounded-xl border border-[#343342] text-xs font-semibold text-[#C6C3D0] hover:bg-[#1E1E28] disabled:opacity-50"
            >
              {verifyCooldown > 0
                ? `Resend verification email (${verifyCooldown}s)`
                : 'Resend verification email'}
            </button>
          </div>
        )}

        {/* Step 2B: Key Setup Step */}
        {step === 'key_setup' && (
          <form onSubmit={handleCompleteKeySetup} className="space-y-4">
            <div className="space-y-1">
              <h2 className="font-display text-base font-bold text-[#FAF6F0] flex items-center space-x-2">
                <KeyRound className="w-4 h-4 text-[#F472B6]" />
                <span>Set up your encryption keys</span>
              </h2>
              <p className="text-xs text-[#9A96A6] leading-relaxed">
                Your ECDH and Ed25519 keys are generated in your browser and encrypted with a separate passphrase using PBKDF2-HMAC-SHA256 + AES-256-GCM.
              </p>
            </div>

            <div className="rounded-2xl bg-amber-950/50 border border-amber-700/70 p-3.5 text-xs text-amber-200 flex items-start space-x-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
              <p className="leading-relaxed">
                <strong className="text-amber-100">Warning:</strong> Your encryption passphrase is never sent to our servers and{' '}
                <strong className="text-amber-100">cannot be recovered</strong> if you forget it. Save it in a password manager.
              </p>
            </div>

            {errorMsg && (
              <div
                role="alert"
                aria-live="polite"
                className="rounded-2xl bg-red-950/60 border border-red-700/70 px-4 py-3 text-xs text-red-200"
              >
                {errorMsg}
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="key-setup-pass" className="block text-xs font-semibold text-[#E5E1D8]">
                Encryption Passphrase (separate from login password)
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="key-setup-pass"
                  type={showKeyPass ? 'text' : 'password'}
                  value={keyPassphrase}
                  onChange={(e) => setKeyPassphrase(e.target.value)}
                  placeholder="Min 10 chars, unique passphrase"
                  className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] focus:outline-none focus:border-[#D9468F]"
                />
                <button
                  type="button"
                  onClick={() => setShowKeyPass((v) => !v)}
                  aria-label={showKeyPass ? 'Hide passphrase' : 'Show passphrase'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8E8A9B] hover:text-[#FAF6F0]"
                >
                  {showKeyPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#9A96A6]">Strength: {keyPassStrength.label}</span>
                {keyPassStrength.feedback[0] && (
                  <span className="text-amber-300">{keyPassStrength.feedback[0]}</span>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="key-setup-confirm" className="block text-xs font-semibold text-[#E5E1D8]">
                Confirm Encryption Passphrase
              </label>
              <input
                id="key-setup-confirm"
                type={showKeyPass ? 'text' : 'password'}
                value={keyPassConfirm}
                onChange={(e) => setKeyPassConfirm(e.target.value)}
                placeholder="Re-enter encryption passphrase"
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] focus:outline-none focus:border-[#D9468F]"
              />
            </div>

            <button
              type="submit"
              disabled={isBusy}
              className="w-full py-3 px-4 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {isBusy ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Generating &amp; Backing Up Keys...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Generate Keys &amp; Continue</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Step 1: Unified Login / Signup Card */}
        {step === 'auth' && (
          <>
            {/* Returning Device Hint Banner */}
            {deviceHint?.returning && (
              <div className="rounded-2xl bg-[#1E1E28] border border-[#D9468F]/40 px-4 py-3 flex items-center justify-between gap-2">
                <div className="text-xs">
                  <p className="font-semibold text-[#FAF6F0] flex items-center space-x-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-[#F472B6]" />
                    <span>Welcome back</span>
                  </p>
                  <p className="text-[11px] text-[#B8B4C4] mt-0.5">
                    Last signed in via{' '}
                    <span className="font-semibold text-[#F472B6] uppercase">
                      {deviceHint.lastMethod || 'saved'}
                    </span>
                    {deviceHint.maskedEmail ? ` (${deviceHint.maskedEmail})` : ''}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleForgetDevice}
                  className="text-[11px] text-[#9A96A6] hover:text-[#FAF6F0] underline whitespace-nowrap"
                >
                  Not you? Forget this device
                </button>
              </div>
            )}

            {/* Login / Signup Tabs */}
            <div
              role="tablist"
              aria-label="Authentication mode"
              className="grid grid-cols-2 p-1 rounded-2xl bg-[#1E1E28] border border-[#2C2B38]"
            >
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'login'}
                onClick={() => {
                  setActiveTab('login');
                  setErrorMsg(null);
                  setInfoMsg(null);
                }}
                className={`py-2 text-xs font-semibold rounded-xl transition ${
                  activeTab === 'login'
                    ? 'bg-[#D9468F] text-white shadow'
                    : 'text-[#B8B4C4] hover:text-white'
                }`}
              >
                Log in
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'signup'}
                onClick={() => {
                  setActiveTab('signup');
                  setErrorMsg(null);
                  setInfoMsg(null);
                }}
                className={`py-2 text-xs font-semibold rounded-xl transition ${
                  activeTab === 'signup'
                    ? 'bg-[#D9468F] text-white shadow'
                    : 'text-[#B8B4C4] hover:text-white'
                }`}
              >
                Create account
              </button>
            </div>

            {errorMsg && (
              <div
                role="alert"
                aria-live="polite"
                className="rounded-2xl bg-red-950/60 border border-red-700/70 px-4 py-3 text-xs text-red-200 flex items-start space-x-2"
              >
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{errorMsg}</span>
              </div>
            )}

            {infoMsg && (
              <div
                role="status"
                aria-live="polite"
                className="rounded-2xl bg-emerald-950/50 border border-emerald-700/60 px-4 py-3 text-xs text-emerald-200 flex items-start space-x-2"
              >
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
                <span>{infoMsg}</span>
              </div>
            )}

            {/* TOTP Challenge Modal */}
            {mfaResolver ? (
              <form onSubmit={handleVerifyTotpChallenge} className="space-y-4">
                <div className="space-y-1.5">
                  <label htmlFor="mfa-totp-code" className="block text-xs font-semibold text-[#E5E1D8]">
                    Authenticator App 6-digit Code
                  </label>
                  <input
                    id="mfa-totp-code"
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="w-full px-4 py-3 rounded-xl bg-[#1E1E28] border border-[#343342] text-center font-mono-tech text-lg tracking-widest text-[#FAF6F0]"
                  />
                </div>
                <button
                  type="submit"
                  disabled={isBusy || totpCode.length < 6}
                  className="w-full py-3 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold disabled:opacity-50"
                >
                  {isBusy ? 'Verifying...' : 'Verify Authenticator Code'}
                </button>
              </form>
            ) : showForgotPassword ? (
              <form onSubmit={handleForgotPassword} className="space-y-4">
                <div className="space-y-1">
                  <h2 className="text-sm font-bold text-[#FAF6F0]">Reset password</h2>
                  <p className="text-xs text-[#9A96A6]">
                    Enter your email address and we will send reset instructions if an account exists.
                  </p>
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="forgot-email" className="block text-xs font-semibold text-[#E5E1D8]">
                    Email Address
                  </label>
                  <input
                    id="forgot-email"
                    type="email"
                    value={resetEmail}
                    onChange={(e) => setResetEmail(e.target.value)}
                    placeholder="you@example.com"
                    className="w-full px-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0]"
                  />
                </div>
                <div className="flex space-x-2">
                  <button
                    type="button"
                    onClick={() => setShowForgotPassword(false)}
                    className="flex-1 py-2.5 rounded-xl border border-[#343342] text-xs font-semibold text-[#C6C3D0]"
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    disabled={isBusy}
                    className="flex-1 py-2.5 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-xs font-semibold text-white disabled:opacity-50"
                  >
                    {isBusy ? 'Sending...' : 'Send reset email'}
                  </button>
                </div>
              </form>
            ) : activeTab === 'login' ? (
              <div className="space-y-4">
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => void handleGoogleAuth('login')}
                  className={`w-full py-2.5 px-4 rounded-xl bg-white hover:bg-gray-100 text-[#16161D] text-sm font-semibold flex items-center justify-center space-x-2 transition disabled:opacity-50 ${
                    deviceHint?.lastMethod === 'google' ? 'ring-2 ring-[#D9468F]' : ''
                  }`}
                >
                  <span>Continue with Google</span>
                </button>

                <div className="relative flex items-center py-1">
                  <div className="flex-grow border-t border-[#2C2B38]" />
                  <span className="px-3 text-[11px] uppercase tracking-wider text-[#8E8A9B]">
                    or email
                  </span>
                  <div className="flex-grow border-t border-[#2C2B38]" />
                </div>

                <form onSubmit={handleEmailLogin} className="space-y-3.5">
                  <div className="space-y-1.5">
                    <label htmlFor="login-email" className="block text-xs font-semibold text-[#E5E1D8]">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        id="login-email"
                        type="email"
                        value={loginEmail}
                        onChange={(e) => setLoginEmail(e.target.value)}
                        autoComplete="email"
                        placeholder={deviceHint?.maskedEmail || 'you@example.com'}
                        className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label htmlFor="login-password" className="block text-xs font-semibold text-[#E5E1D8]">
                        Password
                      </label>
                      <button
                        type="button"
                        onClick={() => {
                          setShowForgotPassword(true);
                          setResetEmail(loginEmail);
                          setErrorMsg(null);
                        }}
                        className="text-[11px] text-[#F472B6] hover:text-[#F9A8D4]"
                      >
                        Forgot password?
                      </button>
                    </div>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        id="login-password"
                        type={showLoginPass ? 'text' : 'password'}
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        autoComplete="current-password"
                        placeholder="Enter password"
                        className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                      />
                      <button
                        type="button"
                        onClick={() => setShowLoginPass((v) => !v)}
                        aria-label={showLoginPass ? 'Hide password' : 'Show password'}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8E8A9B] hover:text-[#FAF6F0]"
                      >
                        {showLoginPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2 pt-1 text-xs text-[#C6C3D0]">
                    <label className="flex items-center space-x-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={keepSignedIn}
                        onChange={(e) => setKeepSignedIn(e.target.checked)}
                        className="h-4 w-4 rounded border-[#343342] text-[#D9468F]"
                      />
                      <span>Keep me signed in</span>
                    </label>
                    <label className="flex items-center space-x-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={rememberEmail}
                        onChange={(e) => setRememberEmail(e.target.checked)}
                        className="h-4 w-4 rounded border-[#343342] text-[#D9468F]"
                      />
                      <span>Remember masked email hint on this device</span>
                    </label>
                  </div>

                  <button
                    type="submit"
                    disabled={isBusy}
                    className="w-full py-3 px-4 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold flex items-center justify-center space-x-2 transition disabled:opacity-50"
                  >
                    {isBusy ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Signing in...</span>
                      </>
                    ) : (
                      <>
                        <span>Log in</span>
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </form>

                <p className="text-center text-xs text-[#9A96A6]">
                  New to AegisNotify?{' '}
                  <button
                    type="button"
                    onClick={() => setActiveTab('signup')}
                    className="text-[#F472B6] font-semibold hover:underline"
                  >
                    Create an account
                  </button>
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => void handleGoogleAuth('signup')}
                  className="w-full py-2.5 px-4 rounded-xl bg-white hover:bg-gray-100 text-[#16161D] text-sm font-semibold flex items-center justify-center space-x-2 transition disabled:opacity-50"
                >
                  <span>Sign up with Google</span>
                </button>

                <div className="relative flex items-center py-1">
                  <div className="flex-grow border-t border-[#2C2B38]" />
                  <span className="px-3 text-[11px] uppercase tracking-wider text-[#8E8A9B]">
                    or email
                  </span>
                  <div className="flex-grow border-t border-[#2C2B38]" />
                </div>

                <form onSubmit={handleEmailSignup} className="space-y-3">
                  <div className="space-y-1">
                    <label htmlFor="signup-name" className="block text-xs font-semibold text-[#E5E1D8]">
                      Full Name
                    </label>
                    <div className="relative">
                      <UserIcon className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        id="signup-name"
                        type="text"
                        value={signupName}
                        onChange={(e) => setSignupName(e.target.value)}
                        autoComplete="name"
                        placeholder="Alex Mercer"
                        className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="signup-email" className="block text-xs font-semibold text-[#E5E1D8]">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        id="signup-email"
                        type="email"
                        value={signupEmail}
                        onChange={(e) => setSignupEmail(e.target.value)}
                        autoComplete="email"
                        placeholder="you@example.com"
                        className="w-full pl-10 pr-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="signup-password" className="block text-xs font-semibold text-[#E5E1D8]">
                      Password (min 10 chars)
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                      <input
                        id="signup-password"
                        type={showSignupPass ? 'text' : 'password'}
                        value={signupPassword}
                        onChange={(e) => setSignupPassword(e.target.value)}
                        autoComplete="new-password"
                        placeholder="Strong password"
                        className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                      />
                      <button
                        type="button"
                        onClick={() => setShowSignupPass((v) => !v)}
                        aria-label={showSignupPass ? 'Hide password' : 'Show password'}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8E8A9B] hover:text-[#FAF6F0]"
                      >
                        {showSignupPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                    {signupPassword.length > 0 && (
                      <div className="space-y-1 pt-1">
                        <div className="grid grid-cols-4 gap-1 h-1.5">
                          {[1, 2, 3, 4].map((lvl) => (
                            <div
                              key={lvl}
                              className={`rounded-full ${
                                signupStrength.score >= lvl
                                  ? signupStrength.score >= 3
                                    ? 'bg-emerald-500'
                                    : 'bg-amber-500'
                                  : 'bg-[#2C2B38]'
                              }`}
                            />
                          ))}
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-[#C6C3D0]">{signupStrength.label}</span>
                          {signupStrength.feedback[0] && (
                            <span className="text-amber-300">{signupStrength.feedback[0]}</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="space-y-1">
                    <label htmlFor="signup-confirm" className="block text-xs font-semibold text-[#E5E1D8]">
                      Confirm Password
                    </label>
                    <input
                      id="signup-confirm"
                      type={showSignupPass ? 'text' : 'password'}
                      value={signupConfirm}
                      onChange={(e) => setSignupConfirm(e.target.value)}
                      autoComplete="new-password"
                      placeholder="Repeat password"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F]"
                    />
                  </div>

                  <label className="flex items-start space-x-2 text-xs text-[#C6C3D0] pt-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={acceptedTerms}
                      onChange={(e) => setAcceptedTerms(e.target.checked)}
                      className="mt-0.5 h-4 w-4 rounded border-[#343342] text-[#D9468F]"
                    />
                    <span className="leading-relaxed">
                      I agree to the Zero-Trust Terms &amp; Privacy Policy (private keys stay encrypted in browser).
                    </span>
                  </label>

                  <button
                    type="submit"
                    disabled={isBusy}
                    className="w-full py-3 px-4 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold flex items-center justify-center space-x-2 transition disabled:opacity-50"
                  >
                    {isBusy ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Creating account...</span>
                      </>
                    ) : (
                      <>
                        <span>Create account</span>
                        <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </form>

                <p className="text-center text-xs text-[#9A96A6]">
                  Already have an account?{' '}
                  <button
                    type="button"
                    onClick={() => setActiveTab('login')}
                    className="text-[#F472B6] font-semibold hover:underline"
                  >
                    Log in
                  </button>
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
