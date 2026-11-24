import { useState, useEffect, useCallback } from 'react';
import AegisDashboard from './app/dashboard/page.js';
import SmartAuthFlow, { type SmartAuthCompletedPayload } from './components/SmartAuthFlow.js';
import UnlockKeysScreen from './components/UnlockKeysScreen.js';
import ErrorBoundary from './components/ErrorBoundary.js';
import {
  auth,
  signOut,
  onAuthStateChanged,
  loadEncryptedKeyBackupFromFirestore,
} from './lib/firebase/client.js';
import {
  wipeAllEphemeralMemory,
  setActiveClientKeyRing,
} from './lib/ephemeral/clientMemory.js';
import {
  isSessionInactiveExceeded,
  touchLastActivity,
  clearLastActivity,
  DEFAULT_INACTIVITY_TIMEOUT_DAYS,
} from './lib/auth/deviceMemory.js';
import type { EncryptedCombinedKeyBackup } from './lib/auth/keyVaultBackup.js';
import type { UnlockedSigningKey } from './lib/provenance/browserCrypto.js';
import { safeReadJson } from './lib/http/safeJson.js';

interface AuthenticatedUser {
  id: string;
  firebaseUid?: string;
  phoneNumber?: string;
  email?: string;
  displayName?: string;
  emailVerified?: boolean;
  role: string;
}

export default function App() {
  const [currentUser, setCurrentUser] = useState<AuthenticatedUser | null>(null);
  const [authToken, setAuthToken] = useState<string>('');
  const [isVerifyingSession, setIsVerifyingSession] = useState(true);
  const [unlockedSigningKey, setUnlockedSigningKey] = useState<UnlockedSigningKey | null>(null);
  const [pendingKeyBackup, setPendingKeyBackup] = useState<EncryptedCombinedKeyBackup | null>(null);
  const [needsKeySetup, setNeedsKeySetup] = useState(false);
  const [needsEmailVerify, setNeedsEmailVerify] = useState(false);
  const [isNewDeviceAlert, setIsNewDeviceAlert] = useState(false);
  const [inactivityDays, setInactivityDays] = useState(DEFAULT_INACTIVITY_TIMEOUT_DAYS);

  const handleLogout = useCallback(() => {
    unlockedSigningKey?.wipe();
    setUnlockedSigningKey(null);
    setActiveClientKeyRing(null);
    wipeAllEphemeralMemory();
    setPendingKeyBackup(null);
    setNeedsKeySetup(false);
    setNeedsEmailVerify(false);
    setIsNewDeviceAlert(false);
    clearLastActivity();
    try {
      localStorage.removeItem('aegis_auth_token');
      localStorage.removeItem('aegis_user');
    } catch {
      // Ignore storage errors
    }
    void signOut(auth).catch(() => {});
    setCurrentUser(null);
    setAuthToken('');
  }, [unlockedSigningKey]);

  useEffect(() => {
    let settled = false;

    const bootstrapSession = async (fbUserPresent: any) => {
      try {
        const storedToken = localStorage.getItem('aegis_auth_token');
        const storedUserRaw = localStorage.getItem('aegis_user');

        if (storedToken && storedUserRaw) {
          const parsedUser = JSON.parse(storedUserRaw) as AuthenticatedUser;

          // Verify token validity + sessionVersion + key backup state
          const sessRes = await fetch('/api/v1/auth/sessions', {
            headers: { Authorization: `Bearer ${storedToken}` },
          }).catch(() => null);

          if (sessRes && sessRes.status === 401) {
            handleLogout();
            return;
          }

          const sessJson = sessRes ? await safeReadJson(sessRes) : null;
          const serverTimeoutDays =
            typeof sessJson?.data?.inactivityTimeoutDays === 'number'
              ? sessJson.data.inactivityTimeoutDays
              : DEFAULT_INACTIVITY_TIMEOUT_DAYS;
          setInactivityDays(serverTimeoutDays);

          if (isSessionInactiveExceeded(serverTimeoutDays)) {
            handleLogout();
            return;
          }

          touchLastActivity();

          // Check email verification if password-based Firebase user
          if (
            fbUserPresent &&
            fbUserPresent.providerData?.some((p: any) => p.providerId === 'password') &&
            !fbUserPresent.emailVerified
          ) {
            setCurrentUser(parsedUser);
            setAuthToken(storedToken);
            setNeedsEmailVerify(true);
            return;
          }

          // Check if user has encrypted key backup that needs unlocking on fresh page load
          let backup: EncryptedCombinedKeyBackup | null = null;
          try {
            const kbRes = await fetch('/api/v1/auth/keys-backup', {
              headers: { Authorization: `Bearer ${storedToken}` },
            });
            const kbJson = await safeReadJson(kbRes);
            if (kbJson?.success && kbJson?.data?.backup) {
              backup = kbJson.data.backup as EncryptedCombinedKeyBackup;
            }
          } catch {
            // Non-fatal
          }

          if (!backup && fbUserPresent) {
            backup = (await loadEncryptedKeyBackupFromFirestore(fbUserPresent.uid).catch(
              () => null
            )) as EncryptedCombinedKeyBackup | null;
          }

          if (backup) {
            setPendingKeyBackup(backup);
          }

          setAuthToken(storedToken);
          setCurrentUser(parsedUser);
        }
      } catch (e) {
        console.error('Session restoration error:', e);
      } finally {
        if (!settled) {
          settled = true;
          setIsVerifyingSession(false);
        }
      }
    };

    const unsubscribe = onAuthStateChanged(auth, (fbUser) => {
      if (!settled) {
        void bootstrapSession(fbUser);
      }
    });

    // Safety fallback if Firebase Auth observer delays on restricted networks
    const fallbackTimer = setTimeout(() => {
      if (!settled) {
        void bootstrapSession(auth.currentUser);
      }
    }, 800);

    return () => {
      clearTimeout(fallbackTimer);
      unsubscribe();
    };
  }, [handleLogout]);

  // Track active usage to keep inactivity timer fresh
  useEffect(() => {
    if (!currentUser) return;
    const onActivity = () => {
      if (isSessionInactiveExceeded(inactivityDays)) {
        handleLogout();
      } else {
        touchLastActivity();
      }
    };
    window.addEventListener('click', onActivity, { passive: true });
    window.addEventListener('keydown', onActivity, { passive: true });
    return () => {
      window.removeEventListener('click', onActivity);
      window.removeEventListener('keydown', onActivity);
    };
  }, [currentUser, inactivityDays, handleLogout]);

  const handleSmartAuthComplete = (payload: SmartAuthCompletedPayload) => {
    setAuthToken(payload.token);
    setCurrentUser(payload.user);
    setInactivityDays(payload.inactivityTimeoutDays || DEFAULT_INACTIVITY_TIMEOUT_DAYS);
    setIsNewDeviceAlert(Boolean(payload.isNewDevice));
    setNeedsEmailVerify(Boolean(payload.requiresEmailVerification));
    setNeedsKeySetup(!payload.hasKeyBackup && Boolean(payload.user.firebaseUid));
    setPendingKeyBackup(payload.keyBackup);

    if (payload.unlockedSigningKey) {
      setUnlockedSigningKey(payload.unlockedSigningKey);
    }
    if (payload.ephemeralKeyRing) {
      setActiveClientKeyRing(payload.ephemeralKeyRing);
    }
    touchLastActivity();
  };

  if (isVerifyingSession) {
    return (
      <div className="min-h-screen bg-[#0D0D14] flex flex-col items-center justify-center font-sans text-[#FAF6F0] text-sm select-none">
        <div className="flex items-center space-x-3 px-6 py-4 rounded-2xl bg-[#16161D] border border-[#2C2B38] shadow-xl">
          <span className="w-2.5 h-2.5 rounded-full bg-[#D9468F] animate-pulse" />
          <span className="font-medium text-[#E5E1D8]">Loading your workspace...</span>
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return <SmartAuthFlow onAuthComplete={handleSmartAuthComplete} />;
  }

  if (needsEmailVerify) {
    return (
      <SmartAuthFlow
        initialStep="verify_email"
        pendingContext={{
          user: currentUser,
          token: authToken,
          isNewUser: false,
          isNewDevice: isNewDeviceAlert,
          onboardingCompleted: false,
          emailVerified: false,
          requiresEmailVerification: true,
          inactivityTimeoutDays: inactivityDays,
          hasKeyBackup: Boolean(pendingKeyBackup),
          keyBackup: pendingKeyBackup,
          unlockedSigningKey,
          ephemeralKeyRing: null,
        }}
        onAuthComplete={handleSmartAuthComplete}
      />
    );
  }

  if (needsKeySetup) {
    return (
      <SmartAuthFlow
        initialStep="key_setup"
        pendingContext={{
          user: currentUser,
          token: authToken,
          isNewUser: false,
          isNewDevice: isNewDeviceAlert,
          onboardingCompleted: false,
          emailVerified: true,
          requiresEmailVerification: false,
          inactivityTimeoutDays: inactivityDays,
          hasKeyBackup: false,
          keyBackup: null,
          unlockedSigningKey: null,
          ephemeralKeyRing: null,
        }}
        onAuthComplete={handleSmartAuthComplete}
      />
    );
  }

  if (pendingKeyBackup && !unlockedSigningKey) {
    return (
      <UnlockKeysScreen
        userId={currentUser.id}
        userEmail={currentUser.email}
        token={authToken}
        backup={pendingKeyBackup}
        isNewDevice={isNewDeviceAlert}
        onSignOut={handleLogout}
        onUnlocked={({ unlockedSigningKey: uk, ephemeralKeyRing: er, updatedBackup }) => {
          setUnlockedSigningKey(uk);
          setActiveClientKeyRing(er);
          if (updatedBackup) setPendingKeyBackup(updatedBackup);
        }}
      />
    );
  }

  return (
    <ErrorBoundary fallbackTitle="Aegis Dashboard Error">
      <AegisDashboard
        user={currentUser}
        initialUnlockedSigningKey={unlockedSigningKey}
        onLogout={handleLogout}
      />
    </ErrorBoundary>
  );
}

