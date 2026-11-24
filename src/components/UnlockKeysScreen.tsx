'use client';

import React, { useState } from 'react';
import {
  KeyRound,
  Lock,
  Eye,
  EyeOff,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  LogOut,
  ShieldAlert,
} from 'lucide-react';
import { AegisGlyphLogo } from './NothingLogos.js';
import {
  MAX_UNLOCK_ATTEMPTS,
  createEncryptedCombinedKeyBackup,
  unlockCombinedKeyBackup,
  type EncryptedCombinedKeyBackup,
} from '../lib/auth/keyVaultBackup.js';
import { validatePasswordStrength } from '../lib/auth/deviceMemory.js';
import type { UnlockedSigningKey } from '../lib/provenance/browserCrypto.js';
import type { EphemeralSessionKeyRing } from '../lib/ephemeral/crypto.js';
import {
  auth,
  saveEncryptedKeyBackupToFirestore,
  saveSmartSecuritySettingsToFirestore,
} from '../lib/firebase/client.js';
import { safeReadJson } from '../lib/http/safeJson.js';

interface UnlockKeysScreenProps {
  userId: string;
  userEmail?: string;
  token: string;
  backup: EncryptedCombinedKeyBackup;
  isNewDevice?: boolean;
  onUnlocked: (keys: {
    unlockedSigningKey: UnlockedSigningKey;
    ephemeralKeyRing: EphemeralSessionKeyRing;
    updatedBackup?: EncryptedCombinedKeyBackup;
  }) => void;
  onSignOut: () => void;
}

export default function UnlockKeysScreen({
  userId,
  userEmail,
  token,
  backup,
  isNewDevice = false,
  onUnlocked,
  onSignOut,
}: UnlockKeysScreenProps) {
  const [passphrase, setPassphrase] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [attemptsUsed, setAttemptsUsed] = useState(0);
  const [isBusy, setIsBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Forgot passphrase / recovery key rotation flow
  const [showForgotFlow, setShowForgotFlow] = useState(false);
  const [ackUnrecoverable, setAckUnrecoverable] = useState(false);
  const [newPassphrase, setNewPassphrase] = useState('');
  const [confirmNewPassphrase, setConfirmNewPassphrase] = useState('');
  const [showNewPass, setShowNewPass] = useState(false);

  const lockedOut = attemptsUsed >= MAX_UNLOCK_ATTEMPTS;
  const attemptsRemaining = Math.max(0, MAX_UNLOCK_ATTEMPTS - attemptsUsed);
  const newStrength = validatePasswordStrength(newPassphrase);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (lockedOut || isBusy) return;
    setErrorMsg(null);

    if (!passphrase) {
      setErrorMsg('Enter your encryption passphrase to unlock your keys.');
      return;
    }

    setIsBusy(true);
    try {
      const unlocked = await unlockCombinedKeyBackup(backup, passphrase, userId);

      // Register public keys into server memory for active session
      await Promise.all([
        fetch('/api/v1/ephemeral/public-key', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            ecdhPublicJwk: unlocked.ephemeralKeyRing.ecdhPublicJwk,
            ecdsaPublicJwk: unlocked.ephemeralKeyRing.ecdsaPublicJwk,
          }),
        }).catch(() => null),
        fetch('/api/v1/provenance/keys', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            publicKey: unlocked.unlockedSigningKey.publicKey,
            kid: unlocked.unlockedSigningKey.kid,
            label: 'Primary Browser Key',
          }),
        }).catch(() => null),
      ]);

      setPassphrase('');
      onUnlocked(unlocked);
    } catch {
      const nextCount = attemptsUsed + 1;
      setAttemptsUsed(nextCount);
      if (nextCount >= MAX_UNLOCK_ATTEMPTS) {
        setErrorMsg(
          `Maximum ${MAX_UNLOCK_ATTEMPTS} unlock attempts reached for this session. Sign out and back in, or reset with new keys below.`
        );
      } else {
        setErrorMsg(
          `Incorrect encryption passphrase (${MAX_UNLOCK_ATTEMPTS - nextCount} attempt${
            MAX_UNLOCK_ATTEMPTS - nextCount === 1 ? '' : 's'
          } remaining).`
        );
      }
    } finally {
      setIsBusy(false);
    }
  };

  const handleRotateLostPassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!ackUnrecoverable) {
      setErrorMsg('Please confirm that old encrypted messages cannot be recovered.');
      return;
    }
    if (!newStrength.valid) {
      setErrorMsg(newStrength.feedback[0] || 'Choose a stronger passphrase (min 10 chars).');
      return;
    }
    if (newPassphrase !== confirmNewPassphrase) {
      setErrorMsg('New passphrases do not match.');
      return;
    }

    setIsBusy(true);
    try {
      const created = await createEncryptedCombinedKeyBackup(userId, newPassphrase);

      const backupRes = await fetch('/api/v1/auth/keys-backup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(created.backup),
      });
      const backupJson = await safeReadJson(backupRes);
      if (!backupRes.ok || !backupJson?.success) {
        throw new Error(backupJson?.message || 'Unable to store new encrypted backup.');
      }

      // Rotate provenance Ed25519 key & ephemeral public bundle
      await Promise.all([
        fetch('/api/v1/provenance/keys/rotate', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            publicKey: created.backup.ed25519PublicKey,
            kid: created.backup.ed25519Kid,
            reason: 'Passphrase recovery key rotation',
          }),
        }).catch(() => null),
        fetch('/api/v1/ephemeral/public-key', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            ecdhPublicJwk: created.backup.ecdhPublicJwk,
            ecdsaPublicJwk: created.backup.ecdsaPublicJwk,
          }),
        }).catch(() => null),
      ]);

      if (auth.currentUser && auth.currentUser.uid === userId) {
        await saveEncryptedKeyBackupToFirestore(userId, created.backup).catch(() => {});
        await saveSmartSecuritySettingsToFirestore(userId, { keySetupCompleted: true }).catch(
          () => {}
        );
      }

      setNewPassphrase('');
      setConfirmNewPassphrase('');
      onUnlocked({
        unlockedSigningKey: created.unlockedSigningKey,
        ephemeralKeyRing: created.ephemeralKeyRing,
        updatedBackup: created.backup,
      });
    } catch (err: any) {
      setErrorMsg(err?.message || 'Key recovery rotation failed.');
    } finally {
      setIsBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0D0D14] text-[#FAF6F0] flex flex-col justify-center items-center px-4 py-10 font-sans">
      <div className="w-full max-w-md rounded-3xl bg-[#16161D] border border-[#2C2B38] shadow-2xl p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AegisGlyphLogo className="w-8 h-8 text-[#D9468F]" />
            <div>
              <h1 className="font-display text-lg font-bold text-[#FAF6F0]">
                Unlock your messages
              </h1>
              <p className="text-xs text-[#A5A2B0]">
                {userEmail || 'End-to-end encrypted session'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onSignOut}
            className="text-xs text-[#A5A2B0] hover:text-[#FAF6F0] flex items-center space-x-1 px-2.5 py-1.5 rounded-lg border border-[#2C2B38] hover:border-[#464451]"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign out</span>
          </button>
        </div>

        {isNewDevice && (
          <div className="rounded-2xl bg-amber-950/50 border border-amber-700/60 px-4 py-3 text-xs text-amber-200 flex items-start space-x-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
            <div>
              <p className="font-semibold text-amber-100">New device sign-in detected</p>
              <p className="mt-0.5 text-amber-200/90">
                Your private encryption keys stay locked until you enter your local passphrase on this device.
              </p>
            </div>
          </div>
        )}

        <div className="rounded-2xl bg-[#1E1E28] border border-[#2C2B38] p-4 space-y-1.5 text-xs text-[#C6C3D0]">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-[#FAF6F0] flex items-center space-x-1.5">
              <KeyRound className="w-3.5 h-3.5 text-[#F472B6]" />
              <span>Encrypted Key Vault</span>
            </span>
            <span className="font-mono-tech text-[11px] text-[#F472B6]">{backup.ed25519Kid}</span>
          </div>
          <p className="text-[11px] text-[#9A96A6]">
            Decrypted locally in browser RAM via PBKDF2-HMAC-SHA256 + AES-256-GCM. Your passphrase is never transmitted.
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

        {!showForgotFlow ? (
          <form onSubmit={handleUnlock} className="space-y-4">
            <div className="space-y-1.5">
              <label
                htmlFor="unlock-passphrase-input"
                className="block text-xs font-semibold text-[#E5E1D8]"
              >
                Encryption Passphrase
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-[#8E8A9B] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="unlock-passphrase-input"
                  type={showPass ? 'text' : 'password'}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  disabled={lockedOut || isBusy}
                  placeholder="Enter your key passphrase"
                  autoComplete="off"
                  className="w-full pl-10 pr-10 py-3 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] placeholder-[#7B7788] focus:outline-none focus:border-[#D9468F] disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => setShowPass((v) => !v)}
                  aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8E8A9B] hover:text-[#FAF6F0]"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-[11px] text-[#8E8A9B]">
                Attempts remaining this session: <span className="font-mono-tech text-[#FAF6F0]">{attemptsRemaining}</span> / {MAX_UNLOCK_ATTEMPTS}
              </p>
            </div>

            <button
              type="submit"
              disabled={lockedOut || isBusy}
              className="w-full py-3 px-4 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-sm font-semibold flex items-center justify-center space-x-2 transition disabled:opacity-50"
            >
              {isBusy ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Unlocking Keys...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Unlock Encrypted Messages</span>
                </>
              )}
            </button>

            <div className="pt-2 border-t border-[#2C2B38] text-center">
              <button
                type="button"
                onClick={() => {
                  setShowForgotFlow(true);
                  setErrorMsg(null);
                }}
                className="text-xs text-[#F472B6] hover:text-[#F9A8D4] font-medium"
              >
                I forgot my passphrase
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleRotateLostPassphrase} className="space-y-4">
            <div className="rounded-2xl bg-red-950/40 border border-red-700/60 p-4 space-y-2 text-xs text-red-200">
              <p className="font-bold text-red-100 flex items-center space-x-1.5">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>Old encrypted messages cannot be recovered</span>
              </p>
              <p className="leading-relaxed">
                Because your passphrase is never stored on our servers, resetting it generates brand-new ECDH and Ed25519 keys. Previous encrypted notifications remain unreadable.
              </p>
              <label className="flex items-start space-x-2 pt-1 cursor-pointer">
                <input
                  type="checkbox"
                  checked={ackUnrecoverable}
                  onChange={(e) => setAckUnrecoverable(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-red-500 text-[#D9468F]"
                />
                <span className="text-[11px] font-semibold text-red-100">
                  I understand old encrypted messages cannot be decrypted after generating new keys.
                </span>
              </label>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reset-new-passphrase" className="block text-xs font-semibold text-[#E5E1D8]">
                New Encryption Passphrase (min 10 chars)
              </label>
              <div className="relative">
                <input
                  id="reset-new-passphrase"
                  type={showNewPass ? 'text' : 'password'}
                  value={newPassphrase}
                  onChange={(e) => setNewPassphrase(e.target.value)}
                  placeholder="Strong new passphrase"
                  className="w-full px-3.5 pr-10 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] focus:outline-none focus:border-[#D9468F]"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPass((v) => !v)}
                  aria-label={showNewPass ? 'Hide passphrase' : 'Show passphrase'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#8E8A9B] hover:text-[#FAF6F0]"
                >
                  {showNewPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-[#9A96A6]">Strength: {newStrength.label}</span>
                {newStrength.feedback[0] && (
                  <span className="text-amber-300">{newStrength.feedback[0]}</span>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reset-confirm-passphrase" className="block text-xs font-semibold text-[#E5E1D8]">
                Confirm New Passphrase
              </label>
              <input
                id="reset-confirm-passphrase"
                type={showNewPass ? 'text' : 'password'}
                value={confirmNewPassphrase}
                onChange={(e) => setConfirmNewPassphrase(e.target.value)}
                placeholder="Repeat new passphrase"
                className="w-full px-3.5 py-2.5 rounded-xl bg-[#1E1E28] border border-[#343342] text-sm text-[#FAF6F0] focus:outline-none focus:border-[#D9468F]"
              />
            </div>

            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => {
                  setShowForgotFlow(false);
                  setErrorMsg(null);
                }}
                className="flex-1 py-2.5 px-3 rounded-xl border border-[#343342] text-xs font-semibold text-[#C6C3D0] hover:bg-[#1E1E28]"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={isBusy}
                className="flex-1 py-2.5 px-3 rounded-xl bg-red-600 hover:bg-red-700 text-xs font-semibold text-white disabled:opacity-50"
              >
                {isBusy ? 'Generating...' : 'Generate New Keys'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
