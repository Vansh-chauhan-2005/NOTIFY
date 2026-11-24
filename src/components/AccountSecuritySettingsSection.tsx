'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Smartphone,
  Mail,
  Laptop,
  LogOut,
  AlertTriangle,
  CheckCircle2,
  Link2,
  Unlink,
  Clock,
  Trash2,
  RefreshCw,
  KeyRound,
  Lock,
} from 'lucide-react';
import {
  auth,
  googleAuthProvider,
  EmailAuthProvider,
  linkWithPopup,
  linkWithCredential,
  unlink,
  reauthenticateWithCredential,
  reauthenticateWithPopup,
  updateEmail,
  deleteUser,
  deleteUserProfileInFirestore,
  saveSmartSecuritySettingsToFirestore,
  type User as FirebaseUser,
} from '../lib/firebase/client.js';
import { safeReadJson } from '../lib/http/safeJson.js';
import { validatePasswordStrength } from '../lib/auth/deviceMemory.js';

interface LoginAuditEntry {
  id: string;
  timestamp: string;
  deviceType: string;
  browserSummary: string;
  ipPrefixHash: string;
  method: string;
  isNewDevice: boolean;
}

interface AccountSecuritySettingsSectionProps {
  userId: string;
  userEmail?: string;
  token: string | null;
  firebaseUser: FirebaseUser | null;
  onForceLogoutAll: () => void;
  onInactivityDaysChanged?: (days: number) => void;
}

type SensitiveActionKind =
  | { type: 'change_email'; newEmail: string }
  | { type: 'delete_account' }
  | { type: 'link_password'; password: string }
  | { type: 'unlink_provider'; providerId: string }
  | null;

export default function AccountSecuritySettingsSection({
  userId,
  userEmail,
  token,
  firebaseUser,
  onForceLogoutAll,
  onInactivityDaysChanged,
}: AccountSecuritySettingsSectionProps) {
  const [recentSignIns, setRecentSignIns] = useState<LoginAuditEntry[]>([]);
  const [inactivityDays, setInactivityDays] = useState<number>(14);
  const [serverMethods, setServerMethods] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );

  // Link Password form
  const [showLinkPassword, setShowLinkPassword] = useState(false);
  const [linkEmailInput, setLinkEmailInput] = useState(userEmail || '');
  const [linkPasswordInput, setLinkPasswordInput] = useState('');

  // Change Email form
  const [newEmailInput, setNewEmailInput] = useState('');

  // Delete Account confirm
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // Re-authentication modal state
  const [pendingAction, setPendingAction] = useState<SensitiveActionKind>(null);
  const [reauthPassword, setReauthPassword] = useState('');

  const loadSessionSecurity = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/auth/sessions', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await safeReadJson(res);
      if (data?.success && data?.data) {
        setRecentSignIns(Array.isArray(data.data.recentSignIns) ? data.data.recentSignIns : []);
        if (typeof data.data.inactivityTimeoutDays === 'number') {
          setInactivityDays(data.data.inactivityTimeoutDays);
        }
        if (Array.isArray(data.data.authMethods)) {
          setServerMethods(data.data.authMethods);
        }
      }
    } catch {
      // Non-fatal
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void loadSessionSecurity();
  }, [loadSessionSecurity]);

  const linkedProviders = firebaseUser
    ? firebaseUser.providerData.map((p) => p.providerId)
    : serverMethods.map((m) =>
        m === 'google' ? 'google.com' : m === 'phone' ? 'phone' : 'password'
      );

  const hasGoogle = linkedProviders.includes('google.com');
  const hasPassword = linkedProviders.includes('password');
  const hasPhone = linkedProviders.includes('phone');
  const activeMethodCount = [hasGoogle, hasPassword, hasPhone].filter(Boolean).length;

  const syncLinkedMethodsToBackend = async (nextProviders: string[]) => {
    const mapped = nextProviders.map((p) =>
      p === 'google.com' ? 'google' : p === 'phone' ? 'phone' : 'password'
    );
    if (token) {
      await fetch('/api/v1/auth/sessions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          action: 'sync_profile',
          authMethods: mapped,
        }),
      }).catch(() => null);
    }
    if (firebaseUser) {
      await saveSmartSecuritySettingsToFirestore(firebaseUser.uid, {
        authMethods: mapped,
      }).catch(() => {});
    }
  };

  const handleLinkGoogle = async () => {
    if (!firebaseUser) {
      setFeedback({ type: 'error', message: 'Sign in with a Firebase account to link Google.' });
      return;
    }
    setBusy(true);
    setFeedback(null);
    try {
      const res = await linkWithPopup(firebaseUser, googleAuthProvider);
      await syncLinkedMethodsToBackend(res.user.providerData.map((p) => p.providerId));
      setFeedback({ type: 'success', message: 'Google Sign-In linked to your account.' });
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message:
          err?.code === 'auth/credential-already-in-use'
            ? 'That Google account is already linked to another user.'
            : err?.message || 'Unable to link Google Sign-In.',
      });
    } finally {
      setBusy(false);
    }
  };

  const executeSensitiveAction = async (action: SensitiveActionKind) => {
    if (!action) return;
    setBusy(true);
    setFeedback(null);

    try {
      if (action.type === 'unlink_provider') {
        if (!firebaseUser) throw new Error('Firebase user session required.');
        if (activeMethodCount <= 1) {
          throw new Error('You cannot remove your only remaining sign-in method.');
        }
        const updatedUser = await unlink(firebaseUser, action.providerId);
        await syncLinkedMethodsToBackend(updatedUser.providerData.map((p) => p.providerId));
        setFeedback({ type: 'success', message: 'Sign-in method unlinked cleanly.' });
      } else if (action.type === 'link_password') {
        if (!firebaseUser) throw new Error('Firebase user session required.');
        const emailToUse = (linkEmailInput || firebaseUser.email || '').trim();
        if (!emailToUse) throw new Error('Account email is required to add password sign-in.');
        const cred = EmailAuthProvider.credential(emailToUse, action.password);
        const res = await linkWithCredential(firebaseUser, cred);
        await syncLinkedMethodsToBackend(res.user.providerData.map((p) => p.providerId));
        setShowLinkPassword(false);
        setLinkPasswordInput('');
        setFeedback({ type: 'success', message: 'Email & Password sign-in linked.' });
      } else if (action.type === 'change_email') {
        if (!firebaseUser) throw new Error('Firebase user session required.');
        await updateEmail(firebaseUser, action.newEmail);
        if (token) {
          await fetch('/api/v1/auth/sessions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ action: 'sync_profile', email: action.newEmail }),
          }).catch(() => null);
        }
        await saveSmartSecuritySettingsToFirestore(firebaseUser.uid, {
          email: action.newEmail,
        }).catch(() => {});
        setNewEmailInput('');
        setFeedback({ type: 'success', message: `Email updated to ${action.newEmail}.` });
      } else if (action.type === 'delete_account') {
        if (token) {
          await fetch('/api/v1/auth/sessions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ action: 'delete_account' }),
          }).catch(() => null);
        }
        if (firebaseUser) {
          await deleteUserProfileInFirestore(firebaseUser.uid).catch(() => {});
          await deleteUser(firebaseUser);
        }
        onForceLogoutAll();
      }
      setPendingAction(null);
      setReauthPassword('');
    } catch (err: any) {
      if (err?.code === 'auth/requires-recent-login') {
        setPendingAction(action);
        setFeedback({
          type: 'error',
          message: 'Please re-authenticate below to complete this sensitive action.',
        });
      } else {
        setFeedback({ type: 'error', message: err?.message || 'Action could not be completed.' });
      }
    } finally {
      setBusy(false);
    }
  };

  const handleConfirmReauthAndRun = async (method: 'password' | 'google') => {
    if (!firebaseUser || !pendingAction) return;
    setBusy(true);
    setFeedback(null);
    try {
      if (method === 'google') {
        await reauthenticateWithPopup(firebaseUser, googleAuthProvider);
      } else {
        const email = firebaseUser.email || userEmail || '';
        if (!email || !reauthPassword) {
          throw new Error('Enter your current password to confirm identity.');
        }
        const cred = EmailAuthProvider.credential(email, reauthPassword);
        await reauthenticateWithCredential(firebaseUser, cred);
      }
      await executeSensitiveAction(pendingAction);
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Re-authentication failed.' });
      setBusy(false);
    }
  };

  const handleInactivityChange = async (days: number) => {
    setInactivityDays(days);
    onInactivityDaysChanged?.(days);
    if (token) {
      await fetch('/api/v1/auth/sessions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ action: 'update_inactivity', inactivityTimeoutDays: days }),
      }).catch(() => null);
    }
    if (firebaseUser) {
      await saveSmartSecuritySettingsToFirestore(firebaseUser.uid, {
        inactivityTimeoutDays: days,
      }).catch(() => {});
    }
    setFeedback({
      type: 'success',
      message: `Inactivity auto-signout set to ${days} day${days === 1 ? '' : 's'}.`,
    });
  };

  const handleSignOutAllDevices = async () => {
    setBusy(true);
    setFeedback(null);
    try {
      if (token) {
        await fetch('/api/v1/auth/sessions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ action: 'revoke_all' }),
        });
      }
      if (firebaseUser) {
        await saveSmartSecuritySettingsToFirestore(firebaseUser.uid, {
          sessionVersion: Date.now(),
        }).catch(() => {});
      }
      onForceLogoutAll();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Unable to sign out all devices.' });
      setBusy(false);
    }
  };

  return (
    <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
              <Shield className="w-4 h-4" />
            </div>
            <h2 className="font-display text-base font-semibold text-[#16161D]">
              Sign-in Methods, Recent Sign-ins &amp; Session Security
            </h2>
          </div>
          <p className="text-xs text-[#464451]">
            Manage linked login methods, review devices that accessed your account, set inactivity sign-out, or revoke all active sessions.
          </p>
        </div>

        <button
          type="button"
          onClick={() => void loadSessionSecurity()}
          disabled={loading}
          className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-xs font-semibold text-[#16161D] flex items-center space-x-1.5 self-start sm:self-center"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {feedback && (
        <div
          role="status"
          aria-live="polite"
          className={`rounded-xl px-4 py-2.5 text-xs border flex items-center space-x-2 ${
            feedback.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-red-50 border-red-200 text-red-700'
          }`}
        >
          {feedback.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          )}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Re-authentication modal / drawer for sensitive operations */}
      {pendingAction && (
        <div className="rounded-2xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/50 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Lock className="w-4 h-4 text-[#F472B6]" />
              <h3 className="text-sm font-semibold">Confirm your identity to continue</h3>
            </div>
            <button
              type="button"
              onClick={() => {
                setPendingAction(null);
                setReauthPassword('');
              }}
              className="text-xs text-[#A5A2B0] hover:text-white"
            >
              Cancel
            </button>
          </div>
          <p className="text-xs text-[#C6C3D0]">
            Recent authentication is required before changing email, unlinking a sign-in method, or deleting your account.
          </p>
          <div className="flex flex-col sm:flex-row gap-3">
            {hasPassword && (
              <div className="flex-1 flex space-x-2">
                <input
                  type="password"
                  value={reauthPassword}
                  onChange={(e) => setReauthPassword(e.target.value)}
                  placeholder="Current password"
                  className="flex-1 px-3 py-2 rounded-xl bg-[#22222C] border border-[#383747] text-xs text-white"
                />
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void handleConfirmReauthAndRun('password')}
                  className="px-3.5 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-xs font-semibold text-white whitespace-nowrap"
                >
                  Confirm
                </button>
              </div>
            )}
            {hasGoogle && (
              <button
                type="button"
                disabled={busy}
                onClick={() => void handleConfirmReauthAndRun('google')}
                className="px-4 py-2 rounded-xl bg-white text-[#16161D] text-xs font-semibold hover:bg-gray-100 whitespace-nowrap"
              >
                Re-verify with Google
              </button>
            )}
          </div>
        </div>
      )}

      {/* Sign-in methods */}
      <div className="space-y-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#6F6C7A]">
          Sign-in methods ({activeMethodCount || 1} active)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Google */}
          <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#16161D]">Google Sign-In</span>
              <span
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                  hasGoogle ? 'bg-emerald-100 text-emerald-800' : 'bg-[#EFE9DF] text-[#6F6C7A]'
                }`}
              >
                {hasGoogle ? 'Linked' : 'Not linked'}
              </span>
            </div>
            {hasGoogle ? (
              <button
                type="button"
                disabled={busy || activeMethodCount <= 1 || !firebaseUser}
                onClick={() =>
                  void executeSensitiveAction({ type: 'unlink_provider', providerId: 'google.com' })
                }
                title={
                  activeMethodCount <= 1
                    ? 'Cannot remove your last sign-in method'
                    : 'Unlink Google Sign-In'
                }
                className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] text-xs font-semibold text-[#464451] hover:bg-[#EFE9DF] disabled:opacity-40 flex items-center justify-center space-x-1"
              >
                <Unlink className="w-3.5 h-3.5" />
                <span>Unlink</span>
              </button>
            ) : (
              <button
                type="button"
                disabled={busy || !firebaseUser}
                onClick={() => void handleLinkGoogle()}
                className="px-3 py-1.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-white text-xs font-semibold disabled:opacity-40 flex items-center justify-center space-x-1"
              >
                <Link2 className="w-3.5 h-3.5" />
                <span>Link Google</span>
              </button>
            )}
          </div>

          {/* Email & Password */}
          <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#16161D] flex items-center space-x-1">
                <Mail className="w-3.5 h-3.5 text-[#D9468F]" />
                <span>Email &amp; Password</span>
              </span>
              <span
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                  hasPassword ? 'bg-emerald-100 text-emerald-800' : 'bg-[#EFE9DF] text-[#6F6C7A]'
                }`}
              >
                {hasPassword ? 'Linked' : 'Not linked'}
              </span>
            </div>
            {hasPassword ? (
              <button
                type="button"
                disabled={busy || activeMethodCount <= 1 || !firebaseUser}
                onClick={() =>
                  void executeSensitiveAction({ type: 'unlink_provider', providerId: 'password' })
                }
                title={
                  activeMethodCount <= 1
                    ? 'Cannot remove your last sign-in method'
                    : 'Unlink Email & Password'
                }
                className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] text-xs font-semibold text-[#464451] hover:bg-[#EFE9DF] disabled:opacity-40 flex items-center justify-center space-x-1"
              >
                <Unlink className="w-3.5 h-3.5" />
                <span>Unlink</span>
              </button>
            ) : (
              <button
                type="button"
                disabled={busy || !firebaseUser}
                onClick={() => setShowLinkPassword((v) => !v)}
                className="px-3 py-1.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-white text-xs font-semibold disabled:opacity-40 flex items-center justify-center space-x-1"
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>Add Password</span>
              </button>
            )}
          </div>

          {/* Phone */}
          <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-[#16161D] flex items-center space-x-1">
                <Smartphone className="w-3.5 h-3.5 text-[#D9468F]" />
                <span>Phone (SMS)</span>
              </span>
              <span
                className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                  hasPhone ? 'bg-emerald-100 text-emerald-800' : 'bg-[#EFE9DF] text-[#6F6C7A]'
                }`}
              >
                {hasPhone ? 'Linked' : 'Via SMS Panel'}
              </span>
            </div>
            {hasPhone ? (
              <button
                type="button"
                disabled={busy || activeMethodCount <= 1 || !firebaseUser}
                onClick={() =>
                  void executeSensitiveAction({ type: 'unlink_provider', providerId: 'phone' })
                }
                className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] text-xs font-semibold text-[#464451] hover:bg-[#EFE9DF] disabled:opacity-40 flex items-center justify-center space-x-1"
              >
                <Unlink className="w-3.5 h-3.5" />
                <span>Unlink</span>
              </button>
            ) : (
              <p className="text-[11px] text-[#6F6C7A]">
                Link your verified phone number using the SMS Verification card above.
              </p>
            )}
          </div>
        </div>

        {showLinkPassword && !hasPassword && (
          <div className="rounded-2xl bg-[#FAF6F0] border border-[#D8CEC0] p-4 space-y-3">
            <p className="text-xs font-semibold text-[#16161D]">
              Add Email &amp; Password to this account
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input
                type="email"
                value={linkEmailInput}
                onChange={(e) => setLinkEmailInput(e.target.value)}
                placeholder="Email address"
                className="px-3 py-2 rounded-xl border border-[#D8CEC0] bg-white text-xs text-[#16161D]"
              />
              <input
                type="password"
                value={linkPasswordInput}
                onChange={(e) => setLinkPasswordInput(e.target.value)}
                placeholder="Password (min 10 chars)"
                className="px-3 py-2 rounded-xl border border-[#D8CEC0] bg-white text-xs text-[#16161D]"
              />
            </div>
            <button
              type="button"
              disabled={busy || !validatePasswordStrength(linkPasswordInput).valid}
              onClick={() =>
                void executeSensitiveAction({ type: 'link_password', password: linkPasswordInput })
              }
              className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-white text-xs font-semibold disabled:opacity-50"
            >
              Save Password Sign-In
            </button>
          </div>
        )}
      </div>

      {/* Recent sign-ins */}
      <div className="space-y-3 pt-2 border-t border-[#E5DDD0]">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-[#6F6C7A]">
          Recent sign-ins
        </h3>
        {recentSignIns.length === 0 ? (
          <p className="text-xs text-[#6F6C7A] bg-[#FAF6F0] border border-[#E5DDD0] rounded-2xl px-4 py-3">
            No device sign-in audit entries recorded yet for this session.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-[#E5DDD0]">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#FAF6F0] text-[#6F6C7A] uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-2.5">Device</th>
                  <th className="px-4 py-2.5">Method</th>
                  <th className="px-4 py-2.5">Network Prefix Hash</th>
                  <th className="px-4 py-2.5">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#EFE9DF] bg-[#FFFDF9]">
                {recentSignIns.map((entry) => (
                  <tr key={entry.id}>
                    <td className="px-4 py-2.5 font-medium text-[#16161D] flex items-center space-x-2">
                      <Laptop className="w-3.5 h-3.5 text-[#6F6C7A]" />
                      <span>
                        {entry.deviceType} · {entry.browserSummary}
                      </span>
                      {entry.isNewDevice && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-100 text-amber-900 text-[10px] font-semibold">
                          New device
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-[#464451]">{entry.method}</td>
                    <td className="px-4 py-2.5 font-mono-tech text-[11px] text-[#6F6C7A]">
                      {entry.ipPrefixHash}
                    </td>
                    <td className="px-4 py-2.5 text-[#6F6C7A]">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Inactivity timeout + Sign out of all devices + Sensitive Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-3 border-t border-[#E5DDD0]">
        <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#16161D] flex items-center space-x-1.5">
              <Clock className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Inactivity auto-signout</span>
            </span>
            <select
              aria-label="Inactivity auto-signout duration"
              value={inactivityDays}
              onChange={(e) => void handleInactivityChange(Number(e.target.value))}
              className="px-2.5 py-1 rounded-lg border border-[#D8CEC0] bg-white text-xs font-semibold text-[#16161D]"
            >
              <option value={1}>1 day</option>
              <option value={3}>3 days</option>
              <option value={7}>7 days</option>
              <option value={14}>14 days (Default)</option>
              <option value={30}>30 days</option>
            </select>
          </div>
          <p className="text-[11px] text-[#6F6C7A]">
            Automatically signs out idle sessions after {inactivityDays} days of inactivity.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() => void handleSignOutAllDevices()}
            className="w-full px-3.5 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center justify-center space-x-1.5 disabled:opacity-50"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign out of all devices</span>
          </button>
        </div>

        <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-3">
          <p className="text-xs font-semibold text-[#16161D]">
            Sensitive Account Actions (Re-auth required)
          </p>
          {firebaseUser && (
            <div className="flex space-x-2">
              <input
                type="email"
                value={newEmailInput}
                onChange={(e) => setNewEmailInput(e.target.value)}
                placeholder="New email address"
                className="flex-1 px-3 py-1.5 rounded-xl border border-[#D8CEC0] bg-white text-xs text-[#16161D]"
              />
              <button
                type="button"
                disabled={busy || !newEmailInput.includes('@')}
                onClick={() =>
                  setPendingAction({ type: 'change_email', newEmail: newEmailInput.trim() })
                }
                className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] bg-white hover:bg-[#EFE9DF] text-xs font-semibold text-[#16161D] disabled:opacity-50 whitespace-nowrap"
              >
                Change Email
              </button>
            </div>
          )}

          <div className="flex space-x-2 pt-1">
            <input
              type="text"
              value={deleteConfirmText}
              onChange={(e) => setDeleteConfirmText(e.target.value)}
              placeholder='Type "DELETE" to confirm'
              className="flex-1 px-3 py-1.5 rounded-xl border border-red-200 bg-white text-xs text-[#16161D]"
            />
            <button
              type="button"
              disabled={busy || deleteConfirmText.trim().toUpperCase() !== 'DELETE'}
              onClick={() => setPendingAction({ type: 'delete_account' })}
              className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold flex items-center space-x-1 disabled:opacity-40 whitespace-nowrap"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Delete Account</span>
            </button>
          </div>
          <p className="text-[10px] text-[#6F6C7A]">User ID: {userId}</p>
        </div>
      </div>
    </div>
  );
}
