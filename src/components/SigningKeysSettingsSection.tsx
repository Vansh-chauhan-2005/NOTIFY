'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  KeyRound,
  Lock,
  Unlock,
  RefreshCw,
  ShieldAlert,
  Download,
  Upload,
  Fingerprint,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  X,
} from 'lucide-react';
import {
  createEncryptedSigningKeyBundle,
  loadEncryptedKeyBundleLocally,
  saveEncryptedKeyBundleLocally,
  unlockEncryptedSigningKeyBundle,
  type EncryptedSigningKeyBundle,
  type UnlockedSigningKey,
} from '../lib/provenance/browserCrypto.js';
import type { KeyLogEntry, ProvenanceKeyRecord } from '../lib/provenance/types.js';
import { safeReadJson } from '../lib/http/safeJson.js';

interface SigningKeysSettingsSectionProps {
  userId: string;
  unlockedKey: UnlockedSigningKey | null;
  onUnlockedKeyChange: (key: UnlockedSigningKey | null) => void;
}

export default function SigningKeysSettingsSection({
  userId,
  unlockedKey,
  onUnlockedKeyChange,
}: SigningKeysSettingsSectionProps) {
  const [localBundle, setLocalBundle] = useState<EncryptedSigningKeyBundle | null>(null);
  const [serverKeys, setServerKeys] = useState<ProvenanceKeyRecord[]>([]);
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);
  const [revokeReason, setRevokeReason] = useState('Key rotated or device replaced');
  const [showKeyLogModal, setShowKeyLogModal] = useState(false);
  const [keyLogEntries, setKeyLogEntries] = useState<KeyLogEntry[]>([]);

  const loadState = useCallback(async () => {
    const bundle = loadEncryptedKeyBundleLocally(userId);
    setLocalBundle(bundle);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch(`/api/v1/provenance/keys/${encodeURIComponent(userId)}`, {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      const data = await safeReadJson(res);
      if (res.ok && data?.success) {
        setServerKeys(data.data?.keys || []);
      }
    } catch {
      // non-fatal
    }
  }, [userId]);

  useEffect(() => {
    void loadState();
  }, [loadState]);

  const registerPublicKeyOnServer = async (publicKey: string, endpoint: string, bodyExtras = {}) => {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    if (!token) throw new Error('Session token missing. Please sign in again.');

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        publicKey,
        newPublicKey: publicKey,
        ...bodyExtras,
      }),
    });
    const data = await safeReadJson(res);
    if (!res.ok || !data?.success) {
      throw new Error(data?.message || `Key operation failed (HTTP ${res.status}).`);
    }
    return data.data;
  };

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    setBusy(true);
    try {
      const { bundle, unlocked } = await createEncryptedSigningKeyBundle(userId, passphrase);
      await registerPublicKeyOnServer(bundle.publicKey, '/api/v1/provenance/keys', {
        reason: 'Initial browser Ed25519 signing key registration',
      });
      saveEncryptedKeyBundleLocally(bundle);
      setLocalBundle(bundle);
      onUnlockedKeyChange(unlocked);
      setPassphrase('');
      setFeedback({
        type: 'success',
        message: `Ed25519 key ${bundle.kid} generated in browser (private seed encrypted with PBKDF2 + AES-GCM) and public key registered.`,
      });
      await loadState();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Unable to generate signing key.' });
    } finally {
      setBusy(false);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!localBundle) return;
    setFeedback(null);
    setBusy(true);
    try {
      const unlocked = await unlockEncryptedSigningKeyBundle(localBundle, passphrase);
      onUnlockedKeyChange(unlocked);
      setPassphrase('');
      // Ensure registered on server if missing after dev reload
      if (!serverKeys.some((k) => k.kid === localBundle.kid)) {
        await registerPublicKeyOnServer(localBundle.publicKey, '/api/v1/provenance/keys').catch(
          () => {}
        );
        await loadState();
      }
      setFeedback({
        type: 'success',
        message: `Signing key ${unlocked.kid} unlocked into volatile memory.`,
      });
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Incorrect passphrase.' });
    } finally {
      setBusy(false);
    }
  };

  const handleLock = () => {
    unlockedKey?.wipe();
    onUnlockedKeyChange(null);
    setFeedback({
      type: 'success',
      message: 'Signing key wiped from browser RAM. Unlock with your passphrase to sign again.',
    });
  };

  const handleRotate = async () => {
    if (!passphrase || passphrase.length < 8) {
      setFeedback({
        type: 'error',
        message: 'Enter an 8+ character passphrase above to encrypt your newly rotated key.',
      });
      return;
    }
    setBusy(true);
    setFeedback(null);
    try {
      const oldKid = localBundle?.kid || unlockedKey?.kid;
      const { bundle, unlocked } = await createEncryptedSigningKeyBundle(userId, passphrase);
      await registerPublicKeyOnServer(bundle.publicKey, '/api/v1/provenance/keys/rotate', {
        oldKid,
        reason: 'User-initiated key rotation',
      });
      unlockedKey?.wipe();
      saveEncryptedKeyBundleLocally(bundle);
      setLocalBundle(bundle);
      onUnlockedKeyChange(unlocked);
      setPassphrase('');
      setFeedback({
        type: 'success',
        message: `Key rotated to ${bundle.kid}. Prior key ${oldKid || ''} remains valid only for pre-rotation messages.`,
      });
      await loadState();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Key rotation failed.' });
    } finally {
      setBusy(false);
    }
  };

  const handleRevoke = async () => {
    const targetKid = activeServerKey?.kid || localBundle?.kid;
    if (!targetKid) return;
    setBusy(true);
    setFeedback(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch('/api/v1/provenance/keys/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          kid: targetKid,
          reason: revokeReason.trim() || 'User-initiated revocation',
        }),
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data?.success) {
        throw new Error(data?.message || 'Failed to revoke key.');
      }
      unlockedKey?.wipe();
      onUnlockedKeyChange(null);
      setShowRevokeConfirm(false);
      setFeedback({
        type: 'success',
        message: `Key ${targetKid} permanently revoked in registry and transparency log.`,
      });
      await loadState();
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Key revocation failed.' });
    } finally {
      setBusy(false);
    }
  };

  const handleExportBackup = () => {
    if (!localBundle) return;
    const blob = new Blob([JSON.stringify(localBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-ed25519-encrypted-backup-${localBundle.kid}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportBackup = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (parsed?.v !== 1 || parsed?.alg !== 'Ed25519' || !parsed?.encryptedPrivateKey) {
        throw new Error('Invalid encrypted Ed25519 backup JSON.');
      }
      saveEncryptedKeyBundleLocally({ ...parsed, userId });
      setLocalBundle({ ...parsed, userId });
      setFeedback({
        type: 'success',
        message: `Imported encrypted backup for key ${parsed.kid}. Unlock with your passphrase.`,
      });
    } catch (err: any) {
      setFeedback({ type: 'error', message: err?.message || 'Failed to import key backup.' });
    }
    e.target.value = '';
  };

  const handleViewTransparencyLog = async () => {
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch(
        `/api/v1/provenance/keylog?userId=${encodeURIComponent(userId)}&limit=50`,
        {
          headers: {
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        }
      );
      const data = await safeReadJson(res);
      if (res.ok && data?.success) {
        setKeyLogEntries(data.data?.entries || []);
      }
      setShowKeyLogModal(true);
    } catch {
      setShowKeyLogModal(true);
    }
  };

  const activeServerKey = serverKeys.find((k) => k.status === 'ACTIVE') || serverKeys[0] || null;
  const displayKid = unlockedKey?.kid || localBundle?.kid || activeServerKey?.kid;
  const displayFpHex =
    unlockedKey?.fingerprintHex || localBundle?.fingerprintHex || activeServerKey?.fingerprintHex;
  const displayFpWords =
    unlockedKey?.fingerprintWords ||
    localBundle?.fingerprintWords ||
    activeServerKey?.fingerprintWords ||
    [];

  return (
    <div className="bg-[#FFFDF9] border border-[#16161D]/10 rounded-xl p-6 space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#16161D]/10 pb-4">
        <div>
          <h3 className="text-base font-bold text-[#16161D] flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-[#D9468F]" />
            Signing Keys (Zero-Trust Ed25519 Provenance)
          </h3>
          <p className="text-xs text-[#16161D]/65 mt-1 max-w-2xl">
            Private signing seeds are generated and encrypted in your browser with PBKDF2-HMAC-SHA256
            + AES-256-GCM and NEVER leave your device. Only your public key is published.
          </p>
        </div>

        <button
          type="button"
          onClick={handleViewTransparencyLog}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#16161D] text-[#FAF6F0] text-xs font-semibold hover:bg-[#23232E] transition"
        >
          <FileSearch className="w-3.5 h-3.5 text-[#F472B6]" />
          Transparency Log
        </button>
      </div>

      {feedback && (
        <div
          className={`p-3 rounded-lg text-xs border flex items-start gap-2 ${
            feedback.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-900'
              : 'bg-red-500/10 border-red-500/30 text-red-900'
          }`}
        >
          {feedback.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-700 mt-0.5" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-700 mt-0.5" />
          )}
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Active Key Summary Card */}
      {displayKid ? (
        <div className="p-4 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-[#F472B6]" />
              <span className="text-xs font-mono font-bold text-[#F472B6]">
                kid: {displayKid}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                  activeServerKey?.status === 'REVOKED'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : activeServerKey?.status === 'ROTATED'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                }`}
              >
                Registry: {activeServerKey?.status || 'LOCAL'}
              </span>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                  unlockedKey
                    ? 'bg-emerald-500/20 text-emerald-300'
                    : 'bg-white/10 text-[#FAF6F0]/75'
                }`}
              >
                {unlockedKey ? (
                  <>
                    <Unlock className="w-3 h-3" /> Unlocked in RAM
                  </>
                ) : (
                  <>
                    <Lock className="w-3 h-3" /> Locked
                  </>
                )}
              </span>
            </div>
          </div>

          {displayFpHex && (
            <div className="font-mono text-xs bg-black/35 p-2.5 rounded-lg border border-white/10 break-all">
              {displayFpHex}
            </div>
          )}

          {displayFpWords.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {displayFpWords.map((word, idx) => (
                <span
                  key={`${word}-${idx}`}
                  className="px-2 py-0.5 rounded bg-[#D9468F]/15 border border-[#D9468F]/30 font-mono text-[11px] text-[#F472B6]"
                >
                  {word}
                </span>
              ))}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 pt-1">
            {unlockedKey && (
              <button
                type="button"
                onClick={handleLock}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-semibold transition"
              >
                <Lock className="w-3.5 h-3.5" /> Lock Key (Wipe RAM)
              </button>
            )}
            {localBundle && (
              <button
                type="button"
                onClick={handleExportBackup}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-semibold transition"
              >
                <Download className="w-3.5 h-3.5" /> Export Encrypted Backup
              </button>
            )}
            <button
              type="button"
              disabled={busy}
              onClick={handleRotate}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#D9468F] hover:bg-[#B52A70] text-white text-xs font-semibold transition disabled:opacity-50"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Rotate Key
            </button>
            {activeServerKey?.status !== 'REVOKED' && (
              <button
                type="button"
                disabled={busy}
                onClick={() => setShowRevokeConfirm(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/35 border border-red-400/40 text-red-200 text-xs font-semibold transition"
              >
                <ShieldAlert className="w-3.5 h-3.5" /> Revoke Key
              </button>
            )}
          </div>
        </div>
      ) : null}

      {/* Passphrase Form (Create or Unlock or Rotate) */}
      <form
        onSubmit={localBundle ? handleUnlock : handleCreateKey}
        className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3"
      >
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder={
            localBundle
              ? 'Enter passphrase to unlock key (or new passphrase to rotate)'
              : 'Create 8+ char passphrase to encrypt Ed25519 private key'
          }
          className="flex-1 px-3.5 py-2 rounded-lg bg-[#FAF6F0] border border-[#16161D]/15 text-xs text-[#16161D] focus:outline-none focus:border-[#D9468F]"
        />
        <button
          type="submit"
          disabled={busy || !passphrase}
          className="px-4 py-2 rounded-lg bg-[#D9468F] hover:bg-[#B52A70] text-white text-xs font-semibold transition disabled:opacity-50"
        >
          {busy
            ? 'Working...'
            : localBundle
            ? 'Unlock Signing Key'
            : 'Generate & Register Keypair'}
        </button>
        <label className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-[#16161D]/15 bg-[#FAF6F0] hover:bg-[#16161D]/5 text-xs font-semibold text-[#16161D] cursor-pointer">
          <Upload className="w-3.5 h-3.5" />
          Import Backup
          <input type="file" accept=".json" onChange={handleImportBackup} className="hidden" />
        </label>
      </form>

      {/* Confirmation Drawer/Modal for Key Revocation */}
      {showRevokeConfirm && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 space-y-3">
          <div className="flex items-start justify-between gap-2">
            <div>
              <h4 className="text-xs font-bold text-red-900">
                Confirm Permanent Key Revocation ({displayKid})
              </h4>
              <p className="text-[11px] text-red-800/80 mt-0.5">
                Any message signed at or after revocation will immediately fail verification with{' '}
                <code>REVOKED_KEY</code>. This action is recorded permanently in the Transparency Log.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setShowRevokeConfirm(false)}
              className="text-red-800 hover:text-red-950"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <input
            type="text"
            value={revokeReason}
            onChange={(e) => setRevokeReason(e.target.value)}
            placeholder="Revocation reason"
            className="w-full px-3 py-1.5 rounded bg-white border border-red-300 text-xs text-[#16161D]"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setShowRevokeConfirm(false)}
              className="px-3 py-1.5 rounded-lg border border-[#16161D]/15 text-xs font-semibold"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={handleRevoke}
              className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold"
            >
              Confirm Revocation
            </button>
          </div>
        </div>
      )}

      {/* User Key Transparency Log Modal */}
      {showKeyLogModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4">
          <div className="w-full max-w-2xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30 rounded-2xl shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/10">
              <span className="text-sm font-bold flex items-center gap-2">
                <FileSearch className="w-4 h-4 text-[#F472B6]" />
                Your Key Transparency Log Entries
              </span>
              <button
                type="button"
                onClick={() => setShowKeyLogModal(false)}
                className="p-1 rounded hover:bg-white/10"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="max-h-96 overflow-y-auto p-5 space-y-2.5 text-xs font-mono">
              {keyLogEntries.length === 0 ? (
                <div className="text-[#FAF6F0]/60">No KeyLog entries recorded for your user ID yet.</div>
              ) : (
                keyLogEntries.map((entry) => (
                  <div
                    key={`${entry.index}-${entry.entryHash}`}
                    className="p-3 rounded-lg bg-white/5 border border-white/10 space-y-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[#F472B6]">
                        #{entry.index} · {entry.type} · kid={entry.kid}
                      </span>
                      <span className="text-[11px] text-[#FAF6F0]/60">
                        {new Date(entry.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div className="truncate text-[11px] text-[#FAF6F0]/70">
                      entryHash: {entry.entryHash}
                    </div>
                    <div className="truncate text-[11px] text-[#FAF6F0]/55">
                      prevHash: {entry.prevHash}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
