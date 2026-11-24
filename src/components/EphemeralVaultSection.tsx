'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Flame,
  Eye,
  EyeOff,
  Lock,
  Shield,
  Info,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import {
  EPHEMERAL_DELETION_LAYERS,
  SCREENSHOT_HONESTY_NOTE,
  formatCountdownMmSs,
} from '../lib/ephemeral/constants.js';
import { verifyAndDecryptEphemeralMessage } from '../lib/ephemeral/crypto.js';
import {
  ensureClientEphemeralKeyRing,
  getDecryptedEphemeralPlaintext,
  storeDecryptedEphemeralEntry,
  wipeDecryptedEphemeralEntry,
} from '../lib/ephemeral/clientMemory.js';
import { safeReadJson } from '../lib/http/safeJson.js';
import type {
  ProvenanceEnvelopeV1,
  ProvenanceVerificationReport,
} from '../lib/provenance/types.js';
import { verifyItemProvenanceOnClient } from '../lib/provenance/clientVerify.js';
import {
  ProvenanceDetailsDrawer,
  ProvenanceStatusBadge,
} from './ProvenanceBadgeAndDrawer.js';

export interface EphemeralInboxItem {
  id: string;
  senderId: string;
  recipientId: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  createdAt: string;
  expiresAt: string;
  ttlSeconds: number;
  status: 'ACTIVE' | 'READ' | 'BURNED' | 'EXPIRED';
  readOnce: boolean;
  remainingSeconds: number;
  provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
  provenanceReport?: ProvenanceVerificationReport | null;
}

interface EphemeralVaultSectionProps {
  userId: string;
  refreshSignal?: number;
  privacyShieldEnabled: boolean;
  isWindowBlurred: boolean;
  onChanged?: () => void;
}

function getUrgencyMeta(remainingSeconds: number): {
  label: string;
  stroke: string;
  badgeClass: string;
} {
  if (remainingSeconds > 120) {
    return {
      label: 'Safe (>2m)',
      stroke: '#16A34A',
      badgeClass: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    };
  }
  if (remainingSeconds >= 30) {
    return {
      label: 'Expiring Soon',
      stroke: '#D97706',
      badgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
    };
  }
  return {
    label: 'Final Seconds',
    stroke: '#DC2626',
    badgeClass: 'bg-red-50 text-red-700 border-red-200',
  };
}

export default function EphemeralVaultSection({
  userId,
  refreshSignal = 0,
  privacyShieldEnabled,
  isWindowBlurred,
  onChanged,
}: EphemeralVaultSectionProps) {
  const [items, setItems] = useState<EphemeralInboxItem[]>([]);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [decryptedViews, setDecryptedViews] = useState<Record<string, string>>({});
  const [busyId, setBusyId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(
    null
  );
  const [showHonestyInfo, setShowHonestyInfo] = useState(false);
  const [clientReports, setClientReports] = useState<
    Record<string, ProvenanceVerificationReport>
  >({});
  const [inspectedReport, setInspectedReport] = useState<ProvenanceVerificationReport | null>(null);
  const [unverifiedGateAcknowledged, setUnverifiedGateAcknowledged] = useState<
    Record<string, boolean>
  >({});

  const loadItems = useCallback(async () => {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    if (!token) return;

    await ensureClientEphemeralKeyRing(userId, token).catch(() => null);

    try {
      const res = await fetch('/api/v1/ephemeral', {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await safeReadJson(res);
      if (res.ok && data?.success && Array.isArray(data?.data?.items)) {
        const fetchedItems = data.data.items as EphemeralInboxItem[];
        setItems(fetchedItems);

        // Verify metadata envelopes on client proactively for items carrying provenance
        for (const item of fetchedItems) {
          if (item.provenanceEnvelope) {
            void verifyItemProvenanceOnClient({
              envelope: item.provenanceEnvelope,
              serverReport: item.provenanceReport,
              expectedRecipientId: item.recipientId,
              expectedMessageId: item.id,
              itemTimestamp: item.createdAt,
            }).then((report) => {
              setClientReports((prev) => ({ ...prev, [item.id]: report }));
            });
          }
        }
      }
    } catch {
      // Non-fatal polling error
    }
  }, [userId]);

  useEffect(() => {
    void loadItems();
  }, [loadItems, refreshSignal]);

  // Poll server active list every 4s
  useEffect(() => {
    const pollTimer = setInterval(() => {
      void loadItems();
    }, 4000);
    return () => clearInterval(pollTimer);
  }, [loadItems]);

  // 1-second local countdown tick that wipes memory & removes item immediately at 00:00
  useEffect(() => {
    const timer = setInterval(() => {
      const tickNow = Date.now();
      setNowMs(tickNow);

      setItems((prev) => {
        const surviving: EphemeralInboxItem[] = [];
        let removedAny = false;
        for (const item of prev) {
          const expMs = Date.parse(item.expiresAt);
          if (!Number.isFinite(expMs) || tickNow >= expMs) {
            wipeDecryptedEphemeralEntry(item.id);
            removedAny = true;
          } else {
            surviving.push(item);
          }
        }
        if (removedAny) {
          setDecryptedViews((curr) => {
            const next = { ...curr };
            for (const key of Object.keys(next)) {
              if (!surviving.some((s) => s.id === key)) {
                delete next[key];
              }
            }
            return next;
          });
        }
        return removedAny ? surviving : prev;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleDecryptAndRead = async (item: EphemeralInboxItem) => {
    setBusyId(item.id);
    setFeedback(null);
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    try {
      const keyRing = await ensureClientEphemeralKeyRing(userId, token);
      const res = await fetch(`/api/v1/ephemeral/${encodeURIComponent(item.id)}`, {
        method: 'GET',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data?.success || !data?.data?.envelope || !data?.data?.keyMaterial) {
        if (res.status === 410) {
          wipeDecryptedEphemeralEntry(item.id);
          setItems((prev) => prev.filter((i) => i.id !== item.id));
        }
        setFeedback({
          type: 'error',
          message: data?.message || `Unable to read ephemeral item (HTTP ${res.status}).`,
        });
        return;
      }

      const env = data.data.envelope;
      const km = data.data.keyMaterial;

      // Client-side Zero-Trust Ed25519 provenance verification BEFORE trusting/showing content
      const provReport = await verifyItemProvenanceOnClient({
        envelope: env.provenanceEnvelope,
        serverReport: env.provenanceReport || item.provenanceReport,
        expectedRecipientId: env.recipientId,
        expectedMessageId: env.id,
        expectedCiphertext: env.ciphertext,
        expectedIv: env.iv,
        itemTimestamp: env.createdAt,
      });
      setClientReports((prev) => ({ ...prev, [item.id]: provReport }));

      const decrypted = await verifyAndDecryptEphemeralMessage({
        envelope: env,
        wrappedDek: km.wrappedDek,
        wrapIv: km.wrapIv,
        recipientEcdhPrivateKey: keyRing.ecdhPrivateKey,
      });

      const expMs = Date.parse(env.expiresAt);
      storeDecryptedEphemeralEntry(item.id, decrypted.plaintext, decrypted.wipeHandle, expMs);
      setDecryptedViews((prev) => ({ ...prev, [item.id]: decrypted.plaintext }));
      setItems((prev) =>
        prev.map((i) =>
          i.id === item.id
            ? {
                ...i,
                expiresAt: env.expiresAt,
                status: env.status,
                remainingSeconds: env.remainingSeconds,
                provenanceEnvelope: env.provenanceEnvelope,
                provenanceReport: provReport,
              }
            : i
        )
      );
      if (!provReport.verified && env.provenanceEnvelope) {
        setFeedback({
          type: 'error',
          message: `Ed25519 Provenance rejected [${provReport.status}]: ${provReport.reason} Plaintext held behind warning gate.`,
        });
      } else if (item.readOnce) {
        setFeedback({
          type: 'success',
          message: 'Read-Once activated: 10s viewing grace countdown started.',
        });
      }
      onChanged?.();
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Decryption failed (key unavailable or destroyed).',
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleHidePlaintext = (id: string) => {
    wipeDecryptedEphemeralEntry(id);
    setDecryptedViews((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  };

  const handleBurnNow = async (item: EphemeralInboxItem) => {
    setBusyId(item.id);
    setFeedback(null);
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    try {
      const res = await fetch(`/api/v1/ephemeral/${encodeURIComponent(item.id)}/burn`, {
        method: 'POST',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      const data = await safeReadJson(res);
      wipeDecryptedEphemeralEntry(item.id);
      setDecryptedViews((prev) => {
        const next = { ...prev };
        delete next[item.id];
        return next;
      });
      setItems((prev) => prev.filter((i) => i.id !== item.id));
      setFeedback({
        type: res.ok ? 'success' : 'error',
        message:
          data?.message ||
          (res.ok ? 'Item burned and crypto-shredded.' : 'Failed to burn item.'),
      });
      onChanged?.();
    } catch (err: any) {
      setFeedback({
        type: 'error',
        message: err?.message || 'Network error burning ephemeral item.',
      });
    } finally {
      setBusyId(null);
    }
  };

  const shieldBlurred = privacyShieldEnabled && isWindowBlurred;

  return (
    <div className="glass-panel rounded-2xl border border-[#F2C4DC] bg-gradient-to-br from-[#FFFDF9] to-[#FCECF4]/45 p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-xl bg-[#16161D] text-[#F472B6] flex items-center justify-center shrink-0">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="font-display text-sm font-semibold text-[#16161D]">
                Ephemeral Self-Destruct Vault
              </h3>
              <span className="px-2 py-0.5 rounded-full bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-[10px] font-mono-tech font-semibold">
                {items.length} Active
              </span>
            </div>
            <p className="text-[11px] text-[#6F6C7A]">
              Zero-persistence ECDH + AES-256-GCM memory vault · 300s default TTL · Crypto-shredded on expiry
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setShowHonestyInfo((prev) => !prev)}
          className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[11px] font-semibold text-[#464451] flex items-center space-x-1.5 whitespace-nowrap self-start sm:self-center"
        >
          <Info className="w-3.5 h-3.5 text-[#D9468F]" />
          <span>How Destruction Works</span>
          {showHonestyInfo ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {showHonestyInfo && (
        <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-3 text-xs">
          <div className="font-semibold text-[#16161D] flex items-center space-x-1.5">
            <Shield className="w-4 h-4 text-[#D9468F]" />
            <span>4-Layer Ephemeral Destruction Architecture (No False Claims)</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {EPHEMERAL_DELETION_LAYERS.map((layer) => (
              <div
                key={layer.layer}
                className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 space-y-1"
              >
                <p className="font-semibold text-[#16161D] text-[11px]">{layer.layer}</p>
                <p className="text-[11px] text-[#464451] leading-relaxed">{layer.description}</p>
              </div>
            ))}
          </div>
          <div className="rounded-xl bg-amber-50 border border-amber-200 px-3 py-2 text-[11px] text-amber-900 flex items-start space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
            <span>{SCREENSHOT_HONESTY_NOTE}</span>
          </div>
        </div>
      )}

      {feedback && (
        <div
          className={`rounded-xl px-3.5 py-2 text-xs border ${
            feedback.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-red-50 border-red-200 text-red-700'
          }`}
        >
          {feedback.message}
        </div>
      )}

      {items.length === 0 ? (
        <div className="rounded-2xl bg-[#FFFDF9]/80 border border-dashed border-[#D8CEC0] px-5 py-6 text-center space-y-1">
          <p className="text-xs font-medium text-[#16161D]">No active ephemeral messages right now</p>
          <p className="text-[11px] text-[#6F6C7A]">
            Toggle &ldquo;Ephemeral (self-destruct in 5 min)&rdquo; in the Dispatch Simulator to send an isolated, crypto-shredding item.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => {
            const expMs = Date.parse(item.expiresAt);
            const remaining = Math.max(0, Math.ceil((expMs - nowMs) / 1000));
            const totalTtl = Math.max(1, item.ttlSeconds || 300);
            const pct = Math.max(0, Math.min(1, remaining / totalTtl));
            const radius = 16;
            const circumference = 2 * Math.PI * radius;
            const dashOffset = circumference * (1 - pct);
            const urgency = getUrgencyMeta(remaining);
            const openPlaintext =
              decryptedViews[item.id] ?? getDecryptedEphemeralPlaintext(item.id);
            const isSender = item.senderId === userId;
            const effectiveReport: ProvenanceVerificationReport = clientReports[item.id] ||
              item.provenanceReport || {
                status: 'UNSIGNED',
                verified: false,
                reason: 'No Ed25519 provenance envelope attached to this ephemeral item.',
                alg: 'NONE',
                badgeVariant: 'unverified',
                chain: [],
              };
            const needsWarningGate =
              Boolean(openPlaintext) &&
              !effectiveReport.verified &&
              !unverifiedGateAcknowledged[item.id];

            return (
              <div
                key={item.id}
                className="rounded-2xl bg-[#FFFDF9] border border-[#E5DDD0] p-4 space-y-3 shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    {/* Live SVG Countdown Ring */}
                    <div className="relative w-11 h-11 flex items-center justify-center shrink-0">
                      <svg className="w-11 h-11 -rotate-90" viewBox="0 0 40 40">
                        <circle
                          cx="20"
                          cy="20"
                          r={radius}
                          fill="none"
                          stroke="#F2ECE2"
                          strokeWidth="3.5"
                        />
                        <circle
                          cx="20"
                          cy="20"
                          r={radius}
                          fill="none"
                          stroke={urgency.stroke}
                          strokeWidth="3.5"
                          strokeDasharray={circumference}
                          strokeDashoffset={dashOffset}
                          strokeLinecap="round"
                        />
                      </svg>
                      <span className="absolute font-mono-tech text-[10px] font-bold text-[#16161D] tabular-nums">
                        {formatCountdownMmSs(remaining)}
                      </span>
                    </div>

                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${urgency.badgeClass}`}
                        >
                          {urgency.label}
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold bg-[#16161D] text-[#FAF6F0]">
                          {item.priority}
                        </span>
                        <ProvenanceStatusBadge
                          report={effectiveReport}
                          compact
                          onClick={() => setInspectedReport(effectiveReport)}
                        />
                        {item.readOnce && (
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC]">
                            {item.status === 'READ' ? 'Read Once · 10s Grace' : 'Read Once'}
                          </span>
                        )}
                        <span className="text-[11px] font-mono-tech text-[#6F6C7A]">
                          {isSender ? `To: ${item.recipientId}` : `From: ${item.senderId}`}
                        </span>
                      </div>

                      <div className="text-[11px] text-[#6F6C7A] font-mono-tech flex items-center space-x-2">
                        <Lock className="w-3 h-3 text-[#16A34A]" />
                        <span>ID: {item.id}</span>
                        <span aria-hidden="true">·</span>
                        <Clock className="w-3 h-3 text-[#6F6C7A]" />
                        <span>Self-destructs at {new Date(item.expiresAt).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {openPlaintext ? (
                      <button
                        type="button"
                        onClick={() => handleHidePlaintext(item.id)}
                        className="px-3 py-1.5 rounded-xl border border-[#D8CEC0] bg-[#FAF6F0] hover:bg-[#F2ECE2] text-xs font-semibold text-[#16161D] flex items-center space-x-1.5 whitespace-nowrap"
                      >
                        <EyeOff className="w-3.5 h-3.5" />
                        <span>Mask View</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={busyId === item.id}
                        onClick={() => void handleDecryptAndRead(item)}
                        className="px-3.5 py-1.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                      >
                        <Eye className="w-3.5 h-3.5 text-[#F472B6]" />
                        <span>{busyId === item.id ? 'Decrypting...' : 'Decrypt & Read'}</span>
                      </button>
                    )}

                    <button
                      type="button"
                      disabled={busyId === item.id}
                      onClick={() => void handleBurnNow(item)}
                      className="px-3 py-1.5 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                      title={
                        isSender
                          ? 'Recall & crypto-shred immediately for everyone'
                          : 'Burn & crypto-shred immediately'
                      }
                    >
                      <Flame className="w-3.5 h-3.5" />
                      <span>{isSender ? 'Burn / Recall' : 'Burn Now'}</span>
                    </button>
                  </div>
                </div>

                {openPlaintext && needsWarningGate && (
                  <div className="rounded-xl bg-red-500/10 border border-red-400/40 p-3.5 space-y-2 text-xs text-red-900">
                    <div className="font-semibold flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-red-700 shrink-0" />
                      <span>
                        Unverified Provenance [{effectiveReport.status}] — Content Collapsed
                      </span>
                    </div>
                    <p className="text-[11px] leading-relaxed">{effectiveReport.reason}</p>
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <button
                        type="button"
                        onClick={() => setInspectedReport(effectiveReport)}
                        className="px-2.5 py-1 rounded-lg bg-white border border-red-300 text-[11px] font-semibold text-red-900"
                      >
                        Inspect Provenance
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setUnverifiedGateAcknowledged((prev) => ({
                            ...prev,
                            [item.id]: true,
                          }))
                        }
                        className="px-2.5 py-1 rounded-lg bg-red-700 hover:bg-red-800 text-white text-[11px] font-semibold"
                      >
                        Reveal Unverified Plaintext Anyway
                      </button>
                    </div>
                  </div>
                )}

                {openPlaintext && !needsWarningGate && (
                  <div className="relative rounded-xl bg-[#16161D] text-[#FAF6F0] p-3.5 border border-[#D9468F]/40">
                    <div className="text-[10px] font-mono-tech text-[#F472B6] mb-1 flex items-center justify-between">
                      <span>
                        VOLATILE MEMORY ONLY ·{' '}
                        {effectiveReport.verified
                          ? `ED25519 VERIFIED (${effectiveReport.kid})`
                          : `UNVERIFIED (${effectiveReport.status})`}{' '}
                        · AES-256-GCM DECRYPTED
                      </span>
                      <span>NEVER WRITTEN TO DISK</span>
                    </div>
                    <p
                      className={`text-sm leading-relaxed select-none transition-all ${
                        shieldBlurred ? 'blur-md opacity-40' : ''
                      }`}
                    >
                      {openPlaintext}
                    </p>
                    {shieldBlurred && (
                      <div className="mt-2 text-[11px] text-[#F472B6] font-medium">
                        Privacy Shield active: window unfocused — plaintext blurred.
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <ProvenanceDetailsDrawer
        report={inspectedReport}
        onClose={() => setInspectedReport(null)}
        onPinOverridden={() => {
          setInspectedReport(null);
          void loadItems();
        }}
      />
    </div>
  );
}
