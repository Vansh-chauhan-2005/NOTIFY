'use client';

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  X,
  Fingerprint,
  Clock,
  Link2,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Info,
  AlertTriangle,
} from 'lucide-react';
import type { ProvenanceVerificationReport } from '../lib/provenance/types.js';
import { acceptNewKeyPinAfterOverride } from '../lib/provenance/pinning.js';

interface ProvenanceStatusBadgeProps {
  report?: ProvenanceVerificationReport | null;
  onClick?: () => void;
  compact?: boolean;
}

export function ProvenanceStatusBadge({
  report,
  onClick,
  compact = false,
}: ProvenanceStatusBadgeProps) {
  const variant = report?.badgeVariant || 'unverified';
  const status = report?.status || 'UNSIGNED';

  let label = 'Unverified';
  let classes =
    'border-orange-500/40 bg-orange-500/15 text-orange-800 hover:bg-orange-500/25';
  let Icon = ShieldQuestion;

  if (variant === 'verified') {
    label = compact ? 'Verified (Ed25519)' : 'Verified (Ed25519)';
    classes =
      'border-emerald-500/40 bg-emerald-500/15 text-emerald-800 hover:bg-emerald-500/25';
    Icon = ShieldCheck;
  } else if (variant === 'gateway') {
    label = compact ? 'Gateway-attested' : 'Gateway-attested (Ed25519)';
    classes =
      'border-amber-500/40 bg-amber-500/15 text-amber-800 hover:bg-amber-500/25';
    Icon = ShieldCheck;
  } else if (variant === 'rejected') {
    if (status === 'REVOKED_KEY') {
      label = 'Revoked Key';
    } else if (status === 'INVALID_SIGNATURE') {
      label = 'Tampered / Invalid';
    } else {
      label = `Rejected (${status})`;
    }
    classes =
      'border-red-500/40 bg-red-500/15 text-red-800 hover:bg-red-500/25';
    Icon = ShieldAlert;
  }

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick?.();
      }}
      title={report?.reason || 'Inspect Ed25519 provenance chain'}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-semibold tracking-wide transition cursor-pointer ${classes}`}
    >
      <Icon className="w-3.5 h-3.5 shrink-0" />
      <span>{label}</span>
    </button>
  );
}

interface ProvenanceDetailsDrawerProps {
  report: ProvenanceVerificationReport | null;
  onClose: () => void;
  onPinOverridden?: () => void;
}

export function ProvenanceDetailsDrawer({
  report,
  onClose,
  onPinOverridden,
}: ProvenanceDetailsDrawerProps) {
  const [showCompareModal, setShowCompareModal] = useState(false);
  const [compareInput, setCompareInput] = useState('');
  const [copiedFp, setCopiedFp] = useState(false);
  const [overrideBusy, setOverrideBusy] = useState(false);

  if (!report) return null;

  const envPayload = report.envelope?.payload;
  const normalizedHex = (report.fingerprintHex || '').replace(/[^0-9A-Za-z]/g, '').toUpperCase();
  const normalizedCompare = compareInput.replace(/[^0-9A-Za-z]/g, '').toUpperCase();
  const matchesComparison =
    normalizedCompare.length >= 8 && normalizedHex.startsWith(normalizedCompare);

  const handleCopyFingerprint = async () => {
    const value = `${report.fingerprintHex || ''}${
      report.fingerprintWords?.length ? ` (${report.fingerprintWords.join(' ')})` : ''
    }`;
    try {
      await navigator.clipboard.writeText(value);
      setCopiedFp(true);
      setTimeout(() => setCopiedFp(false), 1800);
    } catch {
      // ignore clipboard errors
    }
  };

  const handleAcceptOverridePin = async () => {
    if (!report.signerId || !report.kid || !report.fingerprintHex) return;
    setOverrideBusy(true);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch(
        `/api/v1/provenance/keys/${encodeURIComponent(report.signerId)}`,
        {
          headers: {
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
        }
      );
      const json = await res.json();
      const targetKey = (json?.data?.keys || []).find((k: any) => k.kid === report.kid);
      if (targetKey?.publicKey) {
        await acceptNewKeyPinAfterOverride({
          userId: report.signerId,
          kid: report.kid,
          publicKey: targetKey.publicKey,
          fingerprintHex: report.fingerprintHex,
        });
        onPinOverridden?.();
      }
    } finally {
      setOverrideBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/55 backdrop-blur-xs">
      <div className="w-full max-w-lg h-full bg-[#16161D] text-[#FAF6F0] border-l border-[#D9468F]/30 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-[#1C1C26]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#D9468F]/20 border border-[#D9468F]/40 flex items-center justify-center">
              <Fingerprint className="w-4 h-4 text-[#F472B6]" />
            </div>
            <div>
              <h3 className="text-sm font-bold tracking-wide text-[#FAF6F0]">
                Ed25519 Provenance Inspector
              </h3>
              <p className="text-[11px] text-[#FAF6F0]/60 font-mono">
                Zero-Trust Chain Verification
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#FAF6F0]/60 hover:text-white hover:bg-white/10 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Status Summary Banner */}
          <div
            className={`p-4 rounded-xl border ${
              report.verified
                ? 'border-emerald-500/40 bg-emerald-500/10'
                : report.status === 'UNSIGNED'
                ? 'border-orange-500/40 bg-orange-500/10'
                : 'border-red-500/40 bg-red-500/10'
            }`}
          >
            <div className="flex items-center justify-between gap-3 mb-1.5">
              <span className="text-xs font-mono uppercase tracking-wider font-bold">
                Result: {report.status}
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-black/30">
                ALG: {report.alg}
              </span>
            </div>
            <p className="text-xs leading-relaxed text-[#FAF6F0]/90">{report.reason}</p>

            {report.status === 'KEY_MISMATCH' && report.signerId && report.kid && (
              <div className="mt-3 pt-3 border-t border-red-400/20 flex items-center justify-between gap-2">
                <span className="text-[11px] text-red-200 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  Key does not match TOFU pin. Only override after comparing fingerprint out-of-band.
                </span>
                <button
                  type="button"
                  disabled={overrideBusy}
                  onClick={handleAcceptOverridePin}
                  className="px-2.5 py-1 rounded bg-red-500/80 hover:bg-red-500 text-white text-[11px] font-semibold shrink-0 disabled:opacity-50"
                >
                  {overrideBusy ? 'Saving...' : 'Trust New Pin'}
                </button>
              </div>
            )}
          </div>

          {/* Core Signer & Key Metadata */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-white/5 border border-white/10">
              <span className="block text-[10px] uppercase tracking-wider text-[#FAF6F0]/50 mb-1">
                Signer Identity
              </span>
              <span className="font-mono text-[#FAF6F0] break-all">
                {report.signerId || envPayload?.senderId || 'None'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-white/5 border border-white/10">
              <span className="block text-[10px] uppercase tracking-wider text-[#FAF6F0]/50 mb-1">
                Key ID (kid)
              </span>
              <span className="font-mono text-[#F472B6] break-all">
                {report.kid || envPayload?.kid || 'Unsigned'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-white/5 border border-white/10">
              <span className="block text-[10px] uppercase tracking-wider text-[#FAF6F0]/50 mb-1">
                Source Path
              </span>
              <span className="font-mono text-[#FAF6F0]">
                {report.source || envPayload?.source || 'direct'}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-white/5 border border-white/10">
              <span className="block text-[10px] uppercase tracking-wider text-[#FAF6F0]/50 mb-1">
                Signed Timestamp
              </span>
              <span className="font-mono text-[#FAF6F0] text-[11px]">
                {report.createdAt
                  ? new Date(report.createdAt).toLocaleString()
                  : 'N/A'}
              </span>
            </div>
          </div>

          {/* Public Key Fingerprint & Out-of-band Comparison */}
          {report.fingerprintHex && (
            <div className="p-4 rounded-xl bg-white/5 border border-white/10 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-[#FAF6F0]/70 flex items-center gap-1.5">
                  <Fingerprint className="w-3.5 h-3.5 text-[#F472B6]" />
                  Key Fingerprint
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopyFingerprint}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-[11px]"
                  >
                    {copiedFp ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowCompareModal((v) => !v)}
                    className="px-2 py-0.5 rounded bg-[#D9468F]/25 hover:bg-[#D9468F]/40 border border-[#D9468F]/40 text-[#F472B6] text-[11px] font-medium"
                  >
                    Compare fingerprint
                  </button>
                </div>
              </div>

              <div className="font-mono text-xs tracking-wider text-[#FAF6F0] bg-black/35 p-2.5 rounded-lg border border-white/10 break-all">
                {report.fingerprintHex}
              </div>

              {report.fingerprintWords && report.fingerprintWords.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {report.fingerprintWords.map((w, idx) => (
                    <span
                      key={`${w}-${idx}`}
                      className="px-2 py-0.5 rounded bg-[#D9468F]/15 border border-[#D9468F]/30 font-mono text-[11px] text-[#F472B6]"
                    >
                      {w}
                    </span>
                  ))}
                </div>
              )}

              {showCompareModal && (
                <div className="mt-2 p-3 rounded-lg bg-black/40 border border-[#D9468F]/30 space-y-2">
                  <label className="block text-[11px] text-[#FAF6F0]/75">
                    Paste or type the sender’s fingerprint hex from a separate channel (min 8 chars):
                  </label>
                  <input
                    type="text"
                    value={compareInput}
                    onChange={(e) => setCompareInput(e.target.value)}
                    placeholder="e.g. A1B2-C3D4-..."
                    className="w-full px-3 py-1.5 rounded bg-[#16161D] border border-white/15 text-xs font-mono text-white focus:outline-none focus:border-[#D9468F]"
                  />
                  {normalizedCompare.length >= 8 && (
                    <div
                      className={`text-[11px] font-semibold flex items-center gap-1.5 ${
                        matchesComparison ? 'text-emerald-400' : 'text-red-400'
                      }`}
                    >
                      {matchesComparison ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" /> Match confirmed with key{' '}
                          {report.kid}.
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5" /> Mismatch! Do NOT trust without verifying.
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Vertical Attestation Chain Timeline */}
          <div className="space-y-2.5">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[#FAF6F0]/70 flex items-center gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-[#F472B6]" />
              Attestation Chain ({report.chain.length} {report.chain.length === 1 ? 'hop' : 'hops'})
            </h4>

            {report.chain.length === 0 ? (
              <div className="p-3 rounded-lg bg-white/5 border border-white/10 text-xs text-[#FAF6F0]/60">
                No cryptographic attestation hops recorded.
              </div>
            ) : (
              <div className="relative pl-4 border-l-2 border-[#D9468F]/35 space-y-3">
                {report.chain.map((hop, idx) => (
                  <div
                    key={`${hop.kid}-${idx}`}
                    className="relative p-3 rounded-lg bg-white/5 border border-white/10 space-y-1.5"
                  >
                    <span
                      className={`absolute -left-[23px] top-3.5 w-3 h-3 rounded-full border-2 border-[#16161D] ${
                        hop.verified ? 'bg-emerald-400' : 'bg-red-400'
                      }`}
                    />
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-[#FAF6F0]">
                        Hop #{idx + 1} · {hop.role}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          hop.verified
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-red-500/20 text-red-300'
                        }`}
                      >
                        {hop.status}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-[#FAF6F0]/75 space-y-0.5">
                      <div>Signer: {hop.signerId}</div>
                      <div>Key ID: {hop.kid}</div>
                      <div className="truncate">Parent Hash: {hop.parentHash}</div>
                      <div className="flex items-center gap-1 text-[#FAF6F0]/55">
                        <Clock className="w-3 h-3" />
                        {new Date(hop.signedAt).toLocaleString()}
                      </div>
                    </div>
                    <p className="text-[11px] text-[#FAF6F0]/75">{hop.reason}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Envelope Nonce & Ciphertext Digest */}
          {envPayload && (
            <div className="p-3.5 rounded-xl bg-black/35 border border-white/10 text-[11px] font-mono text-[#FAF6F0]/70 space-y-1">
              <div className="text-[10px] uppercase tracking-wider text-[#FAF6F0]/45 font-sans font-semibold mb-1">
                Envelope Cryptographic Binding
              </div>
              <div className="truncate">Message ID: {envPayload.messageId}</div>
              <div className="truncate">Nonce: {envPayload.nonce}</div>
              <div className="truncate">Ciphertext SHA-256: {envPayload.ciphertextHash}</div>
            </div>
          )}

          {/* Honesty Notice */}
          <div className="p-3.5 rounded-xl bg-[#D9468F]/10 border border-[#D9468F]/30 text-[11px] leading-relaxed text-[#FAF6F0]/80 flex gap-2">
            <Info className="w-4 h-4 text-[#F472B6] shrink-0 mt-0.5" />
            <div>
              <strong className="text-[#FAF6F0]">Cryptographic Scope:</strong> Ed25519 provides{' '}
              <strong>authenticity and integrity</strong> (proving who signed it and that fields
              were not altered). Confidentiality is provided separately by{' '}
              <strong>ECDH + AES-256-GCM encryption</strong>.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
