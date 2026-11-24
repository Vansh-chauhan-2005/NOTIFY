'use client';

import React from 'react';
import {
  X,
  Layers,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Info,
  Split,
  ThumbsDown,
} from 'lucide-react';
import type { DedupDecisionResult, DedupThreadMetadata } from '../lib/dedup/types.js';

export interface InspectedDedupTarget {
  thread: DedupThreadMetadata;
  decision?: DedupDecisionResult;
  memberSummaries?: Array<{
    notificationId: string;
    preview: string;
    priority: string;
    similarity: number;
    timestamp: string;
  }>;
}

interface DedupWhyDrawerProps {
  target: InspectedDedupTarget | null;
  onClose: () => void;
  onUngroup?: (threadId: string) => void;
  onMarkNotDuplicate?: (threadId: string) => void;
}

export default function DedupWhyDrawer({
  target,
  onClose,
  onUngroup,
  onMarkNotDuplicate,
}: DedupWhyDrawerProps) {
  if (!target) return null;

  const { thread, decision, memberSummaries } = target;
  const pct = Math.round((decision?.similarity ?? thread.lastSimilarity ?? 0) * 100);
  const mergePct = Math.round((decision?.thresholdUsed ?? 0.88) * 100);
  const reviewPct = Math.round((decision?.reviewThresholdUsed ?? 0.78) * 100);

  return (
    <div
      className="fixed inset-0 z-50 bg-[#16161D]/55 backdrop-blur-xs flex items-center justify-end"
      role="dialog"
      aria-modal="true"
      aria-label="Why notifications were grouped"
    >
      <div className="w-full max-w-lg h-full bg-[#FFFDF9] border-l border-[#E5DDD0] shadow-2xl overflow-y-auto p-6 space-y-5 text-[#16161D]">
        {/* Header */}
        <div className="flex items-start justify-between gap-3 border-b border-[#E5DDD0] pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
                <Layers className="w-4 h-4" />
              </div>
              <h3 className="font-display text-lg font-semibold">
                Why Was This Grouped?
              </h3>
            </div>
            <p className="text-xs text-[#6F6C7A] font-mono-tech">
              Thread {thread.threadId} · Stage: {decision?.stageMatched || thread.stageMatched}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#E5DDD0] text-[#464451]"
            aria-label="Close drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Decision & Similarity Score Summary */}
        <div className="rounded-2xl bg-[#16161D] text-[#FAF6F0] p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-[#D8CEC0]">Similarity Match Score</span>
            <span className="font-mono-tech text-lg font-semibold text-[#F472B6]">
              {pct}%
            </span>
          </div>
          <div className="w-full h-2 rounded-full bg-[#2A2935] overflow-hidden">
            <div
              className="h-full bg-[#D9468F] transition-all"
              style={{ width: `${Math.max(4, Math.min(100, pct))}%` }}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between text-[11px] text-[#D8CEC0] font-mono-tech gap-2">
            <span>Merge threshold: {mergePct}%</span>
            <span>Suggest threshold: {reviewPct}%</span>
            <span>
              Engine:{' '}
              {decision?.modelMode === 'onnx_minilm'
                ? 'ONNX MiniLM-L6-v2'
                : decision?.modelMode === 'tfidf_lightweight'
                ? 'Lightweight TF-IDF'
                : thread.stageMatched}
            </span>
          </div>
          <p className="text-xs text-[#FAF6F0]/90 pt-1 border-t border-white/10">
            {decision?.whySummary ||
              `Grouped ${thread.memberCount} related alert(s) under ${thread.stageMatched} with lowest trust ${thread.lowestTrust}.`}
          </p>
        </div>

        {/* Thread Metadata */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Members</div>
            <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5">
              {thread.memberCount}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Top Priority</div>
            <div className="font-mono-tech font-semibold text-[#B52A70] mt-0.5">
              {thread.topPriority}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Thread Trust</div>
            <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5 truncate">
              {thread.lowestTrust}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Status</div>
            <div className="font-mono-tech font-semibold text-[#15803D] mt-0.5">
              {thread.status}
            </div>
          </div>
        </div>

        {/* Safety Guard Checks */}
        <div className="space-y-2.5">
          <h4 className="text-xs font-semibold text-[#16161D] flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-[#D9468F]" />
            <span>Safety Guard Checks</span>
          </h4>
          {decision?.guards && decision.guards.length > 0 ? (
            <div className="space-y-2">
              {decision.guards.map((g, idx) => (
                <div
                  key={`${g.guard}_${idx}`}
                  className={`p-3 rounded-xl border text-xs flex items-start gap-2.5 ${
                    g.passed
                      ? 'bg-[#F0F7F4] border-[#16A34A]/25 text-[#14532D]'
                      : 'bg-amber-50 border-amber-300 text-amber-950'
                  }`}
                >
                  {g.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="font-mono-tech font-semibold text-[11px]">{g.guard}</div>
                    <div className="text-[11px] leading-relaxed">{g.reason}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs text-[#464451]">
              All safety guards passed before merging into this thread (no conflicting entities, negations, security categories, or provenance mismatches).
            </div>
          )}
        </div>

        {/* Member List Preview (Volatile Device Memory Only) */}
        {memberSummaries && memberSummaries.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-[#16161D]">
              Grouped Members ({memberSummaries.length}) — Shown On-Device Only
            </h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
              {memberSummaries.map((m) => (
                <div
                  key={m.notificationId}
                  className="p-2.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs space-y-1"
                >
                  <div className="flex items-center justify-between gap-2 font-mono-tech text-[11px] text-[#6F6C7A]">
                    <span>{m.priority}</span>
                    <span>{Math.round(m.similarity * 100)}% match</span>
                  </div>
                  <p className="text-[#16161D] leading-snug">{m.preview}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* User Controls */}
        {(onUngroup || onMarkNotDuplicate) && (
          <div className="flex flex-wrap items-center gap-2.5 pt-2 border-t border-[#E5DDD0]">
            {thread.memberCount > 1 && onUngroup && (
              <button
                type="button"
                onClick={() => {
                  onUngroup(thread.threadId);
                  onClose();
                }}
                className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] flex items-center gap-1.5"
              >
                <Split className="w-3.5 h-3.5 text-[#F472B6]" />
                <span>Ungroup Thread</span>
              </button>
            )}
            {onMarkNotDuplicate && (
              <button
                type="button"
                onClick={() => {
                  onMarkNotDuplicate(thread.threadId);
                  onClose();
                }}
                className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FCECF4] hover:bg-[#F9D8E9] text-[#B52A70] border border-[#F2C4DC] flex items-center gap-1.5"
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                <span>Not a Duplicate (Adapt Threshold)</span>
              </button>
            )}
          </div>
        )}

        {/* Honesty Info Panel */}
        <div className="rounded-2xl bg-[#F2ECE2]/70 border border-[#D8CEC0] p-4 space-y-2 text-xs text-[#464451]">
          <div className="font-semibold text-[#16161D] flex items-center gap-1.5">
            <Info className="w-4 h-4 text-[#D9468F]" />
            <span>How Deduplication Works</span>
          </div>
          <p className="leading-relaxed text-[11px]">
            Semantic deduplication is a <strong>similarity heuristic</strong> combining Exact SHA-256,
            MinHash/Jaccard, and 384-dim embeddings (<em>Xenova/all-MiniLM-L6-v2</em> in a browser
            Web Worker, with automatic TF-IDF fallback). It can still make mistakes on terse alerts.
          </p>
          <ul className="list-disc pl-4 space-y-1 text-[11px]">
            <li>
              <strong>Strict Zero-Text &amp; Zero-Vector Privacy:</strong> Embeddings and raw text exist
              only in volatile browser RAM. Firestore and server APIs store only IDs, counts, and status.
            </li>
            <li>
              <strong>Active Thresholds:</strong> Merge &ge; {mergePct}%, Review &ge; {reviewPct}%, 30-min window.
            </li>
            <li>
              <strong>Anti-Suppression:</strong> CRITICAL, security, OTP, entity-distinct (amounts/IDs),
              and recovery/negation updates are never suppressed or merged.
            </li>
          </ul>
          <div className="flex items-center gap-1.5 text-[11px] text-[#6F6C7A] pt-1">
            <ShieldAlert className="w-3.5 h-3.5 text-[#D9468F] shrink-0" />
            <span>Lowest verified member trust sets the thread trust badge.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
