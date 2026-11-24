'use client';

import React, { useState } from 'react';
import {
  X,
  Sliders,
  ShieldCheck,
  TrendingUp,
  Info,
  ThumbsUp,
  ThumbsDown,
  AlertOctagon,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ReferenceLine,
} from 'recharts';
import type {
  PriorityFeedbackKind,
  PriorityScoreBreakdown,
} from '../lib/priority/types.js';
import { safeReadJson } from '../lib/http/safeJson.js';

export interface PriorityInspectableItem {
  notificationId: string;
  eventType: string;
  timestamp: string;
  priority?: string;
  dispatchScore: number;
  ackState?: 'PENDING' | 'ACKED' | 'TIMEOUT_ESCALATED';
  priorityEngine?: PriorityScoreBreakdown | null;
}

interface PriorityWhyDrawerProps {
  item: PriorityInspectableItem | null;
  onClose: () => void;
  onFeedbackSubmitted?: (feedbackKind: PriorityFeedbackKind, data: any) => void;
}

export function PriorityWhyDrawer({
  item,
  onClose,
  onFeedbackSubmitted,
}: PriorityWhyDrawerProps) {
  const [submittingKind, setSubmittingKind] = useState<PriorityFeedbackKind | null>(null);
  const [feedbackNotice, setFeedbackNotice] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  if (!item) return null;

  const breakdown = item.priorityEngine;

  const handleFeedback = async (feedbackKind: PriorityFeedbackKind) => {
    if (!breakdown?.features) return;
    setSubmittingKind(feedbackKind);
    setFeedbackNotice(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (!token) {
        throw new Error('Sign in with an active session token to submit personalization feedback.');
      }

      // Privacy guarantee: send ONLY numeric features (never message text)
      const res = await fetch('/api/v1/priority/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          feedbackKind,
          features: breakdown.features,
        }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Feedback failed (HTTP ${res.status}).`);
      }

      const d = json.data;
      setFeedbackNotice({
        type: 'success',
        message: `Recorded ${feedbackKind} · Feedback #${d?.updatedState?.feedbackCount ?? '?'} · Mode: ${d?.activeMode ?? 'GLOBAL_DEFAULT'} (p moved ${d?.predictedPBefore ?? '-'} -> ${d?.predictedPAfter ?? '-'})`,
      });
      onFeedbackSubmitted?.(feedbackKind, d);
    } catch (err: any) {
      setFeedbackNotice({
        type: 'error',
        message: err?.message || 'Unable to record feedback.',
      });
    } finally {
      setSubmittingKind(null);
    }
  };

  const chartData = (breakdown?.contributions || [])
    .slice(0, 10)
    .map((c) => ({
      name: c.label,
      contribution: Number(c.contribution.toFixed(4)),
      value: c.value,
      weight: c.weight,
    }))
    .reverse();

  const labelColors: Record<string, string> = {
    CRITICAL: 'bg-[#FCECF4] text-[#B52A70] border-[#D9468F]/40',
    HIGH: 'bg-[#16161D] text-[#FAF6F0] border-[#16161D]',
    NORMAL: 'bg-[#F2ECE2] text-[#16161D] border-[#D8CEC0]',
    MEDIUM: 'bg-[#F2ECE2] text-[#16161D] border-[#D8CEC0]',
    LOW: 'bg-[#FAF6F0] text-[#6F6C7A] border-[#E5DDD0]',
  };

  const currentLabel = breakdown?.label || item.priority || 'NORMAL';

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-[#16161D]/45 backdrop-blur-xs"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Priority Explanation Drawer"
    >
      <div
        className="w-full max-w-2xl bg-[#FFFDF9] h-full overflow-y-auto border-l border-[#E5DDD0] shadow-2xl p-6 sm:p-7 space-y-6"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-[#E5DDD0] pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
                <Sliders className="w-4 h-4" />
              </div>
              <h2 className="font-display text-xl font-semibold text-[#16161D]">
                Why This Priority Score
              </h2>
            </div>
            <p className="text-xs text-[#6F6C7A] font-mono tabular-nums">
              {item.notificationId} · {item.eventType} · {new Date(item.timestamp).toLocaleTimeString()}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl border border-[#E5DDD0] text-[#464451] hover:text-[#16161D] hover:bg-[#F2ECE2] transition-colors"
            aria-label="Close priority drawer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {!breakdown ? (
          <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-5 space-y-2 text-xs text-[#464451]">
            <div className="font-semibold text-[#16161D]">
              Legacy / Pre-Sigmoid Score Item ({item.priority || 'MEDIUM'} · {item.dispatchScore})
            </div>
            <p>
              This notification was dispatched before the Sigmoid Priority breakdown was attached. Dispatch a new notification to inspect full feature contributions w_i * x_i.
            </p>
          </div>
        ) : (
          <>
            {/* Score Summary Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-3.5 space-y-1">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Priority Score p</div>
                <div className="text-2xl font-semibold text-[#B52A70] font-mono tabular-nums">
                  {breakdown.p.toFixed(4)}
                </div>
                <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
                  Base p₀ = {breakdown.pBase.toFixed(4)}
                </div>
              </div>

              <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-3.5 space-y-1">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Assigned Label</div>
                <div>
                  <span
                    className={`inline-flex px-2.5 py-0.5 rounded-lg border text-xs font-semibold ${
                      labelColors[currentLabel] || labelColors.NORMAL
                    }`}
                  >
                    {currentLabel}
                  </span>
                </div>
                <div className="text-[11px] text-[#6F6C7A] font-mono">
                  Model: {breakdown.modelLabel}
                </div>
              </div>

              <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-3.5 space-y-1">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Linear Logit z</div>
                <div className="text-xl font-semibold text-[#16161D] font-mono tabular-nums">
                  {breakdown.z >= 0 ? `+${breakdown.z.toFixed(4)}` : breakdown.z.toFixed(4)}
                </div>
                <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
                  Bias b = {breakdown.bias.toFixed(4)}
                </div>
              </div>

              <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-3.5 space-y-1">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Model &amp; Time State</div>
                <div className="text-xs font-semibold text-[#16161D] flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-[#D9468F]" />
                  <span>{breakdown.activeMode === 'PERSONALIZED' ? 'Personalized' : 'Global Default'}</span>
                </div>
                <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
                  Age boost +{breakdown.ageBoostApplied.toFixed(3)}
                  {breakdown.escalationCapped ? ' (capped)' : ''}
                </div>
              </div>
            </div>

            {/* Score Bar with Threshold Markers */}
            <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-2.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[#16161D]">
                  Threshold Position &amp; Hysteresis (±{breakdown.thresholdUsed.hysteresis})
                </span>
                <span className="font-mono text-[#464451] tabular-nums">
                  LOW &lt; {breakdown.thresholdUsed.normal} · NORMAL &lt; {breakdown.thresholdUsed.high} · HIGH &lt; {breakdown.thresholdUsed.critical} · CRITICAL ≥ {breakdown.thresholdUsed.critical}
                </span>
              </div>
              <div className="relative h-3.5 w-full rounded-full bg-[#E5DDD0] overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-[#6F6C7A] via-[#16161D] to-[#D9468F] transition-all"
                  style={{ width: `${Math.min(100, Math.max(2, breakdown.p * 100))}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] font-mono text-[#6F6C7A] tabular-nums">
                <span>0.00</span>
                <span>{breakdown.thresholdUsed.normal.toFixed(2)} (Normal)</span>
                <span>{breakdown.thresholdUsed.high.toFixed(2)} (High)</span>
                <span>{breakdown.thresholdUsed.critical.toFixed(2)} (Critical)</span>
                <span>1.00</span>
              </div>
            </div>

            {/* Applied Hard Safety Rules */}
            {breakdown.appliedRules.length > 0 && (
              <div className="rounded-2xl border border-[#F2C4DC] bg-[#FCECF4]/60 p-4 space-y-2.5">
                <div className="text-xs font-semibold text-[#B52A70] flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Deterministic Hard Safety Rules Applied ({breakdown.appliedRules.length})</span>
                </div>
                <div className="space-y-2">
                  {breakdown.appliedRules.map((rule, idx) => (
                    <div
                      key={`${rule.rule}-${idx}`}
                      className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] px-3 py-2 text-xs space-y-0.5"
                    >
                      <div className="flex items-center justify-between gap-2 font-semibold text-[#16161D]">
                        <span>{rule.rule}</span>
                        <span className="font-mono text-[11px] text-[#B52A70]">
                          {rule.beforeLabel} → {rule.afterLabel} ({rule.action})
                        </span>
                      </div>
                      <p className="text-[11px] text-[#464451]">{rule.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Feature Contribution Bar Chart */}
            <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs font-semibold text-[#16161D] flex items-center gap-1.5">
                  <TrendingUp className="w-4 h-4 text-[#D9468F]" />
                  <span>Per-Feature Logit Contributions (w_i · x_i)</span>
                </div>
                <span className="text-[11px] text-[#6F6C7A]">Top 10 by magnitude</span>
              </div>
              <div className="h-64 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={chartData}
                    layout="vertical"
                    margin={{ top: 4, right: 20, left: 10, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                    <XAxis
                      type="number"
                      tick={{ fontSize: 11, fill: '#464451' }}
                      stroke="#D8CEC0"
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={155}
                      tick={{ fontSize: 11, fill: '#16161D' }}
                      stroke="#D8CEC0"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#FFFDF9',
                        borderColor: '#E5DDD0',
                        borderRadius: '12px',
                        fontSize: '12px',
                      }}
                    />
                    <ReferenceLine x={0} stroke="#16161D" strokeOpacity={0.35} />
                    <Bar dataKey="contribution" radius={[4, 4, 4, 4]}>
                      {chartData.map((entry, idx) => (
                        <Cell
                          key={`cell-${idx}`}
                          fill={entry.contribution >= 0 ? '#D9468F' : '#6F6C7A'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Numeric Feature Breakdown Table */}
            <div className="rounded-2xl border border-[#E5DDD0] overflow-hidden">
              <div className="bg-[#F2ECE2] px-4 py-2.5 text-xs font-semibold text-[#16161D] border-b border-[#E5DDD0]">
                Exact Calculation Terms (Sum + Bias b = {breakdown.z.toFixed(4)})
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#FAF6F0] text-[#6F6C7A] border-b border-[#E5DDD0]">
                    <tr>
                      <th className="py-2 px-3 font-medium">Feature</th>
                      <th className="py-2 px-3 font-medium text-right">Value x_i</th>
                      <th className="py-2 px-3 font-medium text-right">Weight w_i</th>
                      <th className="py-2 px-3 font-medium text-right">w_i · x_i</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E5DDD0] font-mono tabular-nums">
                    {breakdown.contributions.map((c) => (
                      <tr key={c.feature} className="hover:bg-[#FAF6F0]/70">
                        <td className="py-1.5 px-3 font-sans text-[#16161D]">{c.label}</td>
                        <td className="py-1.5 px-3 text-right text-[#464451]">{c.value.toFixed(3)}</td>
                        <td className="py-1.5 px-3 text-right text-[#464451]">
                          {c.weight >= 0 ? `+${c.weight.toFixed(3)}` : c.weight.toFixed(3)}
                        </td>
                        <td
                          className={`py-1.5 px-3 text-right font-semibold ${
                            c.contribution > 0
                              ? 'text-[#B52A70]'
                              : c.contribution < 0
                                ? 'text-[#6F6C7A]'
                                : 'text-[#464451]'
                          }`}
                        >
                          {c.contribution >= 0
                            ? `+${c.contribution.toFixed(4)}`
                            : c.contribution.toFixed(4)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Online Personalization Feedback Controls */}
            <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
              <div className="space-y-0.5">
                <div className="text-xs font-semibold text-[#16161D]">
                  Teach Your Priority Model (Numeric Features Only)
                </div>
                <p className="text-[11px] text-[#6F6C7A]">
                  Updates per-user logistic regression weights using only the numeric feature vector above. Message plaintext is never sent or stored.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={submittingKind !== null}
                  onClick={() => handleFeedback('MORE_IMPORTANT')}
                  className="px-3.5 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <ThumbsUp className="w-3.5 h-3.5 text-[#F472B6]" />
                  <span>More Important</span>
                </button>
                <button
                  type="button"
                  disabled={submittingKind !== null}
                  onClick={() => handleFeedback('LESS_IMPORTANT')}
                  className="px-3.5 py-2 rounded-xl bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <ThumbsDown className="w-3.5 h-3.5 text-[#6F6C7A]" />
                  <span>Less Important</span>
                </button>
                <button
                  type="button"
                  disabled={submittingKind !== null}
                  onClick={() => handleFeedback('MARKED_SPAM')}
                  className="px-3.5 py-2 rounded-xl bg-[#FCECF4] hover:bg-[#F7DCEB] text-[#B52A70] border border-[#F2C4DC] text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>Mark Promo / Spam</span>
                </button>
              </div>

              {feedbackNotice && (
                <div
                  className={`rounded-xl px-3 py-2 text-xs flex items-start gap-2 border ${
                    feedbackNotice.type === 'success'
                      ? 'bg-[#F0F7F4] border-[#16A34A]/30 text-[#15803D]'
                      : 'bg-red-50 border-red-200 text-red-800'
                  }`}
                >
                  {feedbackNotice.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  )}
                  <span>{feedbackNotice.message}</span>
                </div>
              )}
            </div>
          </>
        )}

        {/* Honest Transparency Panel */}
        <div className="rounded-2xl border border-[#E5DDD0] bg-[#F2ECE2]/70 p-4 space-y-2 text-xs text-[#464451]">
          <div className="font-semibold text-[#16161D] flex items-center gap-1.5">
            <Info className="w-4 h-4 text-[#D9468F]" />
            <span>How the priority engine works</span>
          </div>
          <p className="leading-relaxed">
            AegisNotify computes priority with a{' '}
            <strong className="text-[#16161D]">
              transparent logistic regression (sigmoid) model — NOT deep learning
            </strong>
            . Every feature is normalized to [0, 1], combined linearly with calibrated weights, and passed through the sigmoid curve:
          </p>
          <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] px-3 py-2 font-mono text-[11px] text-[#16161D]">
            z = b + Σ(w_i · x_i) &nbsp;&nbsp;|&nbsp;&nbsp; p = 1 / (1 + e^(-z)) ∈ [0, 1]
          </div>
          <ul className="list-disc pl-4 space-y-1 text-[11px]">
            <li>
              <strong>Time Dynamics:</strong> Unacknowledged alerts escalate via ageFactor = 1 − e^(-t/120s), strictly capped at min(p₀ + 0.25, 0.99), and stop immediately upon ACK.
            </li>
            <li>
              <strong>Per-User Learning &amp; Guardrails:</strong> Online SGD updates stay bounded within [-4, 4] with L2 regularization (λ = 0.01), require 20+ feedback events before leaving global defaults, and lock security weights above the minimum safety floor.
            </li>
            <li>
              <strong>Zero-Text Privacy:</strong> Raw message content is scored transiently in RAM and discarded immediately; only numeric feature vectors and weights are retained.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
