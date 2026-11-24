'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Sliders,
  RefreshCw,
  RotateCcw,
  Download,
  AlertTriangle,
  CheckCircle2,
  Plus,
  X,
  Moon,
  ShieldAlert,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts';
import { safeReadJson } from '../lib/http/safeJson.js';
import {
  DEFAULT_PRIORITY_ARTIFACT,
  FEATURE_DISPLAY_LABELS,
} from '../lib/priority/math.js';
import { createDefaultUserPriorityModelState } from '../lib/priority/learning.js';
import type { UserPriorityModelState } from '../lib/priority/types.js';
import {
  loadPriorityModelFromFirestore,
  savePriorityModelToFirestore,
} from '../lib/firebase/client.js';

interface MyPrioritiesSettingsSectionProps {
  userId: string;
  firebaseUid?: string | null;
  onModelUpdated?: (model: UserPriorityModelState) => void;
}

const SOURCE_KEYS = [
  'security',
  'direct',
  'app-github',
  'app-slack',
  'app-telegram',
  'app-discord',
  'webhook',
  'marketing',
];

export default function MyPrioritiesSettingsSection({
  userId,
  firebaseUid,
  onModelUpdated,
}: MyPrioritiesSettingsSectionProps) {
  const [model, setModel] = useState<UserPriorityModelState>(() =>
    createDefaultUserPriorityModelState(userId)
  );
  const [activeMode, setActiveMode] = useState<'PERSONALIZED' | 'GLOBAL_DEFAULT'>('GLOBAL_DEFAULT');
  const [coldStartThreshold, setColdStartThreshold] = useState<number>(
    DEFAULT_PRIORITY_ARTIFACT.hyperparams.coldStartFeedbackThreshold
  );
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [confirmingReset, setConfirmingReset] = useState(false);
  const [newKeyword, setNewKeyword] = useState('');
  const [notice, setNotice] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const loadModel = useCallback(async () => {
    setLoading(true);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (token) {
        const res = await fetch('/api/v1/priority/model', {
          headers: { Authorization: `Bearer ${token}` },
        });
        const json = await safeReadJson(res);
        if (res.ok && json?.success && json?.data?.model) {
          setModel(json.data.model);
          setActiveMode(json.data.activeMode || 'GLOBAL_DEFAULT');
          setColdStartThreshold(json.data.coldStartThreshold ?? 20);
          onModelUpdated?.(json.data.model);
          setLoading(false);
          return;
        }
      }

      if (firebaseUid) {
        const fbModel = await loadPriorityModelFromFirestore(firebaseUid);
        if (fbModel) {
          const fallback = createDefaultUserPriorityModelState(userId);
          const merged: UserPriorityModelState = {
            ...fallback,
            version: fbModel.version,
            personalizationEnabled: fbModel.personalizationEnabled,
            feedbackCount: fbModel.feedbackCount,
            bias: fbModel.bias,
            weights: { ...fallback.weights, ...fbModel.weights } as UserPriorityModelState['weights'],
            thresholds: fbModel.thresholds,
            urgentKeywords: fbModel.urgentKeywords,
            quietHours: fbModel.quietHours,
            sourceReliability: { ...fallback.sourceReliability, ...fbModel.sourceReliability },
            driftWarning: fbModel.driftWarning,
            driftL2Distance: fbModel.driftL2Distance,
          };
          setModel(merged);
          onModelUpdated?.(merged);
        }
      }
    } catch {
      // Non-fatal fallback to default model
    } finally {
      setLoading(false);
    }
  }, [firebaseUid, onModelUpdated, userId]);

  useEffect(() => {
    void loadModel();
  }, [loadModel]);

  const handleSaveSettings = async (overrideModel?: UserPriorityModelState) => {
    const target = overrideModel || model;
    setSaving(true);
    setNotice(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      let savedModel = target;

      if (token) {
        const res = await fetch('/api/v1/priority/model', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            personalizationEnabled: target.personalizationEnabled,
            urgentKeywords: target.urgentKeywords,
            quietHours: target.quietHours,
            sourceReliability: target.sourceReliability,
            thresholds: target.thresholds,
          }),
        });
        const json = await safeReadJson(res);
        if (!res.ok || !json?.success) {
          throw new Error(json?.message || `Save failed (HTTP ${res.status}).`);
        }
        savedModel = json.data.model;
        setModel(savedModel);
        setActiveMode(json.data.activeMode);
      }

      if (firebaseUid) {
        await savePriorityModelToFirestore(firebaseUid, {
          version: savedModel.version,
          personalizationEnabled: savedModel.personalizationEnabled,
          feedbackCount: savedModel.feedbackCount,
          bias: savedModel.bias,
          weights: savedModel.weights,
          thresholds: savedModel.thresholds,
          urgentKeywords: savedModel.urgentKeywords,
          quietHours: savedModel.quietHours,
          sourceReliability: savedModel.sourceReliability,
          driftWarning: savedModel.driftWarning,
          driftL2Distance: savedModel.driftL2Distance,
        });
      }

      onModelUpdated?.(savedModel);
      setNotice({
        type: 'success',
        message: firebaseUid
          ? 'Priority personalization & quiet hours saved and synced to Firestore.'
          : 'Priority personalization & quiet hours saved.',
      });
    } catch (err: any) {
      setNotice({
        type: 'error',
        message: err?.message || 'Failed to save priority preferences.',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleResetWeights = async () => {
    setSaving(true);
    setNotice(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (!token) {
        throw new Error('Sign in required to reset server weights.');
      }

      const res = await fetch('/api/v1/priority/reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ reason: 'User initiated reset in My Priorities settings' }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Reset failed (HTTP ${res.status}).`);
      }

      const resetModel: UserPriorityModelState = json.data.model;
      setModel(resetModel);
      setActiveMode('GLOBAL_DEFAULT');
      setConfirmingReset(false);

      if (firebaseUid) {
        await savePriorityModelToFirestore(firebaseUid, {
          version: resetModel.version,
          personalizationEnabled: resetModel.personalizationEnabled,
          feedbackCount: resetModel.feedbackCount,
          bias: resetModel.bias,
          weights: resetModel.weights,
          thresholds: resetModel.thresholds,
          urgentKeywords: resetModel.urgentKeywords,
          quietHours: resetModel.quietHours,
          sourceReliability: resetModel.sourceReliability,
          driftWarning: resetModel.driftWarning,
          driftL2Distance: resetModel.driftL2Distance,
        });
      }

      onModelUpdated?.(resetModel);
      setNotice({
        type: 'success',
        message: 'Weights cleanly reset to calibrated global defaults.',
      });
    } catch (err: any) {
      setNotice({ type: 'error', message: err?.message || 'Weight reset failed.' });
    } finally {
      setSaving(false);
    }
  };

  const handleExportModelJson = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      activeMode,
      coldStartThreshold,
      note: 'Contains numeric logistic regression weights and metadata only. Zero message text stored.',
      model,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-priority-model-${userId.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleAddKeyword = () => {
    const clean = newKeyword.trim().toLowerCase().slice(0, 40);
    if (!clean) return;
    if (model.urgentKeywords.includes(clean)) {
      setNewKeyword('');
      return;
    }
    setModel((prev) => ({
      ...prev,
      urgentKeywords: [...prev.urgentKeywords, clean].slice(0, 30),
    }));
    setNewKeyword('');
  };

  const progressPct = Math.min(100, Math.round((model.feedbackCount / coldStartThreshold) * 100));
  const historyData = (model.weightHistory || []).map((h) => ({
    step: `#${h.step}`,
    driftL2: h.deltaL2FromDefault,
    securityW: h.weights.category_security,
    textW: h.weights.textScore,
  }));

  return (
    <div className="glass-panel rounded-3xl border border-[#E5DDD0] p-6 sm:p-7 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E5DDD0] pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
              <Sliders className="w-4 h-4" />
            </div>
            <h3 className="font-display text-lg font-semibold text-[#16161D]">
              My Priorities &amp; Sigmoid Personalization
            </h3>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Transparent per-user logistic regression preferences. Raw message text is never saved.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void loadModel()}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-xs font-semibold flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>
          <button
            type="button"
            onClick={handleExportModelJson}
            className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-xs font-semibold flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Drift Warning Banner */}
      {model.driftWarning && (
        <div className="rounded-2xl border border-amber-300 bg-amber-50 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start gap-2.5 text-xs text-amber-950">
            <ShieldAlert className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <div className="font-semibold">
                Model Drift Warning (L2 distance = {model.driftL2Distance.toFixed(3)})
              </div>
              <p className="text-[11px] text-amber-900">
                Your personalized weights diverged significantly from calibrated defaults. Resetting restores clean baseline scoring while keeping your keywords and quiet hours.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void handleResetWeights()}
            disabled={saving}
            className="px-3.5 py-2 rounded-xl bg-amber-700 hover:bg-amber-800 text-white text-xs font-semibold whitespace-nowrap"
          >
            Reset Weights Now
          </button>
        </div>
      )}

      {/* Cold-Start & Mode Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-xs font-semibold text-[#16161D]">
                Enable Online SGD Personalization
              </div>
              <div className="text-[11px] text-[#6F6C7A]">
                Active mode:{' '}
                <strong className="text-[#B52A70] font-mono">{activeMode}</strong>
              </div>
            </div>
            <input
              type="checkbox"
              checked={model.personalizationEnabled}
              onChange={(e) =>
                setModel((prev) => ({ ...prev, personalizationEnabled: e.target.checked }))
              }
              className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between text-[11px] text-[#464451] font-mono tabular-nums">
              <span>Cold-start progress</span>
              <span>
                {model.feedbackCount} / {coldStartThreshold} feedback samples
              </span>
            </div>
            <div className="h-2 rounded-full bg-[#E5DDD0] overflow-hidden">
              <div
                className="h-full bg-[#D9468F] transition-all"
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <p className="text-[11px] text-[#6F6C7A]">
              {model.feedbackCount >= coldStartThreshold && model.personalizationEnabled
                ? 'Personalized weights are active for your feed.'
                : `Using calibrated global default weights until ${Math.max(0, coldStartThreshold - model.feedbackCount)} more feedback signals arrive.`}
            </p>
          </div>
        </div>

        {/* Quiet Hours UTC */}
        <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-xs font-semibold text-[#16161D] flex items-center gap-1.5">
              <Moon className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Focus Quiet Hours (UTC) &amp; DND</span>
            </div>
            <label className="flex items-center gap-1.5 text-[11px] text-[#464451]">
              <input
                type="checkbox"
                checked={model.quietHours.enabled}
                onChange={(e) =>
                  setModel((prev) => ({
                    ...prev,
                    quietHours: { ...prev.quietHours, enabled: e.target.checked },
                  }))
                }
                className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F]"
              />
              <span>Schedule Active</span>
            </label>
          </div>

          <div className="grid grid-cols-3 gap-2.5 text-xs">
            <label className="space-y-1">
              <span className="text-[11px] text-[#6F6C7A]">Start Hour UTC</span>
              <input
                type="number"
                min={0}
                max={23}
                value={model.quietHours.startHourUtc}
                onChange={(e) =>
                  setModel((prev) => ({
                    ...prev,
                    quietHours: {
                      ...prev.quietHours,
                      startHourUtc: Math.max(0, Math.min(23, Number(e.target.value) || 0)),
                    },
                  }))
                }
                className="w-full px-2.5 py-1.5 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] font-mono tabular-nums"
              />
            </label>
            <label className="space-y-1">
              <span className="text-[11px] text-[#6F6C7A]">End Hour UTC</span>
              <input
                type="number"
                min={0}
                max={23}
                value={model.quietHours.endHourUtc}
                onChange={(e) =>
                  setModel((prev) => ({
                    ...prev,
                    quietHours: {
                      ...prev.quietHours,
                      endHourUtc: Math.max(0, Math.min(23, Number(e.target.value) || 0)),
                    },
                  }))
                }
                className="w-full px-2.5 py-1.5 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] font-mono tabular-nums"
              />
            </label>
            <label className="space-y-1 flex flex-col justify-end">
              <span className="text-[11px] text-[#6F6C7A]">Immediate DND</span>
              <button
                type="button"
                onClick={() =>
                  setModel((prev) => ({
                    ...prev,
                    quietHours: { ...prev.quietHours, dndActive: !prev.quietHours.dndActive },
                  }))
                }
                className={`px-2.5 py-1.5 rounded-xl border text-xs font-semibold ${
                  model.quietHours.dndActive
                    ? 'bg-[#16161D] text-[#FAF6F0] border-[#16161D]'
                    : 'bg-[#FFFDF9] text-[#464451] border-[#D8CEC0]'
                }`}
              >
                {model.quietHours.dndActive ? 'DND ON' : 'DND OFF'}
              </button>
            </label>
          </div>
        </div>
      </div>

      {/* Urgent Keywords */}
      <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
        <div className="text-xs font-semibold text-[#16161D]">
          Custom Urgent Keywords (Evaluated In-Memory Only)
        </div>
        <div className="flex flex-wrap gap-2">
          {model.urgentKeywords.map((kw) => (
            <span
              key={kw}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#FFFDF9] border border-[#D8CEC0] text-xs font-mono text-[#16161D]"
            >
              <span>{kw}</span>
              <button
                type="button"
                onClick={() =>
                  setModel((prev) => ({
                    ...prev,
                    urgentKeywords: prev.urgentKeywords.filter((k) => k !== kw),
                  }))
                }
                className="text-[#6F6C7A] hover:text-[#B52A70]"
                aria-label={`Remove keyword ${kw}`}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
        <div className="flex gap-2 max-w-md">
          <input
            type="text"
            value={newKeyword}
            onChange={(e) => setNewKeyword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddKeyword();
              }
            }}
            placeholder="Add urgent term (e.g. prod-down)"
            className="flex-1 px-3 py-1.5 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs focus:outline-none focus:border-[#D9468F]"
          />
          <button
            type="button"
            onClick={handleAddKeyword}
            className="px-3.5 py-1.5 rounded-xl bg-[#16161D] text-[#FAF6F0] text-xs font-semibold flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add</span>
          </button>
        </div>
      </div>

      {/* Source Reliability Sliders */}
      <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-semibold text-[#16161D]">
            Per-Source Reliability Weights (0.00 – 1.00)
          </div>
          <span className="text-[11px] text-[#6F6C7A]">Feeds sourceReliability feature x₄</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {SOURCE_KEYS.map((key) => {
            const val = model.sourceReliability[key] ?? 0.75;
            return (
              <div key={key} className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-mono text-[#16161D]">{key}</span>
                  <span className="font-mono font-semibold text-[#B52A70] tabular-nums">
                    {val.toFixed(2)}
                  </span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={1}
                  step={0.05}
                  value={val}
                  onChange={(e) =>
                    setModel((prev) => ({
                      ...prev,
                      sourceReliability: {
                        ...prev.sourceReliability,
                        [key]: Number(e.target.value),
                      },
                    }))
                  }
                  className="w-full accent-[#D9468F]"
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Weight History Trend Chart */}
      {historyData.length > 0 && (
        <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 space-y-2">
          <div className="text-xs font-semibold text-[#16161D]">
            Online Weight Drift &amp; Security Floor History
          </div>
          <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="step" tick={{ fontSize: 11, fill: '#464451' }} />
                <YAxis tick={{ fontSize: 11, fill: '#464451' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFDF9',
                    borderColor: '#E5DDD0',
                    borderRadius: '12px',
                    fontSize: '12px',
                  }}
                />
                <ReferenceLine
                  y={DEFAULT_PRIORITY_ARTIFACT.hyperparams.driftL2WarningThreshold}
                  stroke="#D97706"
                  strokeDasharray="4 4"
                />
                <Line
                  type="monotone"
                  dataKey="driftL2"
                  name="L2 Drift"
                  stroke="#D9468F"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="securityW"
                  name="Security Weight"
                  stroke="#16161D"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Key Active Weights Preview */}
      <div className="rounded-2xl border border-[#E5DDD0] overflow-hidden">
        <div className="bg-[#F2ECE2] px-4 py-2 text-xs font-semibold text-[#16161D] border-b border-[#E5DDD0] flex justify-between">
          <span>Active Logistic Weights (Bias b = {model.bias.toFixed(4)})</span>
          <span className="font-mono text-[#6F6C7A] tabular-nums">
            L2 Drift: {model.driftL2Distance.toFixed(4)}
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-px bg-[#E5DDD0] text-xs">
          {(Object.keys(model.weights) as Array<keyof typeof model.weights>).map((k) => (
            <div key={k} className="bg-[#FFFDF9] px-3 py-2 flex items-center justify-between gap-2">
              <span className="text-[11px] text-[#464451] truncate" title={FEATURE_DISPLAY_LABELS[k]}>
                {k}
              </span>
              <span className="font-mono font-semibold text-[#16161D] tabular-nums">
                {model.weights[k].toFixed(3)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Footer Save & Safe Reset Actions */}
      {notice && (
        <div
          className={`rounded-xl px-3.5 py-2.5 text-xs flex items-center gap-2 border ${
            notice.type === 'success'
              ? 'bg-[#F0F7F4] border-[#16A34A]/30 text-[#15803D]'
              : 'bg-red-50 border-red-200 text-red-800'
          }`}
        >
          {notice.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          )}
          <span>{notice.message}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#E5DDD0]">
        <div>
          {!confirmingReset ? (
            <button
              type="button"
              onClick={() => setConfirmingReset(true)}
              className="px-3.5 py-2 rounded-xl border border-[#D8CEC0] bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#464451] text-xs font-semibold flex items-center gap-1.5"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset Weights to Default</span>
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#B52A70] font-semibold">Confirm reset?</span>
              <button
                type="button"
                onClick={() => void handleResetWeights()}
                disabled={saving}
                className="px-3 py-1.5 rounded-xl bg-[#B52A70] text-white text-xs font-semibold"
              >
                Yes, Reset
              </button>
              <button
                type="button"
                onClick={() => setConfirmingReset(false)}
                className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs"
              >
                Cancel
              </button>
            </div>
          )}
        </div>

        <button
          type="button"
          disabled={saving}
          onClick={() => void handleSaveSettings()}
          className="px-5 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold shadow-xs disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save My Priority Settings'}
        </button>
      </div>
    </div>
  );
}
