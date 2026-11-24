'use client';

import React, { useState, useEffect } from 'react';
import {
  Layers,
  Cpu,
  Download,
  CheckCircle2,
  AlertTriangle,
  Sliders,
  Save,
} from 'lucide-react';
import { safeReadJson } from '../lib/http/safeJson.js';
import {
  getEmbedderSnapshot,
  prewarmOnnxEmbedder,
  subscribeEmbedderSnapshot,
  type ClientEmbedderSnapshot,
} from '../lib/dedup/clientEmbedder.js';
import { saveDedupSettingsToFirestore } from '../lib/firebase/client.js';
import type { UserDedupSettings } from '../lib/dedup/types.js';

interface DedupSettingsSectionProps {
  userId: string;
  firebaseUid: string | null;
  onSettingsUpdated?: (settings: UserDedupSettings) => void;
}

const MANDATORY_CATEGORIES = ['security', 'otp', 'auth', 'provenance'];
const OPTIONAL_CATEGORIES = ['finance', 'work', 'social', 'promo'];

export default function DedupSettingsSection({
  userId,
  firebaseUid,
  onSettingsUpdated,
}: DedupSettingsSectionProps) {
  const [settings, setSettings] = useState<UserDedupSettings | null>(null);
  const [embedSnap, setEmbedSnap] = useState<ClientEmbedderSnapshot>(() =>
    getEmbedderSnapshot()
  );
  const [saving, setSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    return subscribeEmbedderSnapshot(setEmbedSnap);
  }, []);

  useEffect(() => {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    fetch('/api/v1/dedup/config', {
      headers: {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    })
      .then(async (res) => {
        const json = await safeReadJson(res);
        if (res.ok && json?.success && json?.data?.settings) {
          setSettings(json.data.settings);
        }
      })
      .catch(() => {
        // non-fatal
      });
  }, [userId]);

  const handleSave = async () => {
    if (!settings) return;
    setSaving(true);
    setStatusMsg(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch('/api/v1/dedup/config', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          dedupEnabled: settings.dedupEnabled,
          mergeThreshold: settings.mergeThreshold,
          reviewThreshold: settings.reviewThreshold,
          windowMinutes: settings.windowMinutes,
          neverMergeCategories: settings.neverMergeCategories,
        }),
      });
      const json = await safeReadJson(res);
      if (res.ok && json?.success && json?.data?.settings) {
        const updated = json.data.settings as UserDedupSettings;
        setSettings(updated);
        onSettingsUpdated?.(updated);
        if (firebaseUid) {
          void saveDedupSettingsToFirestore(firebaseUid, {
            dedupEnabled: updated.dedupEnabled,
            mergeThreshold: updated.mergeThreshold,
            reviewThreshold: updated.reviewThreshold,
            effectiveMergeThreshold: updated.effectiveMergeThreshold,
            windowMinutes: updated.windowMinutes,
            neverMergeCategories: updated.neverMergeCategories,
            feedbackCount: updated.feedbackCount,
          }).catch(() => {});
        }
        setStatusMsg('Deduplication settings saved.');
      } else {
        setStatusMsg(json?.message || 'Unable to save deduplication settings.');
      }
    } catch {
      setStatusMsg('Network error saving settings.');
    } finally {
      setSaving(false);
    }
  };

  if (!settings) return null;

  const toggleOptionalCategory = (cat: string) => {
    const has = settings.neverMergeCategories.includes(cat);
    const next = has
      ? settings.neverMergeCategories.filter((c) => c !== cat)
      : [...settings.neverMergeCategories, cat];
    setSettings({ ...settings, neverMergeCategories: next });
  };

  return (
    <div className="glass-panel rounded-3xl border border-[#E5DDD0] p-6 sm:p-7 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5DDD0] pb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-2xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-display text-base font-semibold text-[#16161D]">
              Semantic Deduplication (On-Device ONNX NLP)
            </h3>
            <p className="text-xs text-[#464451]">
              Groups repeated paraphrased alerts inside volatile device RAM without storing plaintext or vectors.
            </p>
          </div>
        </div>

        <label className="flex items-center gap-2 text-xs font-semibold text-[#16161D] cursor-pointer">
          <input
            type="checkbox"
            checked={settings.dedupEnabled}
            onChange={(e) => setSettings({ ...settings, dedupEnabled: e.target.checked })}
            className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
          />
          <span>Enable Deduplication</span>
        </label>
      </div>

      {/* Browser ONNX Model Status & One-Time Download Notice */}
      <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#16161D]">
              <Cpu className="w-4 h-4 text-[#D9468F]" />
              <span>Model: {embedSnap.modelId}</span>
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                  embedSnap.status === 'ready'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : embedSnap.status === 'lightweight_fallback'
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC]'
                }`}
              >
                {embedSnap.status === 'ready'
                  ? `ONNX Ready (${embedSnap.backend.toUpperCase()})`
                  : embedSnap.status === 'loading'
                  ? `Downloading ${embedSnap.progressPercent}%`
                  : embedSnap.status === 'lightweight_fallback'
                  ? 'Lightweight mode (TF-IDF)'
                  : 'Idle (Lazy Load)'}
              </span>
            </div>
            <p className="text-[11px] text-[#6F6C7A]">
              One-time ~{embedSnap.approxDownloadMb} MB quantized ONNX model download cached in Browser Cache Storage. Automatically switches to pure TS TF-IDF if offline or blocked.
            </p>
          </div>

          <button
            type="button"
            onClick={() => prewarmOnnxEmbedder(false)}
            disabled={embedSnap.status === 'loading' || embedSnap.status === 'ready'}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] disabled:opacity-50 flex items-center gap-1.5 shrink-0"
          >
            <Download className="w-3.5 h-3.5 text-[#F472B6]" />
            <span>
              {embedSnap.status === 'ready'
                ? 'Cached in Browser'
                : embedSnap.status === 'lightweight_fallback'
                ? 'Retry ONNX Load (~23 MB)'
                : 'Load ONNX Model (~23 MB)'}
            </span>
          </button>
        </div>

        {embedSnap.status === 'loading' && (
          <div className="space-y-1">
            <div className="w-full h-1.5 rounded-full bg-[#E5DDD0] overflow-hidden">
              <div
                className="h-full bg-[#D9468F] transition-all"
                style={{ width: `${Math.max(5, embedSnap.progressPercent)}%` }}
              />
            </div>
            <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
              {embedSnap.loadingFile ? `Fetching ${embedSnap.loadingFile}...` : 'Initializing Web Worker...'}
            </div>
          </div>
        )}

        {embedSnap.fallbackReason && (
          <div className="flex items-start gap-2 text-[11px] text-amber-900 bg-amber-50/80 border border-amber-200 rounded-xl p-2.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-700 shrink-0 mt-0.5" />
            <span>{embedSnap.fallbackReason}</span>
          </div>
        )}
      </div>

      {/* Sliders & Window Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#16161D] flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Merge Threshold</span>
            </span>
            <span className="font-mono-tech font-semibold text-[#B52A70]">
              {Math.round(settings.mergeThreshold * 100)}%
            </span>
          </div>
          <input
            type="range"
            min={0.8}
            max={0.98}
            step={0.01}
            value={settings.mergeThreshold}
            onChange={(e) => {
              const nextMerge = Number(e.target.value);
              const nextReview = Math.min(settings.reviewThreshold, Number((nextMerge - 0.04).toFixed(2)));
              setSettings({
                ...settings,
                mergeThreshold: nextMerge,
                reviewThreshold: nextReview,
                effectiveMergeThreshold: Math.max(
                  0.8,
                  Math.min(0.98, Number((nextMerge + settings.personalThresholdOffset).toFixed(3)))
                ),
              });
            }}
            className="w-full accent-[#D9468F]"
          />
          <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
            Personal adapted: {Math.round(settings.effectiveMergeThreshold * 100)}% ({settings.feedbackCount} feedbacks)
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#16161D]">Suggest Threshold</span>
            <span className="font-mono-tech font-semibold text-[#16161D]">
              {Math.round(settings.reviewThreshold * 100)}%
            </span>
          </div>
          <input
            type="range"
            min={0.5}
            max={Math.max(0.52, settings.mergeThreshold - 0.02)}
            step={0.01}
            value={settings.reviewThreshold}
            onChange={(e) =>
              setSettings({ ...settings, reviewThreshold: Number(e.target.value) })
            }
            className="w-full accent-[#16161D]"
          />
          <div className="text-[11px] text-[#6F6C7A]">
            Shows &ldquo;Possibly related&rdquo; with manual Merge option.
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
          <label className="text-xs font-semibold text-[#16161D] block">
            RAM Sliding Window
          </label>
          <select
            value={settings.windowMinutes}
            onChange={(e) =>
              setSettings({ ...settings, windowMinutes: Number(e.target.value) })
            }
            className="w-full px-3 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs font-mono-tech text-[#16161D]"
          >
            <option value={5}>5 minutes (300s default)</option>
            <option value={15}>15 minutes</option>
            <option value={30}>30 minutes</option>
            <option value={60}>60 minutes</option>
            <option value={120}>120 minutes</option>
          </select>
          <div className="text-[11px] text-[#6F6C7A]">
            Max 500 items retained in volatile RAM.
          </div>
        </div>
      </div>

      {/* Never-Merge Category Exclusions */}
      <div className="space-y-2">
        <div className="text-xs font-semibold text-[#16161D]">
          Never-Merge Categories (Safety Locked + Optional)
        </div>
        <div className="flex flex-wrap gap-2">
          {MANDATORY_CATEGORIES.map((cat) => (
            <span
              key={cat}
              className="px-2.5 py-1 rounded-xl bg-[#16161D] text-[#FAF6F0] text-[11px] font-mono-tech flex items-center gap-1"
              title="Mandatory safety exclusion"
            >
              <CheckCircle2 className="w-3 h-3 text-[#F472B6]" />
              <span>{cat} (locked)</span>
            </span>
          ))}
          {OPTIONAL_CATEGORIES.map((cat) => {
            const active = settings.neverMergeCategories.includes(cat);
            return (
              <button
                key={cat}
                type="button"
                onClick={() => toggleOptionalCategory(cat)}
                className={`px-2.5 py-1 rounded-xl text-[11px] font-mono-tech border transition-all ${
                  active
                    ? 'bg-[#FCECF4] text-[#B52A70] border-[#D9468F]/45 font-semibold'
                    : 'bg-[#FAF6F0] text-[#464451] border-[#D8CEC0]'
                }`}
              >
                {active ? `✓ ${cat}` : cat}
              </button>
            );
          })}
        </div>
      </div>

      {/* Save Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#E5DDD0]">
        <div className="text-xs text-[#464451]">
          {statusMsg || 'Thresholds automatically adapt within [80%, 98%] when you mark items "Not a duplicate".'}
        </div>
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] flex items-center gap-1.5 disabled:opacity-60"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{saving ? 'Saving...' : 'Save Deduplication Preferences'}</span>
        </button>
      </div>
    </div>
  );
}
