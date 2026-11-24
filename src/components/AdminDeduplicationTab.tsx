'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Layers,
  RefreshCw,
  Cpu,
  Gauge,
  Download,
  Play,
  CheckCircle2,
  XCircle,
  Info,
  FileCode2,
  FlaskConical,
  ShieldCheck,
} from 'lucide-react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from 'recharts';
import { safeReadJson } from '../lib/http/safeJson.js';
import {
  benchmarkClientEmbedder,
  embedTextInBrowser,
  getEmbedderSnapshot,
  prewarmOnnxEmbedder,
  subscribeEmbedderSnapshot,
  type ClientEmbedderSnapshot,
} from '../lib/dedup/clientEmbedder.js';
import { evaluateAllMergeGuards } from '../lib/dedup/guards.js';
import { preprocessNotificationText } from '../lib/dedup/preprocess.js';
import { cosineSimilarity, l2Normalize, sha256HexSync } from '../lib/dedup/similarity.js';
import { computeTfIdfPairSimilarity } from '../lib/dedup/tfidf.js';
import { DEFAULT_DEDUP_CONFIG } from '../lib/dedup/config.js';
import type {
  DedupSimulationScenarioResult,
  DedupStatsSnapshot,
  EmbedderBenchmarkResult,
} from '../lib/dedup/types.js';

interface AdminDeduplicationTabProps {
  token: string | null;
}

const SCENARIO_LIST: Array<{ code: string; label: string }> = [
  { code: 'a', label: 'a. Exact Duplicate' },
  { code: 'b', label: 'b. Semantic Paraphrase' },
  { code: 'c', label: 'c. Unrelated Separate' },
  { code: 'd', label: 'd. Entity Conflict (Rs 500 vs 50k)' },
  { code: 'e', label: 'e. Different OTPs' },
  { code: 'f', label: 'f. Negation (Down vs Recovered)' },
  { code: 'g', label: 'g. CRITICAL Never Suppressed' },
  { code: 'h', label: 'h. Provenance Mismatch' },
  { code: 'i', label: 'i. Higher-Priority Escalation' },
  { code: 'j', label: 'j. Fallback Delivery Dedup' },
  { code: 'k', label: 'k. Ungroup & Threshold Adapt' },
  { code: 'l', label: 'l. ONNX Fallback (Lightweight)' },
  { code: 'm', label: 'm. Zero-Text / Zero-Vector Proof' },
];

export default function AdminDeduplicationTab({ token }: AdminDeduplicationTabProps) {
  const [stats, setStats] = useState<DedupStatsSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [embedSnap, setEmbedSnap] = useState<ClientEmbedderSnapshot>(() =>
    getEmbedderSnapshot()
  );

  // Device Benchmark State
  const [benchBusy, setBenchBusy] = useState(false);
  const [benchmark, setBenchmark] = useState<EmbedderBenchmarkResult | null>(null);

  // Interactive Live Pair What-If Tester
  const [pairTextA, setPairTextA] = useState('Server down on production API');
  const [pairTextB, setPairTextB] = useState('Production backend API not responding');
  const [testThreshold, setTestThreshold] = useState(0.88);
  const [pairTesting, setPairTesting] = useState(false);
  const [pairEval, setPairEval] = useState<{
    similarity: number;
    tfidfSimilarity: number;
    exactMatch: boolean;
    modeUsed: string;
    guardsAllowed: boolean;
    blockedGuard: string | null;
    guardReasons: string[];
    wouldMerge: boolean;
    wouldSuggest: boolean;
  } | null>(null);

  // Isolated Simulator (Demo Mode OFF by default!)
  const [demoModeEnabled, setDemoModeEnabled] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [simNotice, setSimNotice] = useState<string | null>(null);
  const [simResults, setSimResults] = useState<DedupSimulationScenarioResult[]>([]);

  useEffect(() => {
    return subscribeEmbedderSnapshot(setEmbedSnap);
  }, []);

  const resolveToken = () =>
    token ||
    (typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/dedup/stats', {
        headers: {
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Failed to load dedup stats (HTTP ${res.status}).`);
      }
      setStats(json.data.stats);
    } catch (err: any) {
      setError(err?.message || 'Unable to load deduplication telemetry.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void fetchStats();
  }, [fetchStats]);

  const handleRunBenchmark = async () => {
    setBenchBusy(true);
    try {
      const res = await benchmarkClientEmbedder();
      setBenchmark(res);
    } finally {
      setBenchBusy(false);
    }
  };

  const handleEvaluatePair = async () => {
    setPairTesting(true);
    try {
      const normA = preprocessNotificationText(pairTextA).normalizedText;
      const normB = preprocessNotificationText(pairTextB).normalizedText;
      const exactMatch = sha256HexSync(normA) === sha256HexSync(normB);
      const tfidfSim = computeTfIdfPairSimilarity(pairTextA, pairTextB);

      const embA = await embedTextInBrowser(pairTextA);
      const embB = await embedTextInBrowser(pairTextB);

      let similarity = tfidfSim;
      let modeUsed = 'Lightweight TF-IDF';
      if (embA.embedding && embB.embedding) {
        similarity = cosineSimilarity(
          l2Normalize(embA.embedding),
          l2Normalize(embB.embedding)
        );
        modeUsed = `ONNX ${embedSnap.modelId} (${embedSnap.backend})`;
      } else if (exactMatch) {
        similarity = 1.0;
      }

      const guardRes = evaluateAllMergeGuards({
        incoming: {
          notificationId: 'whatif_b',
          userId: 'whatif',
          sourceId: 'simulator',
          senderId: 'simulator',
          category: 'work',
          priority: 'HIGH',
          trust: 'VERIFIED',
        },
        incomingText: pairTextB,
        candidateThread: {
          threadId: 'thr_whatif_a',
          userId: 'whatif',
          createdAt: new Date().toISOString(),
          lastMemberAt: new Date().toISOString(),
          memberCount: 1,
          memberIds: ['whatif_a'],
          sourceId: 'simulator',
          senderId: 'simulator',
          category: 'work',
          topPriority: 'HIGH',
          lowestTrust: 'VERIFIED',
          status: 'ACTIVE',
          stageMatched: 'SEMANTIC_ONNX',
          lastSimilarity: 1,
        },
        candidateLatestText: pairTextA,
        neverMergeCategories: DEFAULT_DEDUP_CONFIG.neverMergeCategories,
      });

      const wouldMerge = guardRes.allowedToMerge && similarity >= testThreshold;
      const wouldSuggest =
        guardRes.allowedToMerge && !wouldMerge && similarity >= Math.max(0.5, testThreshold - 0.1);

      setPairEval({
        similarity: Number(similarity.toFixed(4)),
        tfidfSimilarity: Number(tfidfSim.toFixed(4)),
        exactMatch,
        modeUsed,
        guardsAllowed: guardRes.allowedToMerge,
        blockedGuard: guardRes.blockedByGuard,
        guardReasons: guardRes.guards.filter((g) => !g.passed).map((g) => g.reason),
        wouldMerge,
        wouldSuggest,
      });
    } finally {
      setPairTesting(false);
    }
  };

  const handleRunSimulator = async (scenario: string) => {
    if (!demoModeEnabled) {
      setSimNotice('Enable Demo Mode first to run deduplication test scenarios.');
      return;
    }
    setSimBusy(true);
    setSimNotice(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/dedup/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({ demoMode: true, scenario }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Simulation failed (HTTP ${res.status}).`);
      }
      setSimResults(json.data.results || []);
      setSimNotice(json.message);
    } catch (err: any) {
      setSimNotice(err?.message || 'Simulator execution failed.');
    } finally {
      setSimBusy(false);
    }
  };

  const handleExportReport = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      liveStats: stats,
      benchmark,
      colabEvaluation: DEFAULT_DEDUP_CONFIG.evaluation,
      modelCard: DEFAULT_DEDUP_CONFIG.modelCard,
      simulatorResults: simResults,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-dedup-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const evalData = DEFAULT_DEDUP_CONFIG.evaluation;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
              <Layers className="w-4 h-4" />
            </div>
            <h2 className="font-display text-2xl font-semibold text-[#16161D] tracking-tight">
              Semantic Deduplication (ONNX NLP)
            </h2>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Browser-side Web Worker sentence embeddings ({DEFAULT_DEDUP_CONFIG.modelId}) + safety guards · Metadata-only telemetry
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void fetchStats()}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={handleExportReport}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-[#D9468F]" />
            <span>Export Report</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl bg-red-50 border border-red-200 px-4 py-3 text-xs text-red-700">
          {error}
        </div>
      )}

      {/* Honest Live KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1">
          <div className="text-[11px] font-semibold text-[#6F6C7A]">Items Evaluated</div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats?.itemsReceived ?? 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A]">Live counted events</div>
        </div>
        <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1">
          <div className="text-[11px] font-semibold text-[#6F6C7A]">Items Grouped</div>
          <div className="font-display text-2xl font-semibold text-[#B52A70] tabular-nums">
            {stats?.itemsGrouped ?? 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A]">Merged into existing threads</div>
        </div>
        <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1">
          <div className="text-[11px] font-semibold text-[#6F6C7A]">Real Suppression Rate</div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats && stats.suppressionRatePercent !== null
              ? `${stats.suppressionRatePercent}%`
              : 'No data yet'}
          </div>
          <div className="text-[11px] text-[#6F6C7A]">Never fake 100%</div>
        </div>
        <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1">
          <div className="text-[11px] font-semibold text-[#6F6C7A]">Active / Resolved Threads</div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats ? `${stats.activeThreadsCount} / ${stats.resolvedThreadsCount}` : '0 / 0'}
          </div>
          <div className="text-[11px] text-[#6F6C7A]">Ungroups: {stats?.ungroupCount ?? 0}</div>
        </div>
        <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1">
          <div className="text-[11px] font-semibold text-[#6F6C7A]">Guards Blocked Merges</div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats
              ? Object.values(stats.guardsBlockedByType).reduce((a, b) => a + b, 0)
              : 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A]">Safety overrides active</div>
        </div>
      </div>

      {/* Browser ONNX Worker Status & Benchmark Panel */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#16161D]">
              <Cpu className="w-4 h-4 text-[#D9468F]" />
              <span>Browser ONNX Worker &amp; Device Benchmark</span>
              <span
                className={`px-2 py-0.5 rounded-full text-[11px] border ${
                  embedSnap.status === 'ready'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : embedSnap.status === 'lightweight_fallback'
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : 'bg-[#FAF6F0] text-[#464451] border-[#D8CEC0]'
                }`}
              >
                {embedSnap.status === 'ready'
                  ? `ONNX Ready (${embedSnap.backend.toUpperCase()})`
                  : embedSnap.status === 'loading'
                  ? `Loading ${embedSnap.progressPercent}%`
                  : embedSnap.status === 'lightweight_fallback'
                  ? 'Lightweight mode (TF-IDF)'
                  : 'Idle'}
              </span>
            </div>
            <p className="text-xs text-[#6F6C7A]">
              Measures real on-device embedding throughput, model load latency, and estimated JS heap RAM across 12 representative alerts.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => prewarmOnnxEmbedder(false)}
              disabled={embedSnap.status === 'loading' || embedSnap.status === 'ready'}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] disabled:opacity-50 flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Load ONNX Model (~{embedSnap.approxDownloadMb} MB)</span>
            </button>
            <button
              type="button"
              onClick={() => void handleRunBenchmark()}
              disabled={benchBusy}
              className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] flex items-center gap-1.5 disabled:opacity-60"
            >
              <Gauge className="w-3.5 h-3.5" />
              <span>{benchBusy ? 'Benchmarking...' : 'Benchmark On This Device'}</span>
            </button>
          </div>
        </div>

        {benchmark && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2 border-t border-[#E5DDD0] text-xs">
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[11px] text-[#6F6C7A]">Active Mode</div>
              <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5">
                {benchmark.mode} ({benchmark.backend})
              </div>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[11px] text-[#6F6C7A]">Avg Embed Time</div>
              <div className="font-mono-tech font-semibold text-[#B52A70] mt-0.5">
                {benchmark.avgEmbedMs} ms
              </div>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[11px] text-[#6F6C7A]">Throughput</div>
              <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5">
                {benchmark.throughputPerSec} msg/s
              </div>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[11px] text-[#6F6C7A]">Model Load Time</div>
              <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5">
                {benchmark.modelLoadMs} ms
              </div>
            </div>
            <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[11px] text-[#6F6C7A]">Est. Memory / Cached</div>
              <div className="font-mono-tech font-semibold text-[#16161D] mt-0.5">
                ~{benchmark.estimatedRamMb} MB · {benchmark.cachedInBrowser ? 'Cached' : 'RAM'}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Charts Row: Grouped vs Total + Similarity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="text-xs font-semibold text-[#16161D]">
            Live Volume: Total Evaluated vs Grouped Over Time
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats?.timeSeries || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#464451' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#464451' }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Total Evaluated"
                  stroke="#16161D"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="grouped"
                  name="Grouped Duplicates"
                  stroke="#D9468F"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="text-xs font-semibold text-[#16161D]">
            Measured Cosine Similarity Histogram
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.similarityHistogram || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#464451' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#464451' }} />
                <Tooltip />
                <Bar dataKey="count" name="Events" radius={[6, 6, 0, 0]}>
                  {(stats?.similarityHistogram || []).map((entry, idx) => (
                    <Cell
                      key={entry.bucket}
                      fill={idx >= 8 ? '#D9468F' : idx >= 7 ? '#B52A70' : '#16161D'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live What-If Pair Tester (Zero-Persistence, Browser-Only) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-[#16161D]">
              Live Browser What-If Similarity &amp; Safety Guard Tester
            </h3>
            <p className="text-xs text-[#6F6C7A]">
              Runs purely inside browser memory (zero server storage) with quick safety-trap presets.
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5 text-[11px]">
            <button
              type="button"
              onClick={() => {
                setPairTextA('Server down on production API');
                setPairTextB('Production backend API not responding');
              }}
              className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] border border-[#D8CEC0] hover:bg-[#F2ECE2]"
            >
              Paraphrase
            </button>
            <button
              type="button"
              onClick={() => {
                setPairTextA('Payment debited Rs 500 at Metro Store');
                setPairTextB('Payment debited Rs 50,000 at Metro Store');
              }}
              className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] border border-[#D8CEC0] hover:bg-[#F2ECE2]"
            >
              Entity Trap
            </button>
            <button
              type="button"
              onClick={() => {
                setPairTextA('Production API server is down');
                setPairTextB('Production API server recovered cleanly');
              }}
              className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] border border-[#D8CEC0] hover:bg-[#F2ECE2]"
            >
              Recovery Trap
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="block text-[11px] font-semibold text-[#464451] mb-1">
              Notification A
            </label>
            <input
              type="text"
              value={pairTextA}
              onChange={(e) => setPairTextA(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D]"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-[#464451] mb-1">
              Notification B
            </label>
            <input
              type="text"
              value={pairTextB}
              onChange={(e) => setPairTextB(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D]"
            />
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3 flex-1">
            <span className="text-xs font-semibold text-[#16161D] whitespace-nowrap">
              Test Threshold: {Math.round(testThreshold * 100)}%
            </span>
            <input
              type="range"
              min={0.5}
              max={0.99}
              step={0.01}
              value={testThreshold}
              onChange={(e) => setTestThreshold(Number(e.target.value))}
              className="w-full max-w-xs accent-[#D9468F]"
            />
          </div>
          <button
            type="button"
            onClick={() => void handleEvaluatePair()}
            disabled={pairTesting}
            className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] flex items-center gap-1.5 self-start sm:self-auto"
          >
            <Play className="w-3.5 h-3.5 text-[#F472B6]" />
            <span>{pairTesting ? 'Evaluating...' : 'Evaluate Pair in Browser'}</span>
          </button>
        </div>

        {pairEval && (
          <div className="p-4 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono-tech font-semibold text-[#16161D]">
                Similarity: {Math.round(pairEval.similarity * 100)}% ({pairEval.modeUsed}) · TF-IDF baseline: {Math.round(pairEval.tfidfSimilarity * 100)}%
              </span>
              <span
                className={`px-2.5 py-0.5 rounded-full font-semibold ${
                  pairEval.wouldMerge
                    ? 'bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC]'
                    : pairEval.wouldSuggest
                    ? 'bg-amber-50 text-amber-800 border border-amber-200'
                    : 'bg-[#16161D] text-[#FAF6F0]'
                }`}
              >
                {pairEval.wouldMerge
                  ? 'Decision: MERGE'
                  : pairEval.wouldSuggest
                  ? 'Decision: SUGGEST RELATED'
                  : pairEval.blockedGuard
                  ? `Decision: BLOCKED (${pairEval.blockedGuard})`
                  : 'Decision: SEPARATE THREAD'}
              </span>
            </div>
            {pairEval.guardReasons.length > 0 && (
              <div className="text-amber-900 font-medium">
                Guard Triggered: {pairEval.guardReasons.join(' ')}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Offline Colab Evaluation Metrics & Model Card */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#16161D]">
            <FileCode2 className="w-4 h-4 text-[#D9468F]" />
            <span>
              Imported Colab Evaluation ({DEFAULT_DEDUP_CONFIG.embeddingModel} · Rec Threshold {(DEFAULT_DEDUP_CONFIG.recommendedThreshold * 100).toFixed(0)}% · Window {DEFAULT_DEDUP_CONFIG.dedupWindowSeconds}s)
            </span>
          </div>
          <p className="text-[11px] text-[#6F6C7A]">
            Honesty Note: These Precision/Recall/F1/PR-AUC figures are loaded directly from the imported <code>dedupConfig.json</code> Colab benchmark (not live production traffic).
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#E5DDD0] text-[#6F6C7A] text-[11px]">
                  <th className="py-2 pr-3">Method</th>
                  <th className="py-2 px-2">Thr</th>
                  <th className="py-2 px-2">Prec</th>
                  <th className="py-2 px-2">Rec</th>
                  <th className="py-2 px-2">F1</th>
                  <th className="py-2 px-2">PR-AUC</th>
                  <th className="py-2 pl-2">Tricky FP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5DDD0]/60 font-mono-tech text-[11px]">
                {evalData.methodComparison.map((row) => (
                  <tr key={row.method}>
                    <td className="py-2 pr-3 font-sans font-medium text-[#16161D]">
                      {row.method}
                    </td>
                    <td className="py-2 px-2">{row.threshold.toFixed(2)}</td>
                    <td className="py-2 px-2">{(row.precision * 100).toFixed(1)}%</td>
                    <td className="py-2 px-2">{(row.recall * 100).toFixed(1)}%</td>
                    <td className="py-2 px-2 font-semibold text-[#B52A70]">
                      {(row.f1 * 100).toFixed(1)}%
                    </td>
                    <td className="py-2 px-2">{row.rocAuc.toFixed(3)}</td>
                    <td className="py-2 pl-2">
                      {typeof row.trickyFpRate === 'number'
                        ? `${(row.trickyFpRate * 100).toFixed(1)}%`
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#16161D]">
            <Info className="w-4 h-4 text-[#D9468F]" />
            <span>Model Card · {DEFAULT_DEDUP_CONFIG.modelCard.modelName}</span>
          </div>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="p-2.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[10px] text-[#6F6C7A]">Dimensions</div>
              <div className="font-mono-tech font-semibold">
                {DEFAULT_DEDUP_CONFIG.modelCard.embeddingDimensions}-dim
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[10px] text-[#6F6C7A]">Max Tokens</div>
              <div className="font-mono-tech font-semibold">
                {DEFAULT_DEDUP_CONFIG.modelCard.maxSequenceTokens}
              </div>
            </div>
            <div className="p-2.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
              <div className="text-[10px] text-[#6F6C7A]">Download Size</div>
              <div className="font-mono-tech font-semibold">
                ~{DEFAULT_DEDUP_CONFIG.modelCard.approxDownloadMb} MB
              </div>
            </div>
          </div>
          <p className="text-[11px] text-[#464451] leading-relaxed">
            {DEFAULT_DEDUP_CONFIG.modelCard.intendedUse}
          </p>
          <ul className="list-disc pl-4 space-y-1 text-[11px] text-[#464451]">
            {DEFAULT_DEDUP_CONFIG.modelCard.outOfScopeAndHonesty.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Isolated 13-Scenario Admin Simulator (Demo Mode OFF by default) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5DDD0] pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#16161D]">
              <FlaskConical className="w-4 h-4 text-[#D9468F]" />
              <span>Deduplication Verification Simulator (Scenarios a–m)</span>
            </div>
            <p className="text-xs text-[#6F6C7A]">
              Isolated test harness validating paraphrasing, safety guards, escalation, fallback, and zero-text/zero-vector privacy.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-xs font-semibold text-[#16161D] cursor-pointer px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0]">
              <input
                type="checkbox"
                checked={demoModeEnabled}
                onChange={(e) => setDemoModeEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F]"
              />
              <span>Demo Mode ({demoModeEnabled ? 'ON' : 'OFF'})</span>
            </label>
            <button
              type="button"
              onClick={() => void handleRunSimulator('all')}
              disabled={simBusy || !demoModeEnabled}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] disabled:opacity-50 flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{simBusy ? 'Running...' : 'Run All (a–m)'}</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {SCENARIO_LIST.map((sc) => (
            <button
              key={sc.code}
              type="button"
              onClick={() => void handleRunSimulator(sc.code)}
              disabled={simBusy || !demoModeEnabled}
              className="px-2.5 py-1.5 rounded-xl text-[11px] font-medium bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] disabled:opacity-50"
            >
              {sc.label}
            </button>
          ))}
        </div>

        {simNotice && (
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs text-[#16161D] flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#D9468F] shrink-0" />
            <span>{simNotice}</span>
          </div>
        )}

        {simResults.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-semibold text-[#16161D]">
              Scorecard: {simResults.filter((r) => r.passed).length} / {simResults.length} Passed
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {simResults.map((r) => (
                <div
                  key={r.code}
                  className={`p-3 rounded-xl border text-xs space-y-1 ${
                    r.passed
                      ? 'bg-[#F0F7F4] border-[#16A34A]/25 text-[#14532D]'
                      : 'bg-red-50 border-red-200 text-red-900'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 font-semibold">
                    <span>
                      [{r.code}] {r.title}
                    </span>
                    {r.passed ? (
                      <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-600 shrink-0" />
                    )}
                  </div>
                  <div className="text-[11px] opacity-90">Expected: {r.expected}</div>
                  <div className="text-[11px] font-mono-tech">Observed: {r.observed}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
