'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Sliders,
  RefreshCw,
  Download,
  FileCode2,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  Info,
  Clock,
  Activity,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  Cell,
} from 'recharts';
import { safeReadJson } from '../lib/http/safeJson.js';
import {
  DEFAULT_BIAS,
  DEFAULT_PRIORITY_ARTIFACT,
  DEFAULT_WEIGHTS,
  FEATURE_DISPLAY_LABELS,
  TFIDF_DEFAULT_MODEL_SUMMARY,
  scoreNotification,
  sigmoid,
} from '../lib/priority/math.js';
import {
  PRIORITY_FEATURE_NAMES,
  type FeatureVector,
  type PrioritySimulationScenarioResult,
} from '../lib/priority/types.js';

interface AdminPriorityEngineTabProps {
  token: string | null;
}

const DEFAULT_PLAYGROUND_FEATURES: FeatureVector = {
  textScore: 0.65,
  keywordUrgency: 0.35,
  senderTrust: 0.85,
  sourceReliability: 0.8,
  category_security: 0,
  category_finance: 0,
  category_work: 1,
  category_social: 0,
  category_promo: 0,
  ageFactor: 0,
  userContext: 0.75,
  repetition: 0,
  userAffinity: 0.65,
  senderClaimedPriority: 0.5,
};

export default function AdminPriorityEngineTab({ token }: AdminPriorityEngineTabProps) {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Interactive What-If Playground state (browser-only pure math)
  const [playFeatures, setPlayFeatures] = useState<FeatureVector>(DEFAULT_PLAYGROUND_FEATURES);
  const [playElapsedSec, setPlayElapsedSec] = useState<number>(0);

  // Isolated Simulator state — Demo Mode OFF by default!
  const [demoModeEnabled, setDemoModeEnabled] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [simNotice, setSimNotice] = useState<string | null>(null);
  const [simResults, setSimResults] = useState<PrioritySimulationScenarioResult[]>([]);

  const resolveToken = () =>
    token ||
    (typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null);

  const fetchStats = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/priority/stats', {
        headers: {
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Failed to load priority stats (HTTP ${res.status}).`);
      }
      setStats(json.data);
    } catch (err: any) {
      setError(err?.message || 'Unable to load admin priority stats.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void fetchStats();
  }, [fetchStats]);

  // Live playground evaluation via pure browser math
  const liveScore = useMemo(
    () =>
      scoreNotification({
        features: playFeatures,
        elapsedSeconds: playElapsedSec,
        isAcked: false,
      }),
    [playFeatures, playElapsedSec]
  );

  // Sigmoid Curve Data z in [-6, 6]
  const sigmoidCurveData = useMemo(() => {
    const pts: Array<{ z: number; p: number }> = [];
    for (let z = -6; z <= 6; z += 0.5) {
      pts.push({ z, p: Number(sigmoid(z).toFixed(4)) });
    }
    return pts;
  }, []);

  // Time Escalation Curve Data t in [0, 600] seconds
  const escalationCurveData = useMemo(() => {
    const pts: Array<{ sec: number; pUnacked: number; pAcked: number }> = [];
    const baseFeatures = { ...playFeatures, ageFactor: 0 };
    const ackedBase = scoreNotification({
      features: baseFeatures,
      elapsedSeconds: 0,
      isAcked: true,
    }).p;
    for (let sec = 0; sec <= 600; sec += 60) {
      const unacked = scoreNotification({
        features: baseFeatures,
        elapsedSeconds: sec,
        isAcked: false,
      }).p;
      pts.push({ sec, pUnacked: unacked, pAcked: ackedBase });
    }
    return pts;
  }, [playFeatures]);

  const handleRunSimulation = async (scenarioId?: string) => {
    if (!demoModeEnabled) {
      setSimNotice(
        'Demo Mode is OFF. Turn ON the Demo Mode switch above before running isolated attack simulations.'
      );
      return;
    }
    setSimBusy(true);
    setSimNotice(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/priority/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          demoMode: true,
          ...(scenarioId ? { scenarioId } : {}),
        }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || `Simulation failed (HTTP ${res.status}).`);
      }

      const incoming: PrioritySimulationScenarioResult[] = json.data?.scenarios || [];
      if (scenarioId) {
        setSimResults((prev) => {
          const map = new Map(prev.map((s) => [s.scenarioId, s]));
          for (const item of incoming) map.set(item.scenarioId, item);
          return Array.from(map.values()).sort((a, b) =>
            a.scenarioId.localeCompare(b.scenarioId)
          );
        });
      } else {
        setSimResults(incoming);
      }
      setSimNotice(
        `Executed ${incoming.length} isolated simulation scenario(s): ${incoming.filter((s) => s.passed).length}/${incoming.length} passed.`
      );
      void fetchStats();
    } catch (err: any) {
      setSimNotice(err?.message || 'Simulation request failed.');
    } finally {
      setSimBusy(false);
    }
  };

  const handleExportJson = () => {
    const exportPayload = {
      exportedAt: new Date().toISOString(),
      stats,
      defaultArtifact: DEFAULT_PRIORITY_ARTIFACT,
      simulationResults: simResults,
    };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-priority-engine-report.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleExportHtml = () => {
    const metrics = stats?.defaultModel?.metrics || DEFAULT_PRIORITY_ARTIFACT.metrics;
    const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AegisNotify Priority Engine Report</title>
<style>body{font-family:system-ui,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem;color:#16161D;background:#FAF6F0}
h1,h2{color:#16161D}table{border-collapse:collapse;width:100%;margin:1rem 0;background:#FFFDF9}
th,td{border:1px solid #E5DDD0;padding:8px;text-align:left;font-size:13px}pre{background:#FFFDF9;border:1px solid #E5DDD0;padding:12px;border-radius:8px;overflow:auto}</style>
</head><body>
<h1>AegisNotify Dynamic Sigmoid Priority Engine — Model Card &amp; Evaluation</h1>
<p><strong>Model Type:</strong> Transparent Logistic Regression (NOT deep learning). Formula: <code>z = b + sum(w_i * x_i)</code>, <code>p = 1 / (1 + exp(-z))</code>.</p>
<p><strong>Holdout Test Metrics:</strong> Accuracy=${(metrics.testAccuracy * 100).toFixed(2)}% | Precision=${metrics.testPrecision.toFixed(4)} | Recall=${metrics.testRecall.toFixed(4)} | F1=${metrics.testF1.toFixed(4)} | ROC-AUC=${metrics.testRocAuc.toFixed(4)}</p>
<p><strong>Runtime Stats:</strong> Total Scored=${stats?.totalScored ?? 0} | Mean p=${stats?.meanScore ?? 0} | Total Feedbacks=${stats?.totalFeedback ?? 0}</p>
<h2>Calibrated Global Weights (Bias b = ${DEFAULT_BIAS})</h2>
<table><tr><th>Feature</th><th>Weight</th></tr>
${PRIORITY_FEATURE_NAMES.map((f) => `<tr><td>${f}</td><td>${DEFAULT_WEIGHTS[f]}</td></tr>`).join('')}
</table>
</body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-priority-engine-report.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const labelChartData = [
    { label: 'CRITICAL', count: stats?.labelCounts?.CRITICAL ?? 0, color: '#D9468F' },
    { label: 'HIGH', count: stats?.labelCounts?.HIGH ?? 0, color: '#16161D' },
    { label: 'NORMAL', count: stats?.labelCounts?.NORMAL ?? 0, color: '#6F6C7A' },
    { label: 'LOW', count: stats?.labelCounts?.LOW ?? 0, color: '#B8B2A6' },
  ];

  const histogramData = (stats?.scoreHistogram || new Array(10).fill(0)).map(
    (count: number, idx: number) => ({
      bucket: `${(idx * 0.1).toFixed(1)}-${((idx + 1) * 0.1).toFixed(1)}`,
      count,
    })
  );

  const metrics = stats?.defaultModel?.metrics || DEFAULT_PRIORITY_ARTIFACT.metrics;
  const calibrationData = (metrics.calibrationBins || []).map((b: any) => ({
    bin: `${b.binStart.toFixed(1)}-${b.binEnd.toFixed(1)}`,
    predicted: Number(b.predictedMean.toFixed(3)),
    observed: Number(b.observedFraction.toFixed(3)),
    perfect: Number(((b.binStart + b.binEnd) / 2).toFixed(3)),
  }));

  const scenarioQuickButtons: Array<{ id: string; title: string }> = [
    { id: 'a', title: 'a. Flooding Budget' },
    { id: 'b', title: 'b. Negative Poisoning' },
    { id: 'c', title: 'c. Weight Explosion' },
    { id: 'd', title: 'd. Promo Spoof Cap' },
    { id: 'e', title: 'e. Cold-Start Gate' },
    { id: 'f', title: 'f. Time Escalation Cap' },
    { id: 'g', title: 'g. ACK Stops Escalation' },
    { id: 'h', title: 'h. Drift Warning & Reset' },
    { id: 'i', title: 'i. NaN & Raw-Text Guard' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
              <Sliders className="w-4 h-4" />
            </div>
            <h2 className="font-display text-2xl font-semibold text-[#16161D] tracking-tight">
              Dynamic Sigmoid Priority Engine
            </h2>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Transparent logistic regression scoring, online SGD personalization, calibration diagnostics, and safety-rule simulator.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void fetchStats()}
            disabled={loading}
            className="px-3.5 py-2 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-xs font-semibold text-[#16161D] flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={handleExportJson}
            className="px-3.5 py-2 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-xs font-semibold text-[#16161D] flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            type="button"
            onClick={handleExportHtml}
            className="px-3.5 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center gap-1.5"
          >
            <FileCode2 className="w-3.5 h-3.5 text-[#F472B6]" />
            <span>Export HTML Report</span>
          </button>
        </div>
      </div>

      {/* Honest Formula Info Panel */}
      <div className="rounded-2xl border border-[#E5DDD0] bg-[#FAF6F0] p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-xs">
        <div className="space-y-1">
          <div className="font-semibold text-[#16161D] flex items-center gap-1.5">
            <Info className="w-4 h-4 text-[#D9468F]" />
            <span>How the priority engine works</span>
          </div>
          <p className="text-[#464451]">
            This engine is a <strong>transparent logistic regression model — NOT deep learning</strong>. Every weight is visible, interpretable, bounded in [-4, 4], and paired with hard deterministic safety rules.
          </p>
        </div>
        <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] px-3.5 py-2 font-mono text-[11px] text-[#16161D] shrink-0">
          z = b + Σ(w_i · x_i) &nbsp;|&nbsp; p = 1 / (1 + e^(-z))
        </div>
      </div>

      {error && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-xs text-red-800 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1">
          <div className="text-xs text-[#6F6C7A]">Notifications Scored</div>
          <div className="text-2xl font-semibold text-[#16161D] font-mono tabular-nums">
            {stats?.totalScored ?? 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
            Mean p = {(stats?.meanScore ?? 0).toFixed(4)}
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1">
          <div className="text-xs text-[#6F6C7A]">Feedback &amp; Escalations</div>
          <div className="text-2xl font-semibold text-[#B52A70] font-mono tabular-nums">
            {stats?.totalFeedback ?? 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
            {stats?.escalationCount ?? 0} dynamic escalations
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1">
          <div className="text-xs text-[#6F6C7A]">Active / Personalized Models</div>
          <div className="text-2xl font-semibold text-[#16161D] font-mono tabular-nums">
            {stats?.personalizedUsersCount ?? 0} / {stats?.activeUsersCount ?? 0}
          </div>
          <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
            {stats?.driftingUsersCount ?? 0} user(s) with drift warning
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1">
          <div className="text-xs text-[#6F6C7A]">Holdout Test Performance</div>
          <div className="text-2xl font-semibold text-[#15803D] font-mono tabular-nums">
            AUC {(metrics.testRocAuc ?? 0.9467).toFixed(4)}
          </div>
          <div className="text-[11px] text-[#6F6C7A] font-mono tabular-nums">
            Acc {(metrics.testAccuracy * 100).toFixed(1)}% · F1 {metrics.testF1.toFixed(3)}
          </div>
        </div>
      </div>

      {/* Distribution & Score Histogram */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="text-xs font-semibold text-[#16161D] flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-[#D9468F]" />
            <span>Scored Priority Label Distribution</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={labelChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#16161D' }} />
                <YAxis tick={{ fontSize: 11, fill: '#464451' }} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {labelChartData.map((d) => (
                    <Cell key={d.label} fill={d.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="text-xs font-semibold text-[#16161D]">
            Score Probability Histogram (10 Bins in [0, 1])
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={histogramData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="bucket" tick={{ fontSize: 10, fill: '#464451' }} />
                <YAxis tick={{ fontSize: 11, fill: '#464451' }} allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#16161D" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Interactive Sigmoid & Time Escalation Curves */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#16161D]">
              Sigmoid Function p(z) = 1 / (1 + e^(-z))
            </span>
            <span className="font-mono text-[#B52A70] tabular-nums">
              Current marker z = {liveScore.z.toFixed(2)} → p = {liveScore.p.toFixed(3)}
            </span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={sigmoidCurveData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="z" tick={{ fontSize: 11, fill: '#464451' }} />
                <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: '#464451' }} />
                <Tooltip />
                <ReferenceLine x={0} stroke="#D8CEC0" />
                <ReferenceLine y={0.85} stroke="#D9468F" strokeDasharray="3 3" />
                <ReferenceLine y={0.65} stroke="#16161D" strokeDasharray="3 3" />
                <Line
                  type="monotone"
                  dataKey="p"
                  stroke="#D9468F"
                  strokeWidth={2.5}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#16161D] flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>Unacked Time Escalation vs ACKed Flat Line</span>
            </span>
            <span className="font-mono text-[#6F6C7A] tabular-nums">
              Cap = min(p₀ + 0.25, 0.99)
            </span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={escalationCurveData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis
                  dataKey="sec"
                  tick={{ fontSize: 11, fill: '#464451' }}
                  tickFormatter={(v) => `${v}s`}
                />
                <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: '#464451' }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="pUnacked"
                  name="Unacked p(t)"
                  stroke="#D9468F"
                  strokeWidth={2.5}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="pAcked"
                  name="ACKed (stopped)"
                  stroke="#16161D"
                  strokeDasharray="4 4"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Live What-If Playground */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5DDD0] pb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#16161D]">
              Interactive What-If Sigmoid Playground (Pure Client Math)
            </h3>
            <p className="text-[11px] text-[#6F6C7A]">
              Adjust normalized [0, 1] features and unacked age to watch z, p, safety rules, and contributions update live.
            </p>
          </div>
          <div className="flex items-center gap-3 font-mono text-xs tabular-nums">
            <span className="px-3 py-1 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] font-semibold">
              p = {liveScore.p.toFixed(4)} ({liveScore.label})
            </span>
            <button
              type="button"
              onClick={() => {
                setPlayFeatures(DEFAULT_PLAYGROUND_FEATURES);
                setPlayElapsedSec(0);
              }}
              className="px-3 py-1 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-[#464451] hover:text-[#16161D] font-sans font-semibold"
            >
              Reset Sliders
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {PRIORITY_FEATURE_NAMES.map((name) => (
            <div key={name} className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-2.5 space-y-1">
              <div className="flex justify-between text-[11px]">
                <span className="text-[#464451] truncate" title={FEATURE_DISPLAY_LABELS[name]}>
                  {name}
                </span>
                <span className="font-mono font-semibold text-[#16161D] tabular-nums">
                  {playFeatures[name].toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={playFeatures[name]}
                onChange={(e) =>
                  setPlayFeatures((prev) => ({ ...prev, [name]: Number(e.target.value) }))
                }
                className="w-full accent-[#D9468F]"
              />
            </div>
          ))}

          <div className="rounded-xl bg-[#FCECF4]/60 border border-[#F2C4DC] p-2.5 space-y-1">
            <div className="flex justify-between text-[11px]">
              <span className="text-[#B52A70] font-semibold">elapsedSeconds</span>
              <span className="font-mono font-semibold text-[#B52A70] tabular-nums">
                {playElapsedSec}s
              </span>
            </div>
            <input
              type="range"
              min={0}
              max={600}
              step={15}
              value={playElapsedSec}
              onChange={(e) => setPlayElapsedSec(Number(e.target.value))}
              className="w-full accent-[#D9468F]"
            />
          </div>
        </div>
      </div>

      {/* Model Card: Calibration Curve + Confusion Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
          <div className="text-xs font-semibold text-[#16161D]">
            10-Bin Calibration Reliability Curve (Holdout Set)
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={calibrationData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="bin" tick={{ fontSize: 10, fill: '#464451' }} />
                <YAxis domain={[0, 1]} tick={{ fontSize: 11, fill: '#464451' }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="perfect"
                  name="Ideal (y=x)"
                  stroke="#B8B2A6"
                  strokeDasharray="4 4"
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="observed"
                  name="Observed Positive Rate"
                  stroke="#D9468F"
                  strokeWidth={2.5}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
          <div className="text-xs font-semibold text-[#16161D]">
            Holdout Confusion Matrix &amp; Known Limitations
          </div>
          <div className="grid grid-cols-3 gap-2 text-xs text-center font-mono tabular-nums">
            <div />
            <div className="text-[11px] font-sans font-semibold text-[#6F6C7A]">Pred LOW/NORM</div>
            <div className="text-[11px] font-sans font-semibold text-[#6F6C7A]">Pred HIGH/CRIT</div>

            <div className="text-[11px] font-sans font-semibold text-[#6F6C7A] text-left self-center">
              Actual LOW/NORM
            </div>
            <div className="rounded-xl bg-[#F0F7F4] border border-[#16A34A]/30 py-2.5 font-semibold text-[#15803D]">
              TN: {metrics.confusionMatrix?.[0]?.[0] ?? 0}
            </div>
            <div className="rounded-xl bg-amber-50 border border-amber-200 py-2.5 font-semibold text-amber-900">
              FP: {metrics.confusionMatrix?.[0]?.[1] ?? 0}
            </div>

            <div className="text-[11px] font-sans font-semibold text-[#6F6C7A] text-left self-center">
              Actual HIGH/CRIT
            </div>
            <div className="rounded-xl bg-amber-50 border border-amber-200 py-2.5 font-semibold text-amber-900">
              FN: {metrics.confusionMatrix?.[1]?.[0] ?? 0}
            </div>
            <div className="rounded-xl bg-[#FCECF4] border border-[#F2C4DC] py-2.5 font-semibold text-[#B52A70]">
              TP: {metrics.confusionMatrix?.[1]?.[1] ?? 0}
            </div>
          </div>

          <ul className="list-disc pl-4 space-y-1 text-[11px] text-[#464451]">
            {(DEFAULT_PRIORITY_ARTIFACT.modelCard.limitations || []).map((lim, i) => (
              <li key={i}>{lim}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Imported Global Default Weights (TF-IDF Multiclass Logistic Regression) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-[#16161D]">
            <Activity className="w-4 h-4 text-[#D9468F]" />
            <span>
              Imported Global Default Text Weights ({TFIDF_DEFAULT_MODEL_SUMMARY.modelType} · v{TFIDF_DEFAULT_MODEL_SUMMARY.version})
            </span>
          </div>
          <span className="text-[11px] font-mono text-[#15803D] bg-[#F0F7F4] border border-[#16A34A]/30 px-2.5 py-0.5 rounded-xl">
            {TFIDF_DEFAULT_MODEL_SUMMARY.loaded
              ? `Loaded (${TFIDF_DEFAULT_MODEL_SUMMARY.vocabularySize.toLocaleString()} n-grams)`
              : 'Not loaded'}
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Test Accuracy</div>
            <div className="font-mono font-semibold text-[#16161D]">
              {(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_accuracy * 100).toFixed(2)}%
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">Test F1 Macro</div>
            <div className="font-mono font-semibold text-[#B52A70]">
              {(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_f1_macro * 100).toFixed(2)}%
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">ROC-AUC OvR Macro</div>
            <div className="font-mono font-semibold text-[#16161D]">
              {TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.test_roc_auc_ovr_macro.toFixed(4)}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0]">
            <div className="text-[11px] text-[#6F6C7A]">5-Fold CV F1 Mean</div>
            <div className="font-mono font-semibold text-[#16161D]">
              {(TFIDF_DEFAULT_MODEL_SUMMARY.evaluationMetrics.cv5_f1_macro_mean * 100).toFixed(2)}%
            </div>
          </div>
        </div>
        <div className="text-[11px] text-[#464451] flex flex-wrap gap-x-4 gap-y-1 font-mono">
          <span>Classes: {TFIDF_DEFAULT_MODEL_SUMMARY.classes.join(', ')}</span>
          <span>
            Intercepts: C={TFIDF_DEFAULT_MODEL_SUMMARY.intercepts.Critical}, H={TFIDF_DEFAULT_MODEL_SUMMARY.intercepts.High}, N={TFIDF_DEFAULT_MODEL_SUMMARY.intercepts.Normal}, L={TFIDF_DEFAULT_MODEL_SUMMARY.intercepts.Low}
          </span>
        </div>
      </div>

      {/* Attack & Robustness Simulator (Demo Mode OFF by default) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E5DDD0] pb-4">
          <div className="space-y-1">
            <div className="text-sm font-semibold text-[#16161D] flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#D9468F]" />
              <span>Priority Attack &amp; Robustness Simulator (Scenarios a–i)</span>
            </div>
            <p className="text-[11px] text-[#6F6C7A]">
              Runs isolated sandboxed adversarial checks without mutating real user models.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs font-semibold text-[#16161D] cursor-pointer">
              <input
                type="checkbox"
                checked={demoModeEnabled}
                onChange={(e) => {
                  setDemoModeEnabled(e.target.checked);
                  setSimNotice(null);
                }}
                className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F]"
              />
              <span>Demo Mode ({demoModeEnabled ? 'ON' : 'OFF'})</span>
            </label>

            <button
              type="button"
              disabled={simBusy}
              onClick={() => void handleRunSimulation()}
              className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{simBusy ? 'Running...' : 'Run All 9 Scenarios'}</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          {scenarioQuickButtons.map((s) => (
            <button
              key={s.id}
              type="button"
              disabled={simBusy}
              onClick={() => void handleRunSimulation(s.id)}
              className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-xs font-medium text-[#16161D] disabled:opacity-50"
            >
              {s.title}
            </button>
          ))}
        </div>

        {simNotice && (
          <div className="rounded-xl bg-[#FCECF4]/70 border border-[#F2C4DC] px-3.5 py-2.5 text-xs text-[#B52A70] font-medium">
            {simNotice}
          </div>
        )}

        {simResults.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {simResults.map((res) => (
              <div
                key={res.scenarioId}
                className="rounded-xl border border-[#E5DDD0] bg-[#FAF6F0] p-3.5 space-y-2 text-xs"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="font-semibold text-[#16161D]">
                    [{res.scenarioId.toUpperCase()}] {res.title}
                  </div>
                  {res.passed ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-[#15803D] shrink-0">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      PASS
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-red-700 shrink-0">
                      <XCircle className="w-3.5 h-3.5" />
                      FAIL
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-[#6F6C7A]">{res.attackOrCheck}</div>
                <div className="text-[11px] text-[#16161D] bg-[#FFFDF9] border border-[#E5DDD0] rounded-lg p-2">
                  <strong>Observed:</strong> {res.observedOutcome}
                </div>
                <div className="text-[10px] font-mono text-[#464451]">
                  Events: {res.telemetryEventsLogged.join(', ')}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
