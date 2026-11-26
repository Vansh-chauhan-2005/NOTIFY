'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  Pause,
  Play,
  GitBranch,
  Zap,
  ShieldAlert,
  Ban,
  Check,
  Download,
  FlaskConical,
  Filter,
  SearchX,
  AlertCircle,
  Lock,
  Radio,
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
} from 'recharts';
import {
  TRANSITION_TABLE,
  isTerminalState,
  formatMachineState,
  type DeliveryChannel,
  type DeliveryStateName,
} from '../lib/delivery/stateMachine';

export interface DeliveryHistoryEntry {
  timestamp: string;
  from: DeliveryStateName;
  event: string;
  to: DeliveryStateName;
  channel: DeliveryChannel;
  result: string;
}

export interface DeliveryJobItem {
  id: string;
  notificationId: string;
  userId: string;
  priority: 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW';
  state: DeliveryStateName;
  channel: DeliveryChannel;
  channelChain: DeliveryChannel[];
  channelIndex: number;
  attempt: number;
  requiresAck: boolean;
  ackTimeoutMs: number;
  maxRetriesPerChannel: number;
  nextAttemptAt: string;
  expiresAt: string;
  history: DeliveryHistoryEntry[];
  idempotencyKey: string;
  isDemoJob?: boolean;
  acknowledgedAt?: string | null;
  acknowledgedVia?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface DeliveryStatsData {
  totalJobs: number;
  countsByState: Record<DeliveryStateName, number>;
  deliveredCount: number;
  inProgressCount: number;
  failedCount: number;
  averageTimeToAckMs: number;
  fallbackRatePercent: number;
  channelMetrics: Array<{
    channel: 'push' | 'whatsapp' | 'sms' | 'email';
    attempts: number;
    successes: number;
    failures: number;
    successRatePercent: number;
    circuitState: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
    consecutiveFailures: number;
  }>;
  circuitBreakers: Array<{
    channel: 'push' | 'whatsapp' | 'sms' | 'email';
    state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
    consecutiveFailures: number;
    failureThreshold: number;
    cooldownRemainingMs: number;
    lastFailureReason?: string;
  }>;
  generatedAt: string;
}

export interface ScenarioResultItem {
  id: 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g';
  title: string;
  expectedOutcome: string;
  actualOutcome: string;
  passed: boolean;
  durationMs: number;
  jobId?: string;
}

interface DeliveryPipelineTabProps {
  isAdmin: boolean;
  userId?: string;
}

const SCENARIO_METADATA: Array<{ id: 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g'; label: string }> = [
  { id: 'a', label: '(a) Ack on first push -> DELIVERED_ACKED, no SMS sent' },
  { id: 'b', label: '(b) Push times out -> SMS used -> acked' },
  { id: 'c', label: '(c) Push and SMS fail -> email used -> acked' },
  { id: 'd', label: '(d) All channels fail -> FAILED_ALL_CHANNELS + admin alert' },
  { id: 'e', label: '(e) Duplicate create (same idempotencyKey) -> single job only' },
  { id: 'f', label: '(f) Illegal transition after terminal state -> rejected' },
  { id: 'g', label: '(g) Server restart mid-job -> resumes from saved state' },
];

async function safeDeliveryRequest<T = any>(
  url: string,
  options: RequestInit = {}
): Promise<{ ok: boolean; status: number; data: T | null; message: string }> {
  const token =
    typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        Accept: 'application/json',
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers || {}),
      },
    });
    const rawText = await res.text();
    if (!rawText) {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: `Empty server response (HTTP ${res.status}).`,
      };
    }
    let parsed: any;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: rawText.trimStart().startsWith('<')
          ? `Received HTML instead of JSON from delivery endpoint (HTTP ${res.status}).`
          : `Malformed JSON response (HTTP ${res.status}).`,
      };
    }
    if (!res.ok || !parsed?.success) {
      return {
        ok: false,
        status: res.status,
        data: parsed?.data ?? null,
        message: parsed?.message || `Delivery request failed (HTTP ${res.status}).`,
      };
    }
    return {
      ok: true,
      status: res.status,
      data: (parsed.data ?? null) as T,
      message: parsed.message || 'OK',
    };
  } catch (err: any) {
    return {
      ok: false,
      status: 0,
      data: null,
      message: err?.message || 'Network error contacting delivery API.',
    };
  }
}

function getStateBadgeClasses(state: DeliveryStateName): string {
  switch (state) {
    case 'DELIVERED_ACKED':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'FAILED_ALL_CHANNELS':
    case 'EXPIRED':
      return 'bg-red-50 text-red-700 border-red-200';
    case 'CANCELLED':
      return 'bg-stone-100 text-stone-600 border-stone-300';
    case 'FALLBACK':
    case 'RETRY_WAIT':
      return 'bg-amber-50 text-amber-800 border-amber-200';
    case 'AWAITING_ACK':
    case 'ATTEMPTING':
      return 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC]';
    case 'QUEUED':
    default:
      return 'bg-[#F2ECE2] text-[#464451] border-[#D8CEC0]';
  }
}

function formatDurationMs(ms: number): string {
  if (!ms || ms <= 0) return '0 ms';
  if (ms < 1000) return `${ms} ms`;
  const secs = (ms / 1000).toFixed(1);
  return `${secs} s`;
}

export default function DeliveryPipelineTab({ isAdmin, userId }: DeliveryPipelineTabProps) {
  const [jobs, setJobs] = useState<DeliveryJobItem[]>([]);
  const [stats, setStats] = useState<DeliveryStatsData | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  const [stateFilter, setStateFilter] = useState<string>('');
  const [priorityFilter, setPriorityFilter] = useState<string>('');
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [actionFeedback, setActionFeedback] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);

  // Admin Failure Simulator (Demo Mode OFF by default)
  const [demoMode, setDemoMode] = useState<boolean>(false);
  const [simBusy, setSimBusy] = useState<boolean>(false);
  const [scenarioResults, setScenarioResults] = useState<ScenarioResultItem[]>([]);
  const [lastRunTimestamp, setLastRunTimestamp] = useState<string | null>(null);
  const [showTransitionTable, setShowTransitionTable] = useState<boolean>(false);

  // Quick live test job creator
  const [quickPriority, setQuickPriority] = useState<'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW'>('CRITICAL');
  const [creatingQuickJob, setCreatingQuickJob] = useState<boolean>(false);

  const hasLoadedRef = useRef(false);

  const fetchPipelineData = useCallback(
    async (manual = false) => {
      if (!hasLoadedRef.current) setIsLoading(true);
      else if (manual) setIsRefreshing(true);

      const params = new URLSearchParams();
      params.set('limit', '100');
      if (stateFilter) params.set('state', stateFilter);
      if (priorityFilter) params.set('priority', priorityFilter);

      const [jobsRes, statsRes] = await Promise.all([
        safeDeliveryRequest<{ jobs: DeliveryJobItem[] }>(`/api/v1/delivery/jobs?${params.toString()}`),
        safeDeliveryRequest<DeliveryStatsData>('/api/v1/delivery/stats'),
      ]);

      hasLoadedRef.current = true;
      setIsLoading(false);
      setIsRefreshing(false);

      if (!jobsRes.ok || !statsRes.ok) {
        setErrorMsg(!jobsRes.ok ? jobsRes.message : statsRes.message);
        return;
      }

      setErrorMsg(null);
      const nextJobs = jobsRes.data?.jobs || [];
      setJobs(nextJobs);
      setStats(statsRes.data);

      setSelectedJobId((prev) => {
        if (prev && nextJobs.some((j) => j.id === prev)) return prev;
        return nextJobs[0]?.id || null;
      });
    },
    [stateFilter, priorityFilter]
  );

  useEffect(() => {
    void fetchPipelineData(false);
  }, [fetchPipelineData]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      void fetchPipelineData(false);
    }, 3000);
    return () => clearInterval(timer);
  }, [autoRefresh, fetchPipelineData]);

  const selectedJob = jobs.find((j) => j.id === selectedJobId) || null;

  const handleAckJob = async (jobId: string) => {
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{ job: DeliveryJobItem }>(
      `/api/v1/delivery/${encodeURIComponent(jobId)}/ack`,
      {
        method: 'POST',
        body: JSON.stringify({ via: 'admin-operator-ack' }),
      }
    );
    if (!res.ok) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    setActionFeedback({ type: 'success', message: res.message });
    await fetchPipelineData(true);
  };

  const handleCancelJob = async (jobId: string) => {
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{ job: DeliveryJobItem }>(
      `/api/v1/delivery/jobs/${encodeURIComponent(jobId)}/cancel`,
      {
        method: 'POST',
        body: JSON.stringify({ reason: 'Cancelled from Delivery Pipeline console' }),
      }
    );
    if (!res.ok) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    setActionFeedback({ type: 'success', message: res.message });
    await fetchPipelineData(true);
  };

  const handleCreateQuickLiveJob = async () => {
    setCreatingQuickJob(true);
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{ job: DeliveryJobItem }>('/api/v1/delivery/jobs', {
      method: 'POST',
      body: JSON.stringify({
        notificationId: `pipeline_test_${Date.now().toString(36)}`,
        userId: userId || 'usr_sec_admin_01',
        priority: quickPriority,
        idempotencyKey: `ui_quick:${Date.now()}:${Math.random().toString(36).slice(2, 7)}`,
      }),
    });
    setCreatingQuickJob(false);
    if (!res.ok || !res.data?.job) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    setSelectedJobId(res.data.job.id);
    setActionFeedback({
      type: 'success',
      message: `Live ${quickPriority} job ${res.data.job.id} created -> ${res.data.job.state}.`,
    });
    await fetchPipelineData(true);
  };

  const handleInjectFault = async (
    faultPatch: Record<string, boolean>,
    label: string
  ) => {
    if (!demoMode) return;
    setSimBusy(true);
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{ job: DeliveryJobItem }>('/api/v1/delivery/simulate', {
      method: 'POST',
      body: JSON.stringify({
        demoMode: true,
        action: 'INJECT_FAULTS',
        priority: 'CRITICAL',
        faults: faultPatch,
      }),
    });
    setSimBusy(false);
    if (!res.ok || !res.data?.job) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    setSelectedJobId(res.data.job.id);
    setActionFeedback({
      type: 'success',
      message: `${label}: finished in ${res.data.job.state} (${res.data.job.history.length} transitions).`,
    });
    await fetchPipelineData(true);
  };

  const handleRunScenario = async (scenarioId: 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g') => {
    if (!demoMode) return;
    setSimBusy(true);
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{ result: ScenarioResultItem }>('/api/v1/delivery/simulate', {
      method: 'POST',
      body: JSON.stringify({
        demoMode: true,
        action: 'RUN_SCENARIO',
        scenarioId,
      }),
    });
    setSimBusy(false);
    if (!res.ok || !res.data?.result) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    const item = res.data.result;
    setScenarioResults((prev) => {
      const rest = prev.filter((r) => r.id !== item.id);
      return [...rest, item].sort((a, b) => a.id.localeCompare(b.id));
    });
    setLastRunTimestamp(new Date().toISOString());
    if (item.jobId) setSelectedJobId(item.jobId);
    setActionFeedback({
      type: item.passed ? 'success' : 'error',
      message: `${item.title}: ${item.passed ? 'PASS' : 'FAIL'}`,
    });
    await fetchPipelineData(true);
  };

  const handleRunAllScenarios = async () => {
    if (!demoMode) return;
    setSimBusy(true);
    setActionFeedback(null);
    const res = await safeDeliveryRequest<{
      results: ScenarioResultItem[];
      passedCount: number;
      totalCount: number;
      allPassed: boolean;
      generatedAt: string;
    }>('/api/v1/delivery/simulate', {
      method: 'POST',
      body: JSON.stringify({
        demoMode: true,
        action: 'RUN_ALL',
      }),
    });
    setSimBusy(false);
    if (!res.ok || !res.data?.results) {
      setActionFeedback({ type: 'error', message: res.message });
      return;
    }
    setScenarioResults(res.data.results);
    setLastRunTimestamp(res.data.generatedAt || new Date().toISOString());
    const lastWithJob = [...res.data.results].reverse().find((r) => r.jobId);
    if (lastWithJob?.jobId) setSelectedJobId(lastWithJob.jobId);
    setActionFeedback({
      type: res.data.allPassed ? 'success' : 'error',
      message: `Suite Complete: ${res.data.passedCount}/${res.data.totalCount} scenarios passed.`,
    });
    await fetchPipelineData(true);
  };

  const handleExportReport = (format: 'json' | 'html') => {
    const reportPayload = {
      generatedAt: lastRunTimestamp || new Date().toISOString(),
      stats,
      passedCount: scenarioResults.filter((r) => r.passed).length,
      totalScenariosRun: scenarioResults.length,
      scenarios: scenarioResults,
    };

    let blob: Blob;
    let filename: string;
    if (format === 'json') {
      blob = new Blob([JSON.stringify(reportPayload, null, 2)], { type: 'application/json' });
      filename = `aegis-delivery-report-${Date.now()}.json`;
    } else {
      const rows = scenarioResults
        .map(
          (r) =>
            `<tr><td>${r.id.toUpperCase()}</td><td>${r.title}</td><td><strong>${
              r.passed ? 'PASS' : 'FAIL'
            }</strong></td><td>${r.actualOutcome}</td><td>${r.durationMs}ms</td></tr>`
        )
        .join('');
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>AegisNotify Delivery Test Report</title><style>body{font-family:system-ui,sans-serif;padding:24px;background:#faf6f0;color:#16161d}table{width:100%;border-collapse:collapse;background:#fff}th,td{border:1px solid #d8cec0;padding:8px 10px;text-align:left;font-size:13px}th{background:#f2ece2}</style></head><body><h1>AegisNotify Multi-Channel Delivery Scorecard</h1><p>Generated: ${reportPayload.generatedAt} · Passed: ${reportPayload.passedCount}/${reportPayload.totalScenariosRun}</p><table><thead><tr><th>ID</th><th>Scenario</th><th>Status</th><th>Outcome</th><th>Duration</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
      blob = new Blob([html], { type: 'text/html' });
      filename = `aegis-delivery-report-${Date.now()}.html`;
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  // Compute active edge/state highlights for the live State Machine Diagram
  const traversedStates = new Set<DeliveryStateName>();
  const traversedPairs = new Set<string>();
  if (selectedJob) {
    traversedStates.add(selectedJob.state);
    for (const h of selectedJob.history) {
      traversedStates.add(h.from);
      traversedStates.add(h.to);
      traversedPairs.add(`${h.from}->${h.to}`);
    }
  }

  const isEdgeHot = (from: DeliveryStateName, to: DeliveryStateName) =>
    traversedPairs.has(`${from}->${to}`);

  const diagramNodes: Array<{
    state: DeliveryStateName;
    label: string;
    sublabel: string;
    tone: 'neutral' | 'active' | 'warn' | 'success' | 'danger';
  }> = [
    { state: 'QUEUED', label: 'QUEUED', sublabel: 'Job persisted', tone: 'neutral' },
    {
      state: 'ATTEMPTING',
      label:
        selectedJob?.state === 'ATTEMPTING'
          ? `ATTEMPTING(${selectedJob.channel})`
          : 'ATTEMPTING(ch)',
      sublabel: 'Channel send',
      tone: 'active',
    },
    {
      state: 'AWAITING_ACK',
      label:
        selectedJob?.state === 'AWAITING_ACK'
          ? `AWAITING_ACK(${selectedJob.channel})`
          : 'AWAITING_ACK(ch)',
      sublabel: 'SLA timer running',
      tone: 'active',
    },
    {
      state: 'RETRY_WAIT',
      label:
        selectedJob?.state === 'RETRY_WAIT'
          ? `RETRY_WAIT(${selectedJob.channel})`
          : 'RETRY_WAIT(ch)',
      sublabel: 'Exp backoff + jitter',
      tone: 'warn',
    },
    {
      state: 'FALLBACK',
      label:
        selectedJob?.state === 'FALLBACK'
          ? `FALLBACK(${selectedJob.channel})`
          : 'FALLBACK(next)',
      sublabel: 'Next channel queued',
      tone: 'warn',
    },
    {
      state: 'DELIVERED_ACKED',
      label: 'DELIVERED_ACKED',
      sublabel: 'Terminal · ACKed',
      tone: 'success',
    },
    {
      state: 'FAILED_ALL_CHANNELS',
      label: 'FAILED_ALL_CHANNELS',
      sublabel: 'Terminal · Admin alert',
      tone: 'danger',
    },
    {
      state: 'CANCELLED',
      label: 'CANCELLED',
      sublabel: 'Terminal · Stopped',
      tone: 'neutral',
    },
    {
      state: 'EXPIRED',
      label: 'EXPIRED',
      sublabel: 'Terminal · TTL hit',
      tone: 'danger',
    },
  ];

  const channelChartData = stats?.channelMetrics || [
    { channel: 'push', attempts: 0, successes: 0, failures: 0, successRatePercent: 100 },
    { channel: 'whatsapp', attempts: 0, successes: 0, failures: 0, successRatePercent: 100 },
    { channel: 'sms', attempts: 0, successes: 0, failures: 0, successRatePercent: 100 },
    { channel: 'email', attempts: 0, successes: 0, failures: 0, successRatePercent: 100 },
  ];

  const passedScenarios = scenarioResults.filter((r) => r.passed).length;

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#16161D] text-[#F472B6] flex items-center justify-center">
              <GitBranch className="w-4 h-4" />
            </div>
            <h3 className="font-display text-xl font-semibold text-[#16161D] tracking-tight">
              Multi-Channel Delivery Pipeline
            </h3>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Push → WhatsApp → SMS → Email fallback state machine · Zero plaintext on ephemeral alerts
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Quick live dispatch test */}
          <div className="flex items-center gap-1.5 bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl p-1">
            <select
              aria-label="Test job priority"
              value={quickPriority}
              onChange={(e) => setQuickPriority(e.target.value as any)}
              className="bg-transparent px-2 py-1 text-xs font-semibold text-[#16161D] focus:outline-none"
            >
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="NORMAL">NORMAL</option>
              <option value="LOW">LOW</option>
            </select>
            <button
              type="button"
              onClick={() => void handleCreateQuickLiveJob()}
              disabled={creatingQuickJob}
              className="px-3 py-1.5 rounded-lg bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold flex items-center space-x-1 whitespace-nowrap disabled:opacity-60"
            >
              <Zap className="w-3 h-3" />
              <span>{creatingQuickJob ? 'Queueing...' : 'New Live Job'}</span>
            </button>
          </div>

          <button
            type="button"
            onClick={() => setAutoRefresh((prev) => !prev)}
            className={`px-3.5 py-2 rounded-xl text-xs font-semibold border transition-all flex items-center space-x-1.5 whitespace-nowrap ${
              !autoRefresh
                ? 'bg-[#D9468F] text-[#FFFDF9] border-[#D9468F]'
                : 'bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border-[#D8CEC0]'
            }`}
          >
            {autoRefresh ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{autoRefresh ? 'Pause Poll (3s)' : 'Resume Poll'}</span>
          </button>

          <button
            type="button"
            onClick={() => void fetchPipelineData(true)}
            disabled={isRefreshing}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] flex items-center space-x-1.5 disabled:opacity-60 whitespace-nowrap"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Feedback / Error Banners */}
      {errorMsg && (
        <div className="rounded-2xl bg-red-50 border border-red-200 px-5 py-3.5 flex items-center justify-between gap-3">
          <div className="flex items-center space-x-2.5 text-xs text-red-700">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button
            type="button"
            onClick={() => void fetchPipelineData(true)}
            className="px-3 py-1 rounded-lg bg-red-700 text-white text-xs font-semibold"
          >
            Retry
          </button>
        </div>
      )}

      {actionFeedback && (
        <div
          className={`rounded-2xl px-4 py-3 border text-xs flex items-center space-x-2 ${
            actionFeedback.type === 'success'
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-red-50 border-red-200 text-red-700'
          }`}
        >
          {actionFeedback.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0" />
          )}
          <span>{actionFeedback.message}</span>
        </div>
      )}

      {isLoading ? (
        <div className="glass-panel rounded-2xl p-12 border border-[#E5DDD0] flex flex-col items-center justify-center space-y-3 text-[#6F6C7A]">
          <RefreshCw className="w-6 h-6 text-[#D9468F] animate-spin" />
          <p className="text-xs font-medium">Loading delivery state machine telemetry...</p>
        </div>
      ) : (
        <>
          {/* 1. Stats Row (5 KPIs) */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
            <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
                <span>Delivered</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              </div>
              <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                {stats?.deliveredCount ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                of {stats?.totalJobs ?? 0} total jobs
              </div>
            </div>

            <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
                <span>In-Progress</span>
                <Radio className="w-4 h-4 text-[#D9468F]" />
              </div>
              <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                {stats?.inProgressCount ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                {stats?.countsByState.AWAITING_ACK ?? 0} awaiting ACK
              </div>
            </div>

            <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
                <span>Failed</span>
                <ShieldAlert className="w-4 h-4 text-red-600" />
              </div>
              <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                {stats?.failedCount ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                {stats?.countsByState.CANCELLED ?? 0} cancelled
              </div>
            </div>

            <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1.5">
              <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
                <span>Avg Time to Ack</span>
                <Clock className="w-4 h-4 text-[#B52A70]" />
              </div>
              <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                {formatDurationMs(stats?.averageTimeToAckMs ?? 0)}
              </div>
              <div className="text-[11px] text-[#6F6C7A]">Create to ACK latency</div>
            </div>

            <div className="glass-panel rounded-2xl p-4 border border-[#E5DDD0] space-y-1.5 col-span-2 md:col-span-1">
              <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
                <span>Fallback Rate</span>
                <AlertTriangle className="w-4 h-4 text-amber-600" />
              </div>
              <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                {stats?.fallbackRatePercent ?? 0}%
              </div>
              <div className="text-[11px] text-[#6F6C7A]">Escalated past Push</div>
            </div>
          </div>

          {/* 2. Circuit Breakers + Channel Success Rate Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Circuit Breakers Card */}
            <div className="lg:col-span-5 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
              <div>
                <h4 className="font-display text-base font-semibold text-[#16161D]">
                  Channel Circuit Breakers
                </h4>
                <p className="text-[11px] text-[#6F6C7A]">
                  3 consecutive failures opens channel for 60s; jobs skip directly to next channel
                </p>
              </div>

              <div className="space-y-2.5">
                {(stats?.circuitBreakers || []).map((cb) => {
                  const badgeClass =
                    cb.state === 'OPEN'
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : cb.state === 'HALF_OPEN'
                      ? 'bg-amber-50 text-amber-800 border-amber-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200';
                  return (
                    <div
                      key={cb.channel}
                      className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] px-4 py-3 flex items-center justify-between gap-3"
                    >
                      <div>
                        <div className="text-xs font-bold uppercase tracking-wide text-[#16161D] font-mono-tech">
                          {cb.channel}
                        </div>
                        <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                          Failures: {cb.consecutiveFailures}/{cb.failureThreshold}
                          {cb.state === 'OPEN' && cb.cooldownRemainingMs > 0
                            ? ` · Retry in ${Math.ceil(cb.cooldownRemainingMs / 1000)}s`
                            : ''}
                        </div>
                      </div>
                      <span
                        className={`px-2.5 py-1 rounded-full text-[11px] font-semibold border font-mono-tech ${badgeClass}`}
                      >
                        {cb.state}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Channel Success Rate Chart */}
            <div className="lg:col-span-7 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="font-display text-base font-semibold text-[#16161D]">
                    Channel Success Rate (%)
                  </h4>
                  <p className="text-[11px] text-[#6F6C7A]">
                    Live attempt outcome distribution across Push, WhatsApp, SMS, and Email adapters
                  </p>
                </div>
              </div>

              <div className="h-48 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={channelChartData} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                    <XAxis
                      dataKey="channel"
                      tickFormatter={(v) => String(v).toUpperCase()}
                      tick={{ fontSize: 11, fill: '#464451' }}
                      stroke="#D8CEC0"
                    />
                    <YAxis
                      domain={[0, 100]}
                      tick={{ fontSize: 11, fill: '#6F6C7A' }}
                      stroke="#D8CEC0"
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#FFFDF9',
                        borderColor: '#E5DDD0',
                        borderRadius: '12px',
                        fontSize: '12px',
                        color: '#16161D',
                      }}
                      formatter={(val: any, _name: any, props: any) => [
                        `${val}% (${props.payload.successes}/${props.payload.attempts} attempts)`,
                        'Success Rate',
                      ]}
                    />
                    <Bar dataKey="successRatePercent" name="Success Rate" radius={[8, 8, 0, 0]} isAnimationActive={false}>
                      {channelChartData.map((entry) => (
                        <Cell
                          key={entry.channel}
                          fill={
                            entry.channel === 'push'
                              ? '#16161D'
                              : entry.channel === 'whatsapp'
                              ? '#25D366'
                              : entry.channel === 'sms'
                              ? '#D9468F'
                              : '#464451'
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* 3. Live Interactive State Machine Diagram */}
          <div className="rounded-2xl border border-[#2A2935] bg-[#16161D] text-[#FAF6F0] p-5 sm:p-6 space-y-4 shadow-md">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-[#F472B6]" />
                  <h4 className="font-display text-base font-semibold text-[#FAF6F0]">
                    Live State Machine Diagram
                  </h4>
                  {selectedJob && (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono-tech bg-[#D9468F]/20 text-[#F472B6] border border-[#D9468F]/40">
                      {formatMachineState({ state: selectedJob.state, channel: selectedJob.channel })}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-[#A9A6B5] mt-0.5">
                  {selectedJob
                    ? `Inspecting job ${selectedJob.id} (${selectedJob.priority}) · Chain: ${selectedJob.channelChain.join(' → ')}`
                    : 'Select a delivery job below to highlight its active state and traversed path'}
                </p>
              </div>

              <button
                type="button"
                onClick={() => setShowTransitionTable((prev) => !prev)}
                className="px-3 py-1.5 rounded-xl bg-[#252431] hover:bg-[#312F40] border border-[#3B394D] text-xs font-medium text-[#FAF6F0] self-start sm:self-center whitespace-nowrap"
              >
                {showTransitionTable ? 'Hide Transition Table' : `View Transition Table (${TRANSITION_TABLE.length})`}
              </button>
            </div>

            {/* Visual State Grid + Flow Connectors */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {diagramNodes.map((node) => {
                const isCurrent = selectedJob?.state === node.state;
                const wasVisited = traversedStates.has(node.state);

                let borderStyle = 'border-[#2E2D3B] bg-[#1E1D27]';
                if (isCurrent) {
                  borderStyle =
                    'border-[#D9468F] bg-[#311A29] ring-2 ring-[#D9468F]/50 shadow-lg';
                } else if (wasVisited) {
                  borderStyle = 'border-[#F472B6]/60 bg-[#252130]';
                }

                const dotColor =
                  node.tone === 'success'
                    ? 'bg-emerald-400'
                    : node.tone === 'danger'
                    ? 'bg-red-400'
                    : node.tone === 'warn'
                    ? 'bg-amber-400'
                    : node.tone === 'active'
                    ? 'bg-[#F472B6]'
                    : 'bg-[#8A8794]';

                return (
                  <div
                    key={node.state}
                    className={`rounded-xl border p-3.5 transition-all ${borderStyle}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center space-x-2 min-w-0">
                        <span
                          className={`w-2.5 h-2.5 rounded-full shrink-0 ${dotColor} ${
                            isCurrent ? 'animate-pulse' : ''
                          }`}
                        />
                        <span className="font-mono-tech text-xs font-bold text-[#FAF6F0] truncate">
                          {node.label}
                        </span>
                      </div>
                      {isCurrent && (
                        <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-[#D9468F] text-[#FFFDF9] shrink-0">
                          Active
                        </span>
                      )}
                      {!isCurrent && wasVisited && (
                        <span className="text-[10px] font-mono-tech text-[#F472B6] shrink-0">
                          Visited
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-[#A9A6B5] mt-1">{node.sublabel}</p>
                  </div>
                );
              })}
            </div>

            {/* Key Traversed Transition Pills */}
            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#2E2D3B] text-[11px] font-mono-tech">
              <span className="text-[#A9A6B5]">Key Paths:</span>
              {[
                { from: 'QUEUED' as const, to: 'ATTEMPTING' as const, label: 'QUEUED ─[START]→ ATTEMPTING' },
                { from: 'ATTEMPTING' as const, to: 'AWAITING_ACK' as const, label: 'ATTEMPTING ─[SEND_OK]→ AWAITING_ACK' },
                { from: 'ATTEMPTING' as const, to: 'RETRY_WAIT' as const, label: 'ATTEMPTING ─[SEND_FAILED]→ RETRY_WAIT' },
                { from: 'RETRY_WAIT' as const, to: 'ATTEMPTING' as const, label: 'RETRY_WAIT ─[RETRY_TIMER]→ ATTEMPTING' },
                { from: 'AWAITING_ACK' as const, to: 'FALLBACK' as const, label: 'AWAITING_ACK ─[ACK_TIMEOUT]→ FALLBACK' },
                { from: 'AWAITING_ACK' as const, to: 'DELIVERED_ACKED' as const, label: 'AWAITING_ACK ─[ACK_RECEIVED]→ DELIVERED_ACKED' },
                { from: 'ATTEMPTING' as const, to: 'FAILED_ALL_CHANNELS' as const, label: 'ATTEMPTING ─[EXHAUSTED]→ FAILED_ALL_CHANNELS' },
              ].map((edge) => {
                const hot = isEdgeHot(edge.from, edge.to);
                return (
                  <span
                    key={edge.label}
                    className={`px-2.5 py-1 rounded-lg border ${
                      hot
                        ? 'bg-[#D9468F]/25 border-[#D9468F] text-[#FCECF4]'
                        : 'bg-[#1E1D27] border-[#2E2D3B] text-[#8A8794]'
                    }`}
                  >
                    {edge.label}
                  </span>
                );
              })}
            </div>

            {showTransitionTable && (
              <div className="mt-3 overflow-x-auto rounded-xl border border-[#2E2D3B] bg-[#1A1923]">
                <table className="w-full text-left text-[11px] font-mono-tech">
                  <thead className="bg-[#252431] text-[#D8CEC0]">
                    <tr>
                      <th className="py-2 px-3">From</th>
                      <th className="py-2 px-3">Event</th>
                      <th className="py-2 px-3">Condition</th>
                      <th className="py-2 px-3">To</th>
                      <th className="py-2 px-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2E2D3B]">
                    {TRANSITION_TABLE.map((row) => (
                      <tr key={row.id} className="text-[#D8CEC0]">
                        <td className="py-1.5 px-3">{row.from}</td>
                        <td className="py-1.5 px-3 text-[#F472B6]">{row.event}</td>
                        <td className="py-1.5 px-3 text-[#A9A6B5]">{row.condition}</td>
                        <td className="py-1.5 px-3">{row.to}</td>
                        <td className="py-1.5 px-3 text-[#A9A6B5]">{row.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* 4. Filterable Jobs List & Selected Job Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Jobs Table */}
            <div className="lg:col-span-7 glass-panel rounded-2xl border border-[#E5DDD0] overflow-hidden">
              <div className="p-4 border-b border-[#E5DDD0] bg-[#FFFDF9] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5">
                <div className="flex items-center space-x-2">
                  <Filter className="w-4 h-4 text-[#D9468F]" />
                  <h4 className="font-display text-sm font-semibold text-[#16161D]">
                    Delivery Jobs ({jobs.length})
                  </h4>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    aria-label="Filter jobs by state"
                    value={stateFilter}
                    onChange={(e) => setStateFilter(e.target.value)}
                    className="px-2.5 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D]"
                  >
                    <option value="">All States</option>
                    <option value="QUEUED">QUEUED</option>
                    <option value="ATTEMPTING">ATTEMPTING</option>
                    <option value="AWAITING_ACK">AWAITING_ACK</option>
                    <option value="RETRY_WAIT">RETRY_WAIT</option>
                    <option value="FALLBACK">FALLBACK</option>
                    <option value="DELIVERED_ACKED">DELIVERED_ACKED</option>
                    <option value="FAILED_ALL_CHANNELS">FAILED_ALL_CHANNELS</option>
                    <option value="CANCELLED">CANCELLED</option>
                    <option value="EXPIRED">EXPIRED</option>
                  </select>

                  <select
                    aria-label="Filter jobs by priority"
                    value={priorityFilter}
                    onChange={(e) => setPriorityFilter(e.target.value)}
                    className="px-2.5 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D]"
                  >
                    <option value="">All Priorities</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="NORMAL">NORMAL</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto max-h-[420px]">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#F2ECE2] text-[#464451] text-[11px] font-semibold border-b border-[#E5DDD0] sticky top-0">
                    <tr>
                      <th className="py-2.5 px-3.5">Job</th>
                      <th className="py-2.5 px-3.5">Priority</th>
                      <th className="py-2.5 px-3.5">State</th>
                      <th className="py-2.5 px-3.5">Channel</th>
                      <th className="py-2.5 px-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E5DDD0]">
                    {jobs.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-12 text-center text-[#6F6C7A]">
                          <div className="flex flex-col items-center space-y-2">
                            <SearchX className="w-6 h-6 text-[#D9468F]/70" />
                            <span>No delivery jobs match the active filters.</span>
                          </div>
                        </td>
                      </tr>
                    ) : (
                      jobs.map((job) => {
                        const selected = job.id === selectedJobId;
                        const terminal = isTerminalState(job.state);
                        return (
                          <tr
                            key={job.id}
                            onClick={() => setSelectedJobId(job.id)}
                            className={`cursor-pointer transition-colors ${
                              selected ? 'bg-[#FCECF4]/55' : 'hover:bg-[#FAF6F0]'
                            }`}
                          >
                            <td className="py-2.5 px-3.5 font-mono-tech">
                              <div className="font-semibold text-[#16161D] flex items-center space-x-1.5">
                                <span>{job.id.slice(0, 16)}</span>
                                {job.isDemoJob && (
                                  <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 text-[10px]">
                                    DEMO
                                  </span>
                                )}
                              </div>
                              <div className="text-[10px] text-[#6F6C7A]">
                                {new Date(job.createdAt).toLocaleTimeString()} · {job.history.length} steps
                              </div>
                            </td>
                            <td className="py-2.5 px-3.5 font-semibold text-[#16161D]">
                              {job.priority}
                            </td>
                            <td className="py-2.5 px-3.5">
                              <span
                                className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold border font-mono-tech ${getStateBadgeClasses(
                                  job.state
                                )}`}
                              >
                                {job.state}
                              </span>
                            </td>
                            <td className="py-2.5 px-3.5 font-mono-tech text-[#464451]">
                              {job.channel} (#{job.attempt})
                            </td>
                            <td
                              className="py-2.5 px-3.5 text-right whitespace-nowrap"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {!terminal ? (
                                <div className="inline-flex items-center space-x-1.5">
                                  <button
                                    type="button"
                                    onClick={() => void handleAckJob(job.id)}
                                    className="px-2 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] font-semibold"
                                    title="Acknowledge notification"
                                  >
                                    Ack
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => void handleCancelJob(job.id)}
                                    className="px-2 py-1 rounded-lg bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#464451] border border-[#D8CEC0] text-[11px] font-semibold"
                                    title="Cancel job"
                                  >
                                    Cancel
                                  </button>
                                </div>
                              ) : (
                                <span className="text-[11px] text-[#6F6C7A]">Terminal</span>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Selected Job Timeline */}
            <div className="lg:col-span-5 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
                <div>
                  <h4 className="font-display text-sm font-semibold text-[#16161D]">
                    Job Transition Timeline
                  </h4>
                  <p className="text-[11px] text-[#6F6C7A] font-mono-tech">
                    {selectedJob ? selectedJob.id : 'No job selected'}
                  </p>
                </div>
                {selectedJob && !isTerminalState(selectedJob.state) && (
                  <div className="flex items-center space-x-1.5">
                    <button
                      type="button"
                      onClick={() => void handleAckJob(selectedJob.id)}
                      className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] font-semibold flex items-center space-x-1"
                    >
                      <Check className="w-3 h-3" />
                      <span>Acknowledge</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleCancelJob(selectedJob.id)}
                      className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-[11px] font-semibold flex items-center space-x-1"
                    >
                      <Ban className="w-3 h-3" />
                      <span>Cancel</span>
                    </button>
                  </div>
                )}
              </div>

              {!selectedJob ? (
                <div className="py-12 text-center text-xs text-[#6F6C7A]">
                  Click a job on the left to inspect its channel transitions, retry timers, and fallback reasons.
                </div>
              ) : (
                <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
                  <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-[11px] font-mono-tech space-y-1">
                    <div>
                      <span className="text-[#6F6C7A]">Plan: </span>
                      <span className="text-[#16161D] font-semibold">
                        {selectedJob.channelChain.join(' → ')}
                      </span>
                    </div>
                    <div>
                      <span className="text-[#6F6C7A]">Idempotency: </span>
                      <span className="text-[#464451]">{selectedJob.idempotencyKey}</span>
                    </div>
                    {selectedJob.acknowledgedVia && (
                      <div>
                        <span className="text-[#6F6C7A]">Acked Via: </span>
                        <span className="text-emerald-700 font-semibold">
                          {selectedJob.acknowledgedVia}
                        </span>
                      </div>
                    )}
                  </div>

                  {selectedJob.history.map((step, idx) => (
                    <div
                      key={`${step.timestamp}_${idx}`}
                      className="relative pl-5 pb-3 border-l-2 border-[#E5DDD0] last:border-l-transparent"
                    >
                      <span className="w-2.5 h-2.5 rounded-full bg-[#D9468F] absolute -left-[6px] top-1" />
                      <div className="flex items-center justify-between gap-2 text-[11px]">
                        <span className="font-mono-tech font-semibold text-[#16161D]">
                          {step.from} → {step.to}
                        </span>
                        <span className="text-[#6F6C7A] font-mono-tech">
                          {new Date(step.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="text-[11px] text-[#B52A70] font-mono-tech mt-0.5">
                        [{step.event}] · channel: {step.channel}
                      </div>
                      <p className="text-xs text-[#464451] mt-1 leading-relaxed">{step.result}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* 5. Admin-Only Failure Simulator */}
          {isAdmin && (
            <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-6 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-[#E5DDD0] pb-4">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
                      <FlaskConical className="w-4 h-4" />
                    </div>
                    <h4 className="font-display text-base font-semibold text-[#16161D]">
                      Failure Simulator &amp; Automated Verification Suite
                    </h4>
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                        demoMode
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-[#F2ECE2] text-[#464451] border-[#D8CEC0]'
                      }`}
                    >
                      {demoMode ? 'Demo Mode: ON (Isolated)' : 'Demo Mode: OFF'}
                    </span>
                  </div>
                  <p className="text-xs text-[#6F6C7A]">
                    Inject mock channel faults and run test scenarios (a)–(g) without affecting real users or live circuit breakers.
                  </p>
                </div>

                <label className="flex items-center space-x-2.5 cursor-pointer select-none px-3.5 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0]">
                  <input
                    id="delivery-simulator-demo-mode"
                    type="checkbox"
                    checked={demoMode}
                    onChange={(e) => setDemoMode(e.target.checked)}
                    className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                  />
                  <span className="text-xs font-semibold text-[#16161D]">Enable Demo Mode</span>
                </label>
              </div>

              {!demoMode ? (
                <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-5 flex items-center space-x-3 text-xs text-[#464451]">
                  <Lock className="w-4 h-4 text-[#B52A70] shrink-0" />
                  <span>
                    Fault injection controls are locked while <strong>Demo Mode</strong> is OFF. Toggle Demo Mode ON above to run isolated mock simulations and automated scenarios (a)–(g).
                  </span>
                </div>
              ) : (
                <div className="space-y-5">
                  {/* Fault Injection Buttons */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-[#464451]">
                      1. Fault Injection (Isolated Mock Test Account Only)
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {[
                        {
                          label: 'Force Push Fail',
                          faults: { forcePushFail: true },
                        },
                        {
                          label: 'Force WhatsApp Fail',
                          faults: { forceWhatsappFail: true },
                        },
                        {
                          label: 'Force SMS Fail',
                          faults: { forceSmsFail: true },
                        },
                        {
                          label: 'Force Email Fail',
                          faults: { forceEmailFail: true },
                        },
                        {
                          label: 'Force No Ack',
                          faults: { forceNoAck: true },
                        },
                        {
                          label: 'Force Slow Ack',
                          faults: { forceSlowAck: true },
                        },
                        {
                          label: 'Force All Channels Down',
                          faults: { forceAllDown: true },
                        },
                      ].map((btn) => (
                        <button
                          key={btn.label}
                          type="button"
                          disabled={simBusy}
                          onClick={() => void handleInjectFault(btn.faults, btn.label)}
                          className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all disabled:opacity-50"
                        >
                          {btn.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Scenarios (a)-(g) + Run All + Export */}
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="text-xs font-semibold text-[#464451]">
                          2. Automated Scenarios (a)–(g)
                        </div>
                        {scenarioResults.length > 0 && (
                          <div className="text-xs text-[#16161D] font-mono-tech mt-0.5">
                            Scorecard:{' '}
                            <strong className="text-[#B52A70]">
                              {passedScenarios}/{scenarioResults.length} PASSED
                            </strong>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          disabled={simBusy}
                          onClick={() => void handleRunAllScenarios()}
                          className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] flex items-center space-x-1.5 disabled:opacity-50"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>{simBusy ? 'Running Suite...' : 'Run All Scenarios'}</span>
                        </button>

                        <button
                          type="button"
                          disabled={scenarioResults.length === 0}
                          onClick={() => handleExportReport('json')}
                          className="px-3 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] flex items-center space-x-1.5 disabled:opacity-45"
                        >
                          <Download className="w-3.5 h-3.5 text-[#D9468F]" />
                          <span>Export JSON</span>
                        </button>

                        <button
                          type="button"
                          disabled={scenarioResults.length === 0}
                          onClick={() => handleExportReport('html')}
                          className="px-3 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] flex items-center space-x-1.5 disabled:opacity-45"
                        >
                          <Download className="w-3.5 h-3.5 text-[#16161D]" />
                          <span>Export HTML</span>
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {SCENARIO_METADATA.map((meta) => {
                        const result = scenarioResults.find((r) => r.id === meta.id);
                        return (
                          <div
                            key={meta.id}
                            className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3.5 flex items-start justify-between gap-3"
                          >
                            <div className="space-y-1 min-w-0">
                              <div className="text-xs font-semibold text-[#16161D]">{meta.label}</div>
                              {result && (
                                <p className="text-[11px] text-[#464451] font-mono-tech break-words">
                                  {result.actualOutcome} ({result.durationMs}ms)
                                </p>
                              )}
                            </div>

                            <div className="flex items-center space-x-2 shrink-0">
                              {result && (
                                <span
                                  className={`px-2 py-0.5 rounded-full text-[10px] font-bold border inline-flex items-center space-x-1 ${
                                    result.passed
                                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                      : 'bg-red-50 text-red-700 border-red-200'
                                  }`}
                                >
                                  {result.passed ? (
                                    <CheckCircle2 className="w-3 h-3" />
                                  ) : (
                                    <XCircle className="w-3 h-3" />
                                  )}
                                  <span>{result.passed ? 'PASS' : 'FAIL'}</span>
                                </span>
                              )}

                              <button
                                type="button"
                                disabled={simBusy}
                                onClick={() => void handleRunScenario(meta.id)}
                                className="px-2.5 py-1 rounded-lg bg-[#FFFDF9] hover:bg-[#FCECF4] text-[#16161D] border border-[#D8CEC0] text-[11px] font-semibold disabled:opacity-50"
                              >
                                Run
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
