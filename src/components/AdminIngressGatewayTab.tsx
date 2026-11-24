'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  RefreshCw,
  Activity,
  Ban,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Play,
  Download,
  RotateCcw,
  Plus,
  Trash2,
  FlaskConical,
  Gauge,
  Server,
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
import type {
  GatewayAllowlistRecord,
  GatewayAuditEntry,
  GatewayBlockRecord,
  GatewaySimulationScenarioResult,
  GatewayStatsSnapshot,
  LoadLevel,
  PolicyValidationBounds,
  RouteGroup,
  RoutePolicy,
} from '../lib/gateway/types.js';

interface AdminIngressGatewayTabProps {
  token: string | null;
}

const SCENARIO_LIST: Array<{ code: string; label: string }> = [
  { code: 'a', label: 'a. Login Brute Force' },
  { code: 'b', label: 'b. OTP/SMS Spam' },
  { code: 'c', label: 'c. Single-User Flood' },
  { code: 'd', label: 'd. Shared IP Fairness' },
  { code: 'e', label: 'e. Spoofed XFF' },
  { code: 'f', label: 'f. Oversized Body 413' },
  { code: 'g', label: 'g. JSON Bomb & __proto__' },
  { code: 'h', label: 'h. Slow Request Deadline' },
  { code: 'i', label: 'i. Webhook Flood Pre-HMAC' },
  { code: 'j', label: 'j. 100k Key LRU Cap' },
  { code: 'k', label: 'k. Overload Shedding' },
  { code: 'l', label: 'l. Penalty Escalation' },
  { code: 'm', label: 'm. Store Fail Closed/Open' },
  { code: 'n', label: 'n. Allowlist & Audit' },
  { code: 'o', label: 'o. Login No Enumeration' },
  { code: 'p', label: 'p. Auth Login Brute Force' },
  { code: 'q', label: 'q. Signup IP Flood Spam' },
  { code: 'r', label: 'r. New Device & Locked Keys' },
];

function getLoadBadgeClasses(level: LoadLevel): string {
  switch (level) {
    case 'CRITICAL':
      return 'bg-red-50 text-red-800 border-red-200';
    case 'HIGH':
      return 'bg-amber-50 text-amber-900 border-amber-200';
    case 'ELEVATED':
      return 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC]';
    default:
      return 'bg-emerald-50 text-emerald-800 border-emerald-200';
  }
}

export default function AdminIngressGatewayTab({ token }: AdminIngressGatewayTabProps) {
  const [stats, setStats] = useState<GatewayStatsSnapshot | null>(null);
  const [blocks, setBlocks] = useState<GatewayBlockRecord[]>([]);
  const [allowlist, setAllowlist] = useState<GatewayAllowlistRecord[]>([]);
  const [auditLog, setAuditLog] = useState<GatewayAuditEntry[]>([]);
  const [policies, setPolicies] = useState<Record<RouteGroup, RoutePolicy> | null>(null);
  const [bounds, setBounds] = useState<PolicyValidationBounds | null>(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Policy editor state
  const [selectedGroup, setSelectedGroup] = useState<RouteGroup>('auth');
  const [editLimit, setEditLimit] = useState<number>(5);
  const [editBurst, setEditBurst] = useState<number>(5);
  const [editCost, setEditCost] = useState<number>(5);
  const [editMaxBodyKb, setEditMaxBodyKb] = useState<number>(16);
  const [policyBusy, setPolicyBusy] = useState(false);

  // Manual Block Form
  const [blockTarget, setBlockTarget] = useState('');
  const [blockScope, setBlockScope] = useState<'ip' | 'user' | 'connection' | 'manual'>('ip');
  const [blockMinutes, setBlockMinutes] = useState(60);
  const [blockReason, setBlockReason] = useState('Abuse mitigation block');
  const [blockBusy, setBlockBusy] = useState(false);

  // Allowlist Form
  const [allowTarget, setAllowTarget] = useState('');
  const [allowLabel, setAllowLabel] = useState('Demo Room / Instructor');
  const [allowMinutes, setAllowMinutes] = useState(60);
  const [allowBusy, setAllowBusy] = useState(false);

  // Attack Simulator (Demo Mode OFF by default)
  const [demoModeEnabled, setDemoModeEnabled] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [simResults, setSimResults] = useState<GatewaySimulationScenarioResult[]>([]);

  const resolveToken = useCallback(
    () =>
      token ||
      (typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null),
    [token]
  );

  const loadGatewayData = useCallback(
    async (manual = false) => {
      if (manual) setRefreshing(true);
      else if (!stats) setLoading(true);

      try {
        const authToken = resolveToken();
        const headers = {
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        };

        const [statsRes, blocksRes, allowRes, polRes] = await Promise.all([
          fetch('/api/v1/gateway/stats', { headers }),
          fetch('/api/v1/gateway/blocks', { headers }),
          fetch('/api/v1/gateway/allowlist', { headers }),
          fetch('/api/v1/gateway/policies', { headers }),
        ]);

        const [statsJson, blocksJson, allowJson, polJson] = await Promise.all([
          safeReadJson(statsRes),
          safeReadJson(blocksRes),
          safeReadJson(allowRes),
          safeReadJson(polRes),
        ]);

        if (!statsRes.ok || !statsJson?.success) {
          throw new Error(statsJson?.message || `Failed to load gateway stats (HTTP ${statsRes.status}).`);
        }

        setError(null);
        setStats(statsJson.data.stats);
        setAuditLog(statsJson.data.auditLog || []);
        if (blocksRes.ok && blocksJson?.success) {
          setBlocks(blocksJson.data.blocks || []);
        }
        if (allowRes.ok && allowJson?.success) {
          setAllowlist(allowJson.data.allowlist || []);
        }
        if (polRes.ok && polJson?.success && polJson.data?.policies) {
          setPolicies(polJson.data.policies);
          setBounds(polJson.data.bounds || null);
        }
      } catch (err: any) {
        setError(err?.message || 'Unable to load Ingress Gateway data.');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [resolveToken]
  );

  useEffect(() => {
    void loadGatewayData(false);
    const timer = setInterval(() => {
      void loadGatewayData(false);
    }, 3000);
    return () => clearInterval(timer);
  }, [loadGatewayData]);

  // Sync policy editor inputs when selectedGroup changes
  useEffect(() => {
    if (!policies || !policies[selectedGroup]) return;
    const p = policies[selectedGroup];
    setEditLimit(p.limit);
    setEditBurst(p.burst);
    setEditCost(p.cost);
    setEditMaxBodyKb(Math.max(1, Math.round(p.maxBodyBytes / 1024)));
  }, [selectedGroup, policies]);

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setPolicyBusy(true);
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/gateway/policies', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          group: selectedGroup,
          limit: editLimit,
          burst: editBurst,
          cost: editCost,
          maxBodyBytes: editMaxBodyKb * 1024,
        }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to update gateway policy.');
      }
      setPolicies(json.data.policies);
      setNotice(json.message);
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to save policy update.');
    } finally {
      setPolicyBusy(false);
    }
  };

  const handleResetPolicies = async () => {
    setPolicyBusy(true);
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/gateway/policies', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({ reset: true }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to reset gateway policies.');
      }
      setPolicies(json.data.policies);
      setNotice('Reset all route policies to default limits.');
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to reset policies.');
    } finally {
      setPolicyBusy(false);
    }
  };

  const handleAddBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!blockTarget.trim()) return;
    setBlockBusy(true);
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/gateway/blocks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({
          target: blockTarget.trim(),
          scope: blockScope,
          durationMinutes: blockMinutes,
          reason: blockReason,
        }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to create manual block.');
      }
      setBlockTarget('');
      setNotice(json.message);
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to create block.');
    } finally {
      setBlockBusy(false);
    }
  };

  const handleUnblock = async (id: string) => {
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch(`/api/v1/gateway/blocks/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: {
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to remove block.');
      }
      setNotice('Block removed and audited.');
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to remove block.');
    }
  };

  const handleAddAllowlist = async (allowlistMyIp: boolean) => {
    if (!allowlistMyIp && !allowTarget.trim()) return;
    setAllowBusy(true);
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/gateway/allowlist', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify(
          allowlistMyIp
            ? {
                allowlistMyIp: true,
                label: 'Demo Mode: Current Admin IP',
                durationMinutes: 60,
                multiplier: 3,
              }
            : {
                target: allowTarget.trim(),
                label: allowLabel.trim() || 'Trusted Client',
                durationMinutes: allowMinutes,
                multiplier: 3,
              }
        ),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to add allowlist entry.');
      }
      if (!allowlistMyIp) setAllowTarget('');
      setNotice(json.message);
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to add allowlist entry.');
    } finally {
      setAllowBusy(false);
    }
  };

  const handleRemoveAllowlist = async (id: string) => {
    setNotice(null);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch(`/api/v1/gateway/allowlist?id=${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: {
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Failed to remove allowlist entry.');
      }
      setNotice('Allowlist entry removed.');
      await loadGatewayData(true);
    } catch (err: any) {
      setError(err?.message || 'Unable to remove allowlist entry.');
    }
  };

  const handleRunSimulation = async (scenario: string) => {
    if (!demoModeEnabled) {
      setError('Turn ON the Demo Mode switch before running attack simulations.');
      return;
    }
    setSimBusy(true);
    setError(null);
    try {
      const authToken = resolveToken();
      const res = await fetch('/api/v1/gateway/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        },
        body: JSON.stringify({ demoMode: true, scenario }),
      });
      const json = await safeReadJson(res);
      if (!res.ok || !json?.success) {
        throw new Error(json?.message || 'Simulation request failed.');
      }
      setSimResults(json.data.results || []);
      setNotice(json.message);
    } catch (err: any) {
      setError(err?.message || 'Unable to run gateway simulation.');
    } finally {
      setSimBusy(false);
    }
  };

  const handleExportReport = (format: 'json' | 'html') => {
    const payload = {
      exportedAt: new Date().toISOString(),
      scorecard: {
        passed: simResults.filter((r) => r.passed).length,
        total: simResults.length,
      },
      results: simResults,
      gatewayStats: stats,
    };

    let blob: Blob;
    let filename: string;
    if (format === 'json') {
      blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      filename = `aegis-gateway-report-${Date.now()}.json`;
    } else {
      const rowsHtml = simResults
        .map(
          (r) =>
            `<tr><td>${r.code}</td><td>${r.title}</td><td>${r.expected}</td><td>${r.observed}</td><td><strong>${
              r.passed ? 'PASS' : 'FAIL'
            }</strong></td></tr>`
        )
        .join('');
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>AegisNotify Ingress Gateway Report</title><style>body{font-family:system-ui,sans-serif;padding:24px;color:#16161D}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:13px}th{background:#f5f0e8}</style></head><body><h1>AegisNotify Ingress Gateway Verification Report</h1><p>Generated: ${payload.exportedAt} · Score: ${payload.scorecard.passed}/${payload.scorecard.total} Passed</p><table><thead><tr><th>Code</th><th>Scenario</th><th>Expected</th><th>Observed</th><th>Result</th></tr></thead><tbody>${rowsHtml}</tbody></table></body></html>`;
      blob = new Blob([html], { type: 'text/html' });
      filename = `aegis-gateway-report-${Date.now()}.html`;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  if (loading && !stats) {
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[0, 1, 2, 3].map((idx) => (
            <div
              key={idx}
              className="glass-panel rounded-2xl p-5 border border-[#E5DDD0] space-y-2 animate-pulse"
            >
              <div className="h-3 w-24 bg-[#E5DDD0] rounded" />
              <div className="h-7 w-16 bg-[#D8CEC0] rounded" />
              <div className="h-2.5 w-28 bg-[#F2ECE2] rounded" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const hasTraffic = (stats?.totalRequests ?? 0) > 0;
  const routeBarData = stats
    ? Object.entries(stats.byRouteGroup).map(([group, vals]) => ({
        group,
        allowed: vals.allowed,
        rejected: vals.throttled + vals.blocked + vals.shed,
        total: vals.total,
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
              <Shield className="w-4 h-4" />
            </div>
            <h2 className="font-display text-2xl font-semibold text-[#16161D] tracking-tight">
              Ingress Gateway &amp; DoS Rate Limiter
            </h2>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Pre-body request hardening, identity-keyed token bucket &amp; sliding windows, load shedding, and penalty escalation
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <span
            className={`px-3 py-1.5 rounded-xl border text-xs font-semibold whitespace-nowrap ${getLoadBadgeClasses(
              stats?.loadLevel || 'NORMAL'
            )}`}
          >
            Load: {stats?.loadLevel || 'NORMAL'}
          </span>

          <button
            type="button"
            onClick={() => void loadGatewayData(true)}
            disabled={refreshing}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center space-x-1.5 disabled:opacity-60 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl bg-red-50 border border-red-200 px-4 py-3 text-xs text-red-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-600" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => void loadGatewayData(true)}
            className="px-3 py-1 rounded-lg bg-red-700 text-white font-semibold whitespace-nowrap shrink-0"
          >
            Retry
          </button>
        </div>
      )}

      {notice && (
        <div className="rounded-2xl bg-[#FCECF4] border border-[#F2C4DC] px-4 py-3 text-xs text-[#16161D] flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#B52A70] shrink-0" />
          <span>{notice}</span>
        </div>
      )}

      {/* Real-Time KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
            <span>Requests / sec</span>
            <Activity className="w-4 h-4 text-[#D9468F]" />
          </div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {hasTraffic ? `${stats!.requestsPerSecond}/s` : 'No data yet'}
          </div>
          <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
            {hasTraffic ? `${stats!.totalRequests} total handled` : 'Awaiting live traffic'}
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
            <span>Outcomes</span>
            <Shield className="w-4 h-4 text-[#D9468F]" />
          </div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {hasTraffic ? stats!.outcomes.allowed : 'No data yet'}
          </div>
          <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
            {hasTraffic
              ? `${stats!.outcomes.throttled} throttled · ${stats!.outcomes.blocked} blocked · ${stats!.outcomes.shed} shed`
              : '0 throttled · 0 blocked · 0 shed'}
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
            <span>Latency (p50 / p95)</span>
            <Gauge className="w-4 h-4 text-[#D9468F]" />
          </div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats && stats.latencyMs.sampleCount > 0 ? `${stats.latencyMs.p95}ms` : 'No data yet'}
          </div>
          <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
            {stats && stats.latencyMs.sampleCount > 0
              ? `p50=${stats.latencyMs.p50}ms · ${stats.latencyMs.sampleCount} samples`
              : 'Measured across gateway'}
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
            <span>Event Loop Delay</span>
            <Server className="w-4 h-4 text-[#D9468F]" />
          </div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats ? `${stats.eventLoopDelayMs.mean}ms` : 'No data yet'}
          </div>
          <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
            p95={stats?.eventLoopDelayMs.p95 ?? 0}ms · {stats?.inFlightRequests ?? 0} in-flight
          </div>
        </div>

        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 space-y-1.5 col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-xs font-semibold text-[#464451]">
            <span>Store &amp; Tracked Keys</span>
            <Info className="w-4 h-4 text-[#D9468F]" />
          </div>
          <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
            {stats?.store.trackedKeys ?? 0}
          </div>
          <div className="text-[11px] font-mono-tech text-[#6F6C7A]">
            {stats?.store.mode === 'upstash-redis'
              ? 'Upstash Redis (shared)'
              : `Memory LRU /${stats?.store.maxKeys ?? 50000} (per instance)`}
          </div>
        </div>
      </div>

      {/* Live Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-display text-base font-semibold text-[#16161D]">
                Gateway Traffic by Outcome (Per Minute)
              </h3>
              <p className="text-[11px] text-[#6F6C7A]">
                Real measured requests across rolling 15-minute window
              </p>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-[#464451]">
              <span>Allowed (Orchid)</span>
              <span>·</span>
              <span>Throttled / Blocked (Ink)</span>
            </div>
          </div>
          <div className="h-60 w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats?.byMinute || []} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#6F6C7A' }} stroke="#D8CEC0" />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#6F6C7A' }} stroke="#D8CEC0" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFDF9',
                    borderColor: '#E5DDD0',
                    borderRadius: '12px',
                    fontSize: '12px',
                    color: '#16161D',
                  }}
                />
                <Line type="monotone" dataKey="allowed" name="Allowed" stroke="#D9468F" strokeWidth={2.5} dot={{ r: 2.5 }} isAnimationActive={false} />
                <Line type="monotone" dataKey="throttled" name="Throttled (429)" stroke="#16161D" strokeWidth={2} dot={{ r: 2 }} isAnimationActive={false} />
                <Line type="monotone" dataKey="blocked" name="Blocked" stroke="#B52A70" strokeDasharray="4 2" strokeWidth={1.75} dot={false} isAnimationActive={false} />
                <Line type="monotone" dataKey="shed" name="Shed (503)" stroke="#D97706" strokeWidth={1.75} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-5 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
          <div>
            <h3 className="font-display text-base font-semibold text-[#16161D]">
              Traffic by Route Group
            </h3>
            <p className="text-[11px] text-[#6F6C7A]">
              Allowed vs. rejected across auth, ingest, messaging &amp; telemetry
            </p>
          </div>
          <div className="h-60 w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={routeBarData} layout="vertical" margin={{ top: 4, right: 16, left: 10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" horizontal={false} />
                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11, fill: '#6F6C7A' }} stroke="#D8CEC0" />
                <YAxis type="category" dataKey="group" width={88} tick={{ fontSize: 11, fill: '#464451' }} stroke="#D8CEC0" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFDF9',
                    borderColor: '#E5DDD0',
                    borderRadius: '12px',
                    fontSize: '12px',
                    color: '#16161D',
                  }}
                />
                <Bar dataKey="allowed" name="Allowed" stackId="a" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                  {routeBarData.map((entry) => (
                    <Cell key={entry.group} fill="#16161D" />
                  ))}
                </Bar>
                <Bar dataKey="rejected" name="Rejected" stackId="a" radius={[0, 4, 4, 0]} fill="#D9468F" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top Throttled Hashed Keys Table */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] overflow-hidden">
        <div className="p-5 border-b border-[#E5DDD0] flex items-center justify-between bg-[#FFFDF9]">
          <div>
            <h3 className="font-display text-base font-semibold text-[#16161D]">
              Top Throttled Keys (Hashed Only)
            </h3>
            <p className="text-[11px] text-[#6F6C7A]">
              Only first 8 hex characters of salted SHA-256 hashes are displayed; zero raw IPs stored
            </p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#F2ECE2] text-[#464451] text-[11px] font-semibold border-b border-[#E5DDD0]">
              <tr>
                <th className="py-2.5 px-4">Key Prefix (8-hex)</th>
                <th className="py-2.5 px-4">Throttled Hits</th>
                <th className="py-2.5 px-4">Active Strikes</th>
                <th className="py-2.5 px-4">Penalty Stage</th>
                <th className="py-2.5 px-4">Block Expiry</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5DDD0]">
              {!stats || stats.topThrottledKeys.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 px-4 text-center text-xs text-[#6F6C7A]">
                    No throttled keys recorded yet. Rate-limit violations and strike escalations appear here automatically.
                  </td>
                </tr>
              ) : (
                stats.topThrottledKeys.map((row) => (
                  <tr key={row.shortKey} className="hover:bg-[#FCECF4]/30">
                    <td className="py-2.5 px-4 font-mono-tech font-semibold text-[#16161D]">
                      {row.shortKey}
                    </td>
                    <td className="py-2.5 px-4 font-mono-tech tabular-nums">{row.throttledCount}</td>
                    <td className="py-2.5 px-4 font-mono-tech tabular-nums">{row.strikes}</td>
                    <td className="py-2.5 px-4 font-medium">{row.stage}</td>
                    <td className="py-2.5 px-4 font-mono-tech text-[#6F6C7A]">
                      {row.blockedUntil ? new Date(row.blockedUntil).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Policy Editor & Block / Allowlist Managers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Editable Route Policy Editor */}
        <form onSubmit={handleSavePolicy} className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="font-display text-base font-semibold text-[#16161D]">
                Route Policy Editor
              </h3>
              <p className="text-[11px] text-[#6F6C7A]">
                All changes validate against safe bounds and write an admin audit entry
              </p>
            </div>
            <button
              type="button"
              onClick={() => void handleResetPolicies()}
              disabled={policyBusy}
              className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-xs font-semibold text-[#16161D] flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset to defaults</span>
            </button>
          </div>

          {policies && (
            <>
              <div>
                <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                  Route Group
                </label>
                <select
                  value={selectedGroup}
                  onChange={(e) => setSelectedGroup(e.target.value as RouteGroup)}
                  className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D]"
                >
                  {Object.values(policies).map((p) => (
                    <option key={p.group} value={p.group}>
                      {p.group.toUpperCase()} — {p.description}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                    Rate Limit ({bounds?.minLimit ?? 3}–{bounds?.maxLimit ?? 2000})
                  </label>
                  <input
                    type="number"
                    min={bounds?.minLimit ?? 3}
                    max={bounds?.maxLimit ?? 2000}
                    value={editLimit}
                    onChange={(e) => setEditLimit(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] font-mono-tech"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                    Burst ({bounds?.minBurst ?? 1}–{bounds?.maxBurst ?? 500})
                  </label>
                  <input
                    type="number"
                    min={bounds?.minBurst ?? 1}
                    max={bounds?.maxBurst ?? 500}
                    value={editBurst}
                    onChange={(e) => setEditBurst(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] font-mono-tech"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                    Cost Weight ({bounds?.minCost ?? 1}–{bounds?.maxCost ?? 50})
                  </label>
                  <input
                    type="number"
                    min={bounds?.minCost ?? 1}
                    max={bounds?.maxCost ?? 50}
                    value={editCost}
                    onChange={(e) => setEditCost(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] font-mono-tech"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                    Max Body (KB, 1–512)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={512}
                    value={editMaxBodyKb}
                    onChange={(e) => setEditMaxBodyKb(Number(e.target.value))}
                    className="w-full px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] font-mono-tech"
                  />
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-[11px] font-mono-tech text-[#464451] space-y-1">
                <div>
                  Live Preview: {selectedGroup} · {policies[selectedGroup]?.algorithm} · {editLimit} req/{Math.round((policies[selectedGroup]?.windowMs || 60000) / 1000)}s · burst={editBurst} · cost={editCost} · cap={editMaxBodyKb}KB
                </div>
                <div>
                  Failure Mode: {policies[selectedGroup]?.failureMode} · Shedding: {policies[selectedGroup]?.shedAtLevel}
                </div>
              </div>

              <button
                type="submit"
                disabled={policyBusy}
                className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold disabled:opacity-50 whitespace-nowrap"
              >
                {policyBusy ? 'Saving...' : 'Save Policy'}
              </button>
            </>
          )}
        </form>

        {/* Manual Blocks & Allowlist Manager */}
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-5">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="font-display text-base font-semibold text-[#16161D]">
                Allowlist &amp; Block Controls
              </h3>
              <button
                type="button"
                disabled={allowBusy}
                onClick={() => void handleAddAllowlist(true)}
                className="px-3 py-1.5 rounded-xl bg-[#FCECF4] hover:bg-[#F8DCEB] border border-[#F2C4DC] text-[#B52A70] text-xs font-semibold whitespace-nowrap shrink-0"
              >
                Demo mode: allowlist my current IP for 1 hour
              </button>
            </div>

            {/* Add Allowlist Row */}
            <div className="flex flex-wrap gap-2">
              <input
                type="text"
                placeholder="IP, userId, or hashed key"
                value={allowTarget}
                onChange={(e) => setAllowTarget(e.target.value)}
                className="flex-1 min-w-[140px] px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs font-mono-tech"
              />
              <input
                type="text"
                placeholder="Label"
                value={allowLabel}
                onChange={(e) => setAllowLabel(e.target.value)}
                className="w-32 px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs"
              />
              <input
                type="number"
                min={1}
                max={10080}
                value={allowMinutes}
                onChange={(e) => setAllowMinutes(Number(e.target.value))}
                className="w-20 px-2.5 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs font-mono-tech"
                title="Duration in minutes"
              />
              <button
                type="button"
                disabled={allowBusy || !allowTarget.trim()}
                onClick={() => void handleAddAllowlist(false)}
                className="px-3 py-1.5 rounded-xl bg-[#16161D] text-[#FAF6F0] text-xs font-semibold flex items-center gap-1 disabled:opacity-40 whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Allowlist</span>
              </button>
            </div>

            {allowlist.length > 0 && (
              <div className="space-y-1.5 max-h-28 overflow-y-auto">
                {allowlist.map((a) => (
                  <div
                    key={a.id}
                    className="flex items-center justify-between px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs"
                  >
                    <div className="truncate">
                      <span className="font-mono-tech font-semibold text-[#16161D]">{a.shortKey}</span>
                      <span className="text-[#6F6C7A]"> · {a.label} ({a.multiplier}x) · exp {new Date(a.expiresAt).toLocaleTimeString()}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleRemoveAllowlist(a.id)}
                      className="text-red-700 hover:text-red-900 ml-2 shrink-0"
                      title="Remove allowlist"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <hr className="border-[#E5DDD0]" />

          {/* Manual Block Form + Active Block List */}
          <form onSubmit={handleAddBlock} className="space-y-2.5">
            <div className="text-xs font-semibold text-[#464451]">Manual Block</div>
            <div className="flex flex-wrap gap-2">
              <select
                value={blockScope}
                onChange={(e) => setBlockScope(e.target.value as any)}
                className="px-2.5 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs"
              >
                <option value="ip">IP</option>
                <option value="user">User ID</option>
                <option value="connection">Connection</option>
                <option value="manual">Key</option>
              </select>
              <input
                type="text"
                placeholder="Target IP or ID (hashed on save)"
                value={blockTarget}
                onChange={(e) => setBlockTarget(e.target.value)}
                className="flex-1 min-w-[140px] px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs font-mono-tech"
              />
              <input
                type="number"
                min={1}
                max={1440}
                value={blockMinutes}
                onChange={(e) => setBlockMinutes(Number(e.target.value))}
                className="w-20 px-2.5 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs font-mono-tech"
                title="Minutes (max 1440)"
              />
              <button
                type="submit"
                disabled={blockBusy || !blockTarget.trim()}
                className="px-3 py-1.5 rounded-xl bg-red-700 hover:bg-red-800 text-white text-xs font-semibold flex items-center gap-1 disabled:opacity-40 whitespace-nowrap"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>Block</span>
              </button>
            </div>
            <input
              type="text"
              placeholder="Audit reason"
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
              className="w-full px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs"
            />
          </form>

          <div className="space-y-1.5 max-h-36 overflow-y-auto">
            {blocks.length === 0 ? (
              <div className="text-xs text-[#6F6C7A] py-2">No active manual or penalty-box blocks.</div>
            ) : (
              blocks.map((b) => (
                <div
                  key={b.id}
                  className="flex items-center justify-between px-3 py-2 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs"
                >
                  <div className="truncate">
                    <span className="font-mono-tech font-semibold text-[#16161D]">{b.shortKey}</span>
                    <span className="text-[#6F6C7A]"> · {b.scope} · {b.reason} · exp {new Date(b.expiresAt).toLocaleTimeString()}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleUnblock(b.id)}
                    className="px-2.5 py-1 rounded-lg bg-[#FFFDF9] hover:bg-[#FCECF4] border border-[#D8CEC0] text-[#B52A70] font-semibold ml-2 whitespace-nowrap shrink-0"
                  >
                    Unblock
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* How the Gateway Works (Honesty Panel) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-2.5">
        <div className="flex items-center gap-2 text-sm font-semibold text-[#16161D]">
          <Info className="w-4 h-4 text-[#D9468F]" />
          <span>How the gateway works</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs text-[#464451] leading-relaxed">
          <ul className="list-disc pl-4 space-y-1">
            <li>
              <strong>App-Layer vs Network DDoS:</strong> This gateway protects against application-layer abuse (login/OTP brute force, SMS spam, API floods, webhook floods, JSON bombs, slow requests). It cannot stop a volumetric network-level DDoS, which must be mitigated by your hosting provider or CDN (e.g. Cloudflare / Cloud Armor).
            </li>
            <li>
              <strong>Trusted Proxy &amp; IP Privacy:</strong> Client IPs come only from the trusted hop offset in <code className="font-mono-tech">X-Forwarded-For</code> (<code className="font-mono-tech">TRUST_PROXY_HOPS</code>), normalize IPv6 to <code className="font-mono-tech">/64</code> prefixes, and are salted SHA-256 hashed (<code className="font-mono-tech">GATEWAY_IP_SALT</code>) before display or logging.
            </li>
          </ul>
          <ul className="list-disc pl-4 space-y-1">
            <li>
              <strong>Per-Instance vs Shared Store:</strong> By default, the bounded 50,000-key LRU store counts strictly per Node/Express server instance. Setting <code className="font-mono-tech">UPSTASH_REDIS_REST_URL</code> and <code className="font-mono-tech">UPSTASH_REDIS_REST_TOKEN</code> shares counters across instances.
            </li>
            <li>
              <strong>Failure Modes &amp; Shedding:</strong> Auth routes fail CLOSED on store failure; static/general routes fail OPEN with alerts. Under load, priority-aware shedding drops low-value stats before ACK links, OTP verify, or authenticated CRITICAL notifications.
            </li>
          </ul>
        </div>
      </div>

      {/* Admin Attack Simulator (Scenarios a-n, Demo Mode OFF by default) */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#E5DDD0] pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#16161D]">
              <FlaskConical className="w-4 h-4 text-[#D9468F]" />
              <span>Ingress Gateway &amp; Auth Attack Simulator (Scenarios a–r)</span>
            </div>
            <p className="text-xs text-[#6F6C7A]">
              Runs against isolated virtual clocks and memory stores inside the server — never targets external hosts or affects real users.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <label className="flex items-center gap-2 text-xs font-semibold text-[#16161D] cursor-pointer px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0]">
              <input
                type="checkbox"
                checked={demoModeEnabled}
                onChange={(e) => setDemoModeEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-[#D8CEC0] accent-[#D9468F]"
              />
              <span>Demo Mode ({demoModeEnabled ? 'ON' : 'OFF'})</span>
            </label>

            <button
              type="button"
              onClick={() => void handleRunSimulation('full')}
              disabled={simBusy || !demoModeEnabled}
              className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] disabled:opacity-50 flex items-center gap-1.5 whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{simBusy ? 'Running...' : 'Run All (a–r)'}</span>
            </button>

            {simResults.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={() => handleExportReport('json')}
                  className="px-3 py-2 rounded-xl text-xs font-semibold bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-[#16161D] flex items-center gap-1 whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>JSON</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleExportReport('html')}
                  className="px-3 py-2 rounded-xl text-xs font-semibold bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-[#16161D] flex items-center gap-1 whitespace-nowrap"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>HTML Report</span>
                </button>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {SCENARIO_LIST.map((sc) => (
            <button
              key={sc.code}
              type="button"
              onClick={() => void handleRunSimulation(sc.code)}
              disabled={simBusy || !demoModeEnabled}
              className="px-2.5 py-1.5 rounded-xl text-[11px] font-medium bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] disabled:opacity-50 whitespace-nowrap"
            >
              {sc.label}
            </button>
          ))}
        </div>

        {simResults.length > 0 && (
          <div className="space-y-3">
            <div className="text-xs font-semibold text-[#16161D]">
              Scorecard: {simResults.filter((r) => r.passed).length}/{simResults.length} defenses passed
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
                    <span className="inline-flex items-center gap-1 font-mono-tech text-[11px]">
                      {r.passed ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-[#16A34A]" />
                          <span>PASS</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-3.5 h-3.5 text-red-600" />
                          <span>FAIL</span>
                        </>
                      )}
                    </span>
                  </div>
                  <div className="text-[11px] opacity-90">Expected: {r.expected}</div>
                  <div className="text-[11px] font-mono-tech">Observed: {r.observed}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent Admin Audit Log */}
        {auditLog.length > 0 && (
          <div className="pt-2 space-y-1.5">
            <div className="text-xs font-semibold text-[#464451]">Recent Admin Gateway Audit Trail</div>
            <div className="max-h-32 overflow-y-auto space-y-1">
              {auditLog.slice(0, 8).map((entry) => (
                <div
                  key={entry.id}
                  className="text-[11px] font-mono-tech text-[#464451] px-2.5 py-1 rounded-lg bg-[#FAF6F0] border border-[#E5DDD0]"
                >
                  [{new Date(entry.timestamp).toLocaleTimeString()}] {entry.action} ({entry.adminId}): {entry.details}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
