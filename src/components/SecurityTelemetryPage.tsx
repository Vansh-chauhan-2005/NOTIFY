'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Pause,
  Play,
  RefreshCw,
  Filter,
  SearchX,
  AlertCircle,
  GitBranch,
  Flame,
  Fingerprint,
  Sliders,
  Layers,
  Shield,
} from 'lucide-react';
import DeliveryPipelineTab from './DeliveryPipelineTab';
import EphemeralSimulatorPanel from './EphemeralSimulatorPanel';
import AdminProvenanceTab from './AdminProvenanceTab';
import AdminPriorityEngineTab from './AdminPriorityEngineTab';
import AdminDeduplicationTab from './AdminDeduplicationTab';
import AdminIngressGatewayTab from './AdminIngressGatewayTab';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  Cell,
} from 'recharts';

export type SecurityEventType =
  | 'OTP_SENT'
  | 'OTP_VERIFIED'
  | 'OTP_FAILED'
  | 'OTP_LOCKED'
  | 'SMS_OTP_SENT'
  | 'SMS_OTP_VERIFIED'
  | 'SMS_OTP_FAILED'
  | 'SMS_OTP_LOCKED'
  | 'SMS_RATE_LIMIT_HIT'
  | 'SMS_MOCK_USED'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'RATE_LIMIT_HIT'
  | 'MESSAGE_SENT'
  | 'MESSAGE_DECRYPT_FAILED'
  | 'SIGNATURE_INVALID'
  | 'CONSENT_GRANTED'
  | 'CONSENT_DENIED'
  | 'CONNECTION_CREATED'
  | 'CONNECTION_REMOVED'
  | 'INGEST_ACCEPTED'
  | 'INGEST_REJECTED'
  | 'DEVICE_SCAN_RUN'
  | 'DELIVERY_CREATED'
  | 'DELIVERY_ATTEMPT'
  | 'DELIVERY_ACKED'
  | 'DELIVERY_FALLBACK'
  | 'DELIVERY_FAILED'
  | 'CHANNEL_CIRCUIT_OPEN'
  | 'ACK_LINK_INVALID'
  | 'EPHEMERAL_CREATED'
  | 'EPHEMERAL_READ'
  | 'EPHEMERAL_BURNED'
  | 'EPHEMERAL_EXPIRED'
  | 'EPHEMERAL_ACCESS_DENIED_EXPIRED'
  | 'EPHEMERAL_SWEEP_RUN'
  | 'PROVENANCE_KEY_REGISTERED'
  | 'PROVENANCE_KEY_ROTATED'
  | 'PROVENANCE_KEY_REVOKED'
  | 'PROVENANCE_VERIFIED'
  | 'PROVENANCE_REJECTED'
  | 'PROVENANCE_REPLAY_BLOCKED'
  | 'KEY_PIN_MISMATCH'
  | 'KEYLOG_CHAIN_VERIFIED'
  | 'KEYLOG_CHAIN_BROKEN'
  | 'PRIORITY_SCORED'
  | 'PRIORITY_RULE_APPLIED'
  | 'PRIORITY_BUDGET_EXCEEDED'
  | 'PRIORITY_FEEDBACK'
  | 'PRIORITY_MODEL_UPDATED'
  | 'PRIORITY_MODEL_RESET'
  | 'PRIORITY_DRIFT_WARNING'
  | 'PRIORITY_ESCALATED'
  | 'DEDUP_MODEL_LOADED'
  | 'DEDUP_FALLBACK_USED'
  | 'DEDUP_MERGED'
  | 'DEDUP_SUGGESTED'
  | 'DEDUP_GUARD_BLOCKED'
  | 'DEDUP_UNGROUPED'
  | 'DEDUP_FEEDBACK'
  | 'DEDUP_THREAD_CAP_HIT'
  | 'GATEWAY_ALLOWED_SAMPLE'
  | 'GATEWAY_THROTTLED'
  | 'GATEWAY_BLOCKED'
  | 'GATEWAY_STRIKE'
  | 'GATEWAY_SHED'
  | 'GATEWAY_LOAD_LEVEL_CHANGED'
  | 'GATEWAY_OVERSIZE_REJECTED'
  | 'GATEWAY_MALFORMED_REJECTED'
  | 'GATEWAY_STORE_ERROR'
  | 'GATEWAY_MANUAL_BLOCK'
  | 'GATEWAY_POLICY_CHANGED'
  | 'SIGNUP_STARTED'
  | 'SIGNUP_COMPLETED'
  | 'RETURNING_DEVICE_DETECTED'
  | 'NEW_DEVICE_LOGIN';

export type SecuritySeverity = 'info' | 'warning' | 'critical';
export type SecurityResult = 'success' | 'blocked' | 'failed';
export type ThreatLevel = 'Low' | 'Medium' | 'High';

export interface SecurityTelemetryEvent {
  id: string;
  timestamp: string;
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  userId?: string;
  email?: string;
  ipAddress: string;
  userAgent: string;
  result: SecurityResult;
  details: string;
}

export interface SecurityStatsData {
  totalEvents: number;
  blockedAttacks: number;
  countsByType: Record<string, number>;
  countsBySeverity: Record<SecuritySeverity, number>;
  blockedVsAllowed: {
    blocked: number;
    allowed: number;
    failed: number;
  };
  failedLogins: {
    last1h: number;
    last24h: number;
  };
  activeThreatLevel: ThreatLevel;
  eventsPerMinute: Array<{
    minute: string;
    label: string;
    total: number;
    blocked: number;
    failed: number;
    success: number;
  }>;
  generatedAt: string;
}

interface SecurityTelemetryPageProps {
  user?: {
    id?: string;
    email?: string;
    phoneNumber?: string;
    role?: string;
  } | null;
}

const EVENT_TYPE_OPTIONS: SecurityEventType[] = [
  'OTP_SENT',
  'OTP_VERIFIED',
  'OTP_FAILED',
  'OTP_LOCKED',
  'SMS_OTP_SENT',
  'SMS_OTP_VERIFIED',
  'SMS_OTP_FAILED',
  'SMS_OTP_LOCKED',
  'SMS_RATE_LIMIT_HIT',
  'SMS_MOCK_USED',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  'RATE_LIMIT_HIT',
  'MESSAGE_SENT',
  'MESSAGE_DECRYPT_FAILED',
  'SIGNATURE_INVALID',
  'CONSENT_GRANTED',
  'CONSENT_DENIED',
  'CONNECTION_CREATED',
  'CONNECTION_REMOVED',
  'INGEST_ACCEPTED',
  'INGEST_REJECTED',
  'DEVICE_SCAN_RUN',
  'DELIVERY_CREATED',
  'DELIVERY_ATTEMPT',
  'DELIVERY_ACKED',
  'DELIVERY_FALLBACK',
  'DELIVERY_FAILED',
  'CHANNEL_CIRCUIT_OPEN',
  'ACK_LINK_INVALID',
  'EPHEMERAL_CREATED',
  'EPHEMERAL_READ',
  'EPHEMERAL_BURNED',
  'EPHEMERAL_EXPIRED',
  'EPHEMERAL_ACCESS_DENIED_EXPIRED',
  'EPHEMERAL_SWEEP_RUN',
  'PROVENANCE_KEY_REGISTERED',
  'PROVENANCE_KEY_ROTATED',
  'PROVENANCE_KEY_REVOKED',
  'PROVENANCE_VERIFIED',
  'PROVENANCE_REJECTED',
  'PROVENANCE_REPLAY_BLOCKED',
  'KEY_PIN_MISMATCH',
  'KEYLOG_CHAIN_VERIFIED',
  'KEYLOG_CHAIN_BROKEN',
  'PRIORITY_SCORED',
  'PRIORITY_RULE_APPLIED',
  'PRIORITY_BUDGET_EXCEEDED',
  'PRIORITY_FEEDBACK',
  'PRIORITY_MODEL_UPDATED',
  'PRIORITY_MODEL_RESET',
  'PRIORITY_DRIFT_WARNING',
  'PRIORITY_ESCALATED',
  'DEDUP_MODEL_LOADED',
  'DEDUP_FALLBACK_USED',
  'DEDUP_MERGED',
  'DEDUP_SUGGESTED',
  'DEDUP_GUARD_BLOCKED',
  'DEDUP_UNGROUPED',
  'DEDUP_FEEDBACK',
  'DEDUP_THREAD_CAP_HIT',
  'GATEWAY_ALLOWED_SAMPLE',
  'GATEWAY_THROTTLED',
  'GATEWAY_BLOCKED',
  'GATEWAY_STRIKE',
  'GATEWAY_SHED',
  'GATEWAY_LOAD_LEVEL_CHANGED',
  'GATEWAY_OVERSIZE_REJECTED',
  'GATEWAY_MALFORMED_REJECTED',
  'GATEWAY_STORE_ERROR',
  'GATEWAY_MANUAL_BLOCK',
  'GATEWAY_POLICY_CHANGED',
];

interface EphemeralStatsData {
  activeCount: number;
  expiredTotalCount: number;
  expiredLast1hCount: number;
  burnedCount: number;
  readOnceBurnedCount: number;
  averageLifetimeSeconds: number;
  aboutToExpire: Array<{
    id: string;
    senderId: string;
    recipientId: string;
    priority: string;
    status: string;
    readOnce: boolean;
    expiresAt: string;
    remainingSeconds: number;
  }>;
  configuredDefaultTtlSeconds: number;
  serverMaxTtlSeconds: number;
  sweeperActive: boolean;
  lastSweepAt: string | null;
}

async function safeFetchJson<T = any>(
  url: string,
  token: string | null
): Promise<{ ok: boolean; status: number; data: T | null; message: string }> {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    });

    const rawText = await res.text();
    if (!rawText) {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: `Server returned an empty response (HTTP ${res.status}).`,
      };
    }

    let parsed: any;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      const isHtml = rawText.trimStart().startsWith('<');
      return {
        ok: false,
        status: res.status,
        data: null,
        message: isHtml
          ? `Received HTML instead of JSON from telemetry endpoint (HTTP ${res.status}).`
          : `Received malformed non-JSON response (HTTP ${res.status}).`,
      };
    }

    if (!res.ok || !parsed?.success) {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: parsed?.message || `Telemetry request failed (HTTP ${res.status}).`,
      };
    }

    return {
      ok: true,
      status: res.status,
      data: parsed.data as T,
      message: parsed.message || 'OK',
    };
  } catch (err: any) {
    return {
      ok: false,
      status: 0,
      data: null,
      message: err?.message || 'Network error contacting security telemetry API.',
    };
  }
}

function getSeverityBadgeClass(severity: SecuritySeverity): string {
  switch (severity) {
    case 'info':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'warning':
      return 'bg-amber-50 text-amber-800 border-amber-200';
    case 'critical':
      return 'bg-red-50 text-red-700 border-red-200';
  }
}

function getResultTextClass(result: SecurityResult): string {
  switch (result) {
    case 'success':
      return 'text-emerald-700';
    case 'blocked':
      return 'text-red-700';
    case 'failed':
      return 'text-amber-800';
  }
}

function formatShortType(eventType: string): string {
  return eventType.replace(/_/g, ' ');
}

export default function SecurityTelemetryPage({ user }: SecurityTelemetryPageProps) {
  const isAdmin = String(user?.role || '').toUpperCase() === 'ADMIN';

  const [telemetrySubTab, setTelemetrySubTab] = useState<'audit' | 'delivery' | 'ephemeral' | 'provenance' | 'priority' | 'dedup' | 'gateway'>('audit');
  const [events, setEvents] = useState<SecurityTelemetryEvent[]>([]);
  const [stats, setStats] = useState<SecurityStatsData | null>(null);
  const [ephemeralStats, setEphemeralStats] = useState<EphemeralStatsData | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [limit, setLimit] = useState<number>(100);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const hasLoadedOnceRef = useRef(false);

  const fetchTelemetry = useCallback(
    async (manual = false) => {
      if (!isAdmin) {
        setIsLoading(false);
        return;
      }

      if (!hasLoadedOnceRef.current) {
        setIsLoading(true);
      } else if (manual) {
        setIsRefreshing(true);
      }

      const token =
        typeof window !== 'undefined' ? localStorage.getItem('aegis_auth_token') : null;

      const params = new URLSearchParams();
      params.set('limit', String(limit));
      if (severityFilter) params.set('severity', severityFilter);
      if (typeFilter) params.set('type', typeFilter);

      const [eventsRes, statsRes, ephRes] = await Promise.all([
        safeFetchJson<{ events: SecurityTelemetryEvent[]; totalMatching: number }>(
          `/api/v1/telemetry/events?${params.toString()}`,
          token
        ),
        safeFetchJson<SecurityStatsData>('/api/v1/telemetry/stats', token),
        safeFetchJson<{ stats: EphemeralStatsData }>('/api/v1/ephemeral/stats', token),
      ]);

      hasLoadedOnceRef.current = true;
      setIsLoading(false);
      setIsRefreshing(false);

      if (!eventsRes.ok || !statsRes.ok) {
        const msg = !eventsRes.ok ? eventsRes.message : statsRes.message;
        setErrorMsg(msg);
        return;
      }

      setErrorMsg(null);
      setEvents(eventsRes.data?.events || []);
      setStats(statsRes.data || null);
      if (ephRes.ok && ephRes.data?.stats) {
        setEphemeralStats(ephRes.data.stats);
      }
      setLastUpdated(new Date().toLocaleTimeString());
    },
    [isAdmin, limit, severityFilter, typeFilter]
  );

  useEffect(() => {
    void fetchTelemetry(false);
  }, [fetchTelemetry]);

  // Auto-refresh every 3 seconds unless paused
  useEffect(() => {
    if (!isAdmin || isPaused) return;
    const interval = setInterval(() => {
      void fetchTelemetry(false);
    }, 3000);
    return () => clearInterval(interval);
  }, [isAdmin, isPaused, fetchTelemetry]);

  if (!isAdmin) {
    return (
      <div className="glass-panel rounded-3xl border border-[#E5DDD0] p-10 text-center max-w-xl mx-auto my-8 space-y-4">
        <div className="w-12 h-12 rounded-2xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center mx-auto">
          <Lock className="w-6 h-6" />
        </div>
        <h2 className="font-display text-2xl font-semibold text-[#16161D]">
          Administrator Access Required
        </h2>
        <p className="text-sm text-[#464451] leading-relaxed">
          Security Telemetry is restricted to verified administrators. Your current account role (
          <span className="font-mono-tech font-semibold text-[#16161D]">
            {user?.role || 'USER'}
          </span>
          ) does not have permission to inspect security audit streams.
        </p>
      </div>
    );
  }

  const threatLevel: ThreatLevel = stats?.activeThreatLevel || 'Low';
  const threatBadgeStyle =
    threatLevel === 'High'
      ? 'bg-red-50 text-red-700 border-red-200'
      : threatLevel === 'Medium'
      ? 'bg-amber-50 text-amber-800 border-amber-200'
      : 'bg-emerald-50 text-emerald-700 border-emerald-200';

  const barChartData = EVENT_TYPE_OPTIONS.map((type) => ({
    name: formatShortType(type),
    eventType: type,
    count: stats?.countsByType?.[type] ?? 0,
  }));

  const lineChartData = stats?.eventsPerMinute || [];

  return (
    <div className="space-y-6">
      {/* Sub-Tab Bar inside Security Telemetry: Audit Stream vs Delivery Pipeline */}
      <div className="flex flex-wrap items-center gap-2 p-1.5 rounded-2xl bg-[#F2ECE2] border border-[#E5DDD0] w-fit">
        <button
          type="button"
          onClick={() => setTelemetrySubTab('audit')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all ${
            telemetrySubTab === 'audit'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Activity className={`w-3.5 h-3.5 ${telemetrySubTab === 'audit' ? 'text-[#F472B6]' : ''}`} />
          <span>Audit Stream</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('delivery')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'delivery'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <GitBranch className={`w-3.5 h-3.5 ${telemetrySubTab === 'delivery' ? 'text-[#F472B6]' : ''}`} />
          <span>Delivery Pipeline</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('ephemeral')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'ephemeral'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Flame className={`w-3.5 h-3.5 ${telemetrySubTab === 'ephemeral' ? 'text-[#F472B6]' : ''}`} />
          <span>Expiry Simulator</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('provenance')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'provenance'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Fingerprint className={`w-3.5 h-3.5 ${telemetrySubTab === 'provenance' ? 'text-[#F472B6]' : ''}`} />
          <span>Provenance</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('priority')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'priority'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Sliders className={`w-3.5 h-3.5 ${telemetrySubTab === 'priority' ? 'text-[#F472B6]' : ''}`} />
          <span>Priority Engine</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('dedup')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'dedup'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Layers className={`w-3.5 h-3.5 ${telemetrySubTab === 'dedup' ? 'text-[#F472B6]' : ''}`} />
          <span>Deduplication</span>
        </button>
        <button
          type="button"
          onClick={() => setTelemetrySubTab('gateway')}
          className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap ${
            telemetrySubTab === 'gateway'
              ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
              : 'text-[#464451] hover:text-[#16161D]'
          }`}
        >
          <Shield className={`w-3.5 h-3.5 ${telemetrySubTab === 'gateway' ? 'text-[#F472B6]' : ''}`} />
          <span>Ingress Gateway</span>
        </button>
      </div>

      {telemetrySubTab === 'delivery' ? (
        <DeliveryPipelineTab isAdmin={isAdmin} userId={user?.id} />
      ) : telemetrySubTab === 'ephemeral' ? (
        <EphemeralSimulatorPanel />
      ) : telemetrySubTab === 'provenance' ? (
        <AdminProvenanceTab
          token={typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null}
        />
      ) : telemetrySubTab === 'priority' ? (
        <AdminPriorityEngineTab
          token={typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null}
        />
      ) : telemetrySubTab === 'dedup' ? (
        <AdminDeduplicationTab
          token={typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null}
        />
      ) : telemetrySubTab === 'gateway' ? (
        <AdminIngressGatewayTab
          token={typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null}
        />
      ) : (
        <>
      {/* Page Title & Live Controls */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
              <Activity className="w-4 h-4" />
            </div>
            <h2 className="font-display text-2xl font-semibold text-[#16161D] tracking-tight">
              Security Telemetry
            </h2>
          </div>
          <p className="text-xs text-[#6F6C7A]">
            Admin-only audit telemetry for authentication, rate limiting, and payload integrity
            {lastUpdated ? ` · Last synced ${lastUpdated}` : ''}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div
            className={`px-3 py-1.5 rounded-full border text-xs font-medium flex items-center space-x-2 ${
              isPaused
                ? 'bg-[#F2ECE2] border-[#D8CEC0] text-[#464451]'
                : 'bg-[#FCECF4] border-[#F2C4DC] text-[#B52A70]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isPaused ? 'bg-[#6F6C7A]' : 'bg-[#D9468F] animate-pulse'
              }`}
            />
            <span className="whitespace-nowrap">
              {isPaused ? 'Live updates paused' : 'Auto-refresh · 3s'}
            </span>
          </div>

          <button
            type="button"
            onClick={() => setIsPaused((prev) => !prev)}
            className={`px-3.5 py-2 rounded-xl text-xs font-semibold border transition-all flex items-center space-x-1.5 whitespace-nowrap ${
              isPaused
                ? 'bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] border-[#D9468F]'
                : 'bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border-[#D8CEC0]'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Live Updates' : 'Pause Live Updates'}</span>
          </button>

          <button
            type="button"
            onClick={() => void fetchTelemetry(true)}
            disabled={isRefreshing}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center space-x-1.5 disabled:opacity-60 whitespace-nowrap"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Error State Banner */}
      {errorMsg && (
        <div className="rounded-2xl bg-red-50 border border-red-200 px-5 py-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="flex items-start space-x-3">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-red-800">
                Unable to load security telemetry
              </p>
              <p className="text-xs text-red-700 mt-0.5">{errorMsg}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void fetchTelemetry(true)}
            className="px-3.5 py-1.5 rounded-xl bg-red-700 hover:bg-red-800 text-white text-xs font-semibold self-start sm:self-center whitespace-nowrap"
          >
            Retry
          </button>
        </div>
      )}

      {/* Initial Loading State */}
      {isLoading ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[0, 1, 2, 3].map((idx) => (
              <div
                key={idx}
                className="glass-panel rounded-2xl p-5 border border-[#E5DDD0] space-y-3 animate-pulse"
              >
                <div className="h-3 w-24 bg-[#E5DDD0] rounded" />
                <div className="h-8 w-16 bg-[#D8CEC0] rounded" />
                <div className="h-2.5 w-32 bg-[#F2ECE2] rounded" />
              </div>
            ))}
          </div>
          <div className="glass-panel rounded-2xl p-12 border border-[#E5DDD0] flex flex-col items-center justify-center space-y-3 text-[#6F6C7A]">
            <RefreshCw className="w-6 h-6 text-[#D9468F] animate-spin" />
            <p className="text-xs font-medium">Loading security telemetry stream...</p>
          </div>
        </div>
      ) : (
        <>
          {/* 1. Top Row of Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 border border-[#E5DDD0]">
              <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
                <span>Total Events</span>
                <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                  <Activity className="w-4 h-4" />
                </div>
              </div>
              <div className="font-display text-3xl font-semibold text-[#16161D] tabular-nums">
                {stats?.totalEvents ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                {stats?.blockedVsAllowed.allowed ?? 0} allowed · {stats?.blockedVsAllowed.failed ?? 0} failed
              </div>
            </div>

            <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 border border-[#E5DDD0]">
              <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
                <span>Blocked Attacks</span>
                <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                  <ShieldAlert className="w-4 h-4" />
                </div>
              </div>
              <div className="font-display text-3xl font-semibold text-[#16161D] tabular-nums">
                {stats?.blockedAttacks ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                {stats?.countsBySeverity.critical ?? 0} critical severity
              </div>
            </div>

            <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 border border-[#E5DDD0]">
              <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
                <span>Failed Logins (24h)</span>
                <div className="w-7 h-7 rounded-lg bg-[#F2ECE2] text-[#16161D] flex items-center justify-center">
                  <AlertTriangle className="w-4 h-4" />
                </div>
              </div>
              <div className="font-display text-3xl font-semibold text-[#16161D] tabular-nums">
                {stats?.failedLogins.last24h ?? 0}
              </div>
              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">
                {stats?.failedLogins.last1h ?? 0} in last 1h
              </div>
            </div>

            <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 border border-[#E5DDD0]">
              <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
                <span>Current Threat Level</span>
                <div className="w-7 h-7 rounded-lg bg-[#F2ECE2] text-[#16161D] flex items-center justify-center">
                  <ShieldCheck className="w-4 h-4" />
                </div>
              </div>
              <div className="pt-1 flex items-center">
                <span
                  className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold border ${threatBadgeStyle}`}
                >
                  {threatLevel}
                </span>
              </div>
              <div className="text-[11px] text-[#6F6C7A]">
                Calculated from recent failures &amp; blocks
              </div>
            </div>
          </div>

          {/* Ephemeral Data Isolation Overview Card */}
          <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div className="flex items-center space-x-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                  <Flame className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-display text-base font-semibold text-[#16161D]">
                    Ephemeral Data Isolation ({ephemeralStats?.configuredDefaultTtlSeconds ?? 300}s TTL)
                  </h3>
                  <p className="text-[11px] text-[#6F6C7A]">
                    Isolated ephemeralMessages + crypto-shredded ephemeralKeys · 5s background sweeper ({ephemeralStats?.sweeperActive ? 'Active' : 'Standby'})
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setTelemetrySubTab('ephemeral')}
                className="px-3 py-1.5 rounded-xl bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] text-xs font-semibold whitespace-nowrap self-start sm:self-center"
              >
                Open Expiry Simulator
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Active Ephemeral</div>
                <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                  {ephemeralStats?.activeCount ?? 0}
                </div>
              </div>
              <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Expired (Last 1h)</div>
                <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                  {ephemeralStats?.expiredLast1hCount ?? 0}
                </div>
              </div>
              <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Manual Burns</div>
                <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                  {ephemeralStats?.burnedCount ?? 0}
                </div>
              </div>
              <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3">
                <div className="text-[11px] text-[#6F6C7A] font-medium">Avg Lifetime</div>
                <div className="font-display text-2xl font-semibold text-[#16161D] tabular-nums">
                  {ephemeralStats?.averageLifetimeSeconds ?? 0}s
                </div>
              </div>
            </div>

            {ephemeralStats?.aboutToExpire && ephemeralStats.aboutToExpire.length > 0 && (
              <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3 space-y-2">
                <div className="text-[11px] font-semibold text-[#464451]">
                  Live Expiring-Soon Metadata (Zero Plaintext / Keys Shown)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {ephemeralStats.aboutToExpire.map((item) => (
                    <div
                      key={item.id}
                      className="rounded-lg bg-[#FFFDF9] border border-[#E5DDD0] px-3 py-2 flex items-center justify-between text-[11px] font-mono-tech"
                    >
                      <span className="truncate text-[#16161D]">{item.id}</span>
                      <span className="text-[#B52A70] font-semibold whitespace-nowrap ml-2">
                        {item.remainingSeconds}s left
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* 2 & 3. Charts Row: Live Line Chart (Events/min) & Bar Chart (Events by Type) */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Live Line Chart */}
            <div className="lg:col-span-7 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-display text-base font-semibold text-[#16161D]">
                    Events per Minute
                  </h3>
                  <p className="text-[11px] text-[#6F6C7A]">
                    Rolling 15-minute live window (total vs. blocked)
                  </p>
                </div>
                <div className="flex items-center space-x-3 text-[11px] text-[#464451]">
                  <span className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#D9468F]" />
                    <span>Total</span>
                  </span>
                  <span className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#16161D]" />
                    <span>Blocked</span>
                  </span>
                </div>
              </div>

              <div className="h-64 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={lineChartData}
                    margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" />
                    <XAxis
                      dataKey="label"
                      tick={{ fontSize: 11, fill: '#6F6C7A' }}
                      stroke="#D8CEC0"
                    />
                    <YAxis
                      allowDecimals={false}
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
                    />
                    <Line
                      type="monotone"
                      dataKey="total"
                      name="Total Events"
                      stroke="#D9468F"
                      strokeWidth={2.5}
                      dot={{ r: 3, fill: '#D9468F' }}
                      activeDot={{ r: 5 }}
                      isAnimationActive={false}
                    />
                    <Line
                      type="monotone"
                      dataKey="blocked"
                      name="Blocked"
                      stroke="#16161D"
                      strokeWidth={2}
                      dot={{ r: 2.5, fill: '#16161D' }}
                      isAnimationActive={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Bar Chart: Events by Type */}
            <div className="lg:col-span-5 glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
              <div>
                <h3 className="font-display text-base font-semibold text-[#16161D]">
                  Events by Type
                </h3>
                <p className="text-[11px] text-[#6F6C7A]">
                  Distribution across authentication, OTP, and integrity checks
                </p>
              </div>

              <div className="h-64 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={barChartData}
                    layout="vertical"
                    margin={{ top: 4, right: 16, left: 20, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#E5DDD0" horizontal={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{ fontSize: 11, fill: '#6F6C7A' }}
                      stroke="#D8CEC0"
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      width={132}
                      tick={{ fontSize: 10, fill: '#464451' }}
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
                    />
                    <Bar dataKey="count" name="Events" radius={[0, 6, 6, 0]} isAnimationActive={false}>
                      {barChartData.map((entry, idx) => (
                        <Cell
                          key={entry.eventType}
                          fill={
                            entry.eventType === 'OTP_LOCKED' ||
                            entry.eventType === 'SMS_OTP_LOCKED' ||
                            entry.eventType === 'SIGNATURE_INVALID' ||
                            entry.eventType === 'INGEST_REJECTED' ||
                            entry.eventType === 'MESSAGE_DECRYPT_FAILED'
                              ? '#D9468F'
                              : idx % 2 === 0
                              ? '#16161D'
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

          {/* 4. Live Event Feed Table */}
          <div className="glass-panel rounded-2xl border border-[#E5DDD0] overflow-hidden">
            {/* Filters Toolbar */}
            <div className="p-5 border-b border-[#E5DDD0] flex flex-col md:flex-row md:items-center md:justify-between gap-3 bg-[#FFFDF9]">
              <div className="flex items-center space-x-2">
                <Filter className="w-4 h-4 text-[#D9468F]" />
                <h3 className="font-display text-base font-semibold text-[#16161D]">
                  Live Security Event Feed
                </h3>
                <span className="text-xs font-mono-tech text-[#6F6C7A]">
                  ({events.length} shown)
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-2.5">
                <select
                  aria-label="Filter by severity"
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                >
                  <option value="">All Severities</option>
                  <option value="info">Info (Green)</option>
                  <option value="warning">Warning (Yellow)</option>
                  <option value="critical">Critical (Red)</option>
                </select>

                <select
                  aria-label="Filter by event type"
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                >
                  <option value="">All Event Types</option>
                  {EVENT_TYPE_OPTIONS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>

                <select
                  aria-label="Event limit"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value) || 100)}
                  className="px-3 py-1.5 rounded-xl bg-[#FAF6F0] border border-[#D8CEC0] text-xs text-[#16161D] font-mono-tech focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                >
                  <option value={50}>Limit: 50</option>
                  <option value={100}>Limit: 100</option>
                  <option value={200}>Limit: 200</option>
                </select>
              </div>
            </div>

            {/* Table or Empty State */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-sans">
                <thead className="bg-[#F2ECE2] text-[#464451] text-[11px] font-semibold border-b border-[#E5DDD0]">
                  <tr>
                    <th className="py-3 px-4 whitespace-nowrap">Time</th>
                    <th className="py-3 px-4 whitespace-nowrap">Event Type</th>
                    <th className="py-3 px-4 whitespace-nowrap">Severity</th>
                    <th className="py-3 px-4 whitespace-nowrap">User / Email</th>
                    <th className="py-3 px-4 whitespace-nowrap">Result</th>
                    <th className="py-3 px-4 whitespace-nowrap">IP Address</th>
                    <th className="py-3 px-4">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E5DDD0]">
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-14 px-4 text-center">
                        <div className="flex flex-col items-center justify-center space-y-2 text-[#6F6C7A]">
                          <SearchX className="w-7 h-7 text-[#D9468F]/70" />
                          <p className="text-sm font-medium text-[#16161D]">
                            No security telemetry events match your filters
                          </p>
                          <p className="text-xs text-[#6F6C7A]">
                            Security events are logged automatically as authentication, OTP, and messaging activity occurs.
                          </p>
                          {(severityFilter || typeFilter) && (
                            <button
                              type="button"
                              onClick={() => {
                                setSeverityFilter('');
                                setTypeFilter('');
                              }}
                              className="mt-2 px-3.5 py-1.5 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-xs font-semibold hover:bg-[#F8DCEB]"
                            >
                              Clear Filters
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ) : (
                    events.map((ev) => (
                      <tr key={ev.id} className="hover:bg-[#FCECF4]/30 transition-colors">
                        <td className="py-3.5 px-4 text-[#464451] whitespace-nowrap font-mono-tech">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-3.5 px-4 font-mono-tech font-semibold text-[#16161D] whitespace-nowrap">
                          {ev.eventType}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold border capitalize ${getSeverityBadgeClass(
                              ev.severity
                            )}`}
                          >
                            {ev.severity}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-[#464451] font-mono-tech whitespace-nowrap">
                          {ev.email || ev.userId || '—'}
                        </td>
                        <td
                          className={`py-3.5 px-4 font-semibold capitalize whitespace-nowrap ${getResultTextClass(
                            ev.result
                          )}`}
                        >
                          {ev.result}
                        </td>
                        <td className="py-3.5 px-4 text-[#6F6C7A] font-mono-tech whitespace-nowrap">
                          <div title={ev.userAgent}>{ev.ipAddress}</div>
                        </td>
                        <td className="py-3.5 px-4 text-[#464451] max-w-md">
                          <p className="truncate" title={ev.details}>
                            {ev.details}
                          </p>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
        </>
      )}
    </div>
  );
}
