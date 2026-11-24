'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Play,
  Download,
  Info,
  Lock,
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
} from 'recharts';
import type {
  KeyLogEntry,
  ProvenanceQuarantineRecord,
  ProvenanceStatus,
} from '../lib/provenance/types.js';
import type { ProvenanceSimulationReport } from '../lib/provenance/simulator.js';
import { safeReadJson } from '../lib/http/safeJson.js';

interface AdminProvenanceTabProps {
  token: string | null;
}

const CHART_STATUS_KEYS: ProvenanceStatus[] = [
  'VERIFIED',
  'UNSIGNED',
  'INVALID_SIGNATURE',
  'UNKNOWN_KEY',
  'REVOKED_KEY',
  'KEY_MISMATCH',
  'EXPIRED_ENVELOPE',
  'REPLAY',
  'CLOCK_SKEW',
  'BAD_CHAIN',
  'TARGET_MISMATCH',
];

export default function AdminProvenanceTab({ token }: AdminProvenanceTabProps) {
  const [loading, setLoading] = useState(true);
  const [countsByStatus, setCountsByStatus] = useState<Record<string, number>>({});
  const [totalVerified, setTotalVerified] = useState(0);
  const [totalRejected, setTotalRejected] = useState(0);
  const [quarantine, setQuarantine] = useState<ProvenanceQuarantineRecord[]>([]);
  const [keyLog, setKeyLog] = useState<KeyLogEntry[]>([]);
  const [headHash, setHeadHash] = useState('');
  const [serverKeyInfo, setServerKeyInfo] = useState<any>(null);
  const [chainVerifyResult, setChainVerifyResult] = useState<{
    ok: boolean;
    checkedCount: number;
    brokenAtIndex?: number;
    reason: string;
  } | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);

  // Attack Simulator (Demo Mode OFF by default)
  const [demoMode, setDemoMode] = useState(false);
  const [simRunning, setSimRunning] = useState(false);
  const [simReport, setSimReport] = useState<ProvenanceSimulationReport | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };
      const [qRes, kRes, sRes] = await Promise.all([
        fetch('/api/v1/provenance/quarantine?limit=50', { headers }),
        fetch('/api/v1/provenance/keylog?limit=100', { headers }),
        fetch('/api/v1/provenance/server-key', { headers }),
      ]);

      const [qData, kData, sData] = await Promise.all([
        safeReadJson(qRes),
        safeReadJson(kRes),
        safeReadJson(sRes),
      ]);

      if (qRes.ok && qData?.success) {
        setQuarantine(qData.data?.quarantine || []);
        setCountsByStatus(qData.data?.countsByStatus || {});
        setTotalVerified(qData.data?.totalVerified || 0);
        setTotalRejected(qData.data?.totalRejected || 0);
      }
      if (kRes.ok && kData?.success) {
        setKeyLog(kData.data?.entries || []);
        setHeadHash(kData.data?.headHash || '');
      }
      if (sRes.ok && sData?.success) {
        setServerKeyInfo(sData.data || null);
      }
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const res = await fetch('/api/v1/provenance/keylog?limit=200&verify=1', {
        headers: {
          Accept: 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      const data = await safeReadJson(res);
      if (res.ok && data?.success) {
        setKeyLog(data.data?.entries || []);
        setHeadHash(data.data?.headHash || '');
        setChainVerifyResult(data.data?.verification || null);
      }
    } finally {
      setVerifyingChain(false);
    }
  };

  const handleRunSimulator = async (scenarioIds?: string[]) => {
    if (!demoMode) return;
    setSimRunning(true);
    setSimError(null);
    try {
      const res = await fetch('/api/v1/provenance/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          demoMode: true,
          ...(scenarioIds ? { scenarios: scenarioIds } : {}),
        }),
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data?.success) {
        throw new Error(data?.message || `Simulation failed (HTTP ${res.status}).`);
      }
      setSimReport(data.data as ProvenanceSimulationReport);
      await loadData();
    } catch (err: any) {
      setSimError(err?.message || 'Provenance simulator error.');
    } finally {
      setSimRunning(false);
    }
  };

  const handleExportReportJson = () => {
    if (!simReport) return;
    const blob = new Blob([JSON.stringify(simReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-provenance-simulation-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportReportHtml = () => {
    if (!simReport) return;
    const rows = simReport.steps
      .map(
        (s) => `
      <tr>
        <td style="padding:8px;border-bottom:1px solid #333;">${s.label}</td>
        <td style="padding:8px;border-bottom:1px solid #333;font-weight:bold;color:${
          s.passed ? '#10b981' : '#ef4444'
        };">${s.passed ? 'PASS' : 'FAIL'}</td>
        <td style="padding:8px;border-bottom:1px solid #333;">${s.expectedStatus}</td>
        <td style="padding:8px;border-bottom:1px solid #333;">${s.actualStatus}</td>
        <td style="padding:8px;border-bottom:1px solid #333;">${s.details}</td>
      </tr>`
      )
      .join('');
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>AegisNotify Provenance Security Report</title></head>
<body style="font-family:system-ui,sans-serif;background:#16161D;color:#FAF6F0;padding:32px;">
<h1 style="color:#F472B6;">Zero-Trust Ed25519 Provenance Attack Simulation Report</h1>
<p>Executed at: ${simReport.ranAt} | Score: ${simReport.passedCount}/${simReport.totalCount} Passed</p>
<table style="width:100%;border-collapse:collapse;font-size:13px;">
<thead><tr style="text-align:left;border-bottom:2px solid #D9468F;"><th>Scenario</th><th>Result</th><th>Expected</th><th>Actual</th><th>Details</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-provenance-report-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const chartData = CHART_STATUS_KEYS.map((status) => ({
    status: status.replace('_', ' '),
    rawStatus: status,
    count: countsByStatus[status] || 0,
  }));

  return (
    <div className="space-y-6">
      {/* Top Server Key & Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30">
          <div className="text-[11px] uppercase tracking-wider text-[#FAF6F0]/60">
            Verified Envelopes
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{totalVerified}</div>
          <div className="text-[11px] text-[#FAF6F0]/55 mt-1">Ed25519 chain verified</div>
        </div>
        <div className="p-4 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30">
          <div className="text-[11px] uppercase tracking-wider text-[#FAF6F0]/60">
            Rejected / Quarantined
          </div>
          <div className="text-2xl font-bold text-[#F472B6] mt-1">{totalRejected}</div>
          <div className="text-[11px] text-[#FAF6F0]/55 mt-1">Zero-trust policy blocks</div>
        </div>
        <div className="p-4 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30">
          <div className="text-[11px] uppercase tracking-wider text-[#FAF6F0]/60">
            KeyLog Entries
          </div>
          <div className="text-2xl font-bold text-[#FAF6F0] mt-1">{keyLog.length}</div>
          <div className="text-[11px] font-mono text-[#FAF6F0]/55 truncate mt-1">
            Head: {headHash ? `${headHash.slice(0, 14)}...` : 'genesis'}
          </div>
        </div>
        <div className="p-4 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/30">
          <div className="text-[11px] uppercase tracking-wider text-[#FAF6F0]/60">
            Server Gateway Key
          </div>
          <div className="text-sm font-mono font-bold text-[#F472B6] mt-1.5">
            {serverKeyInfo?.kid || 'Loading...'}
          </div>
          <div className="text-[11px] text-[#FAF6F0]/55 mt-1">
            Source: {serverKeyInfo?.keySource || 'env'} · Ed25519
          </div>
        </div>
      </div>

      {/* Bar Chart: Verified vs Rejected by Reason */}
      <div className="p-5 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/25">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#F472B6]" />
            Verification Outcomes by Reason
          </h3>
          <button
            type="button"
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/10 hover:bg-white/20 text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 8, right: 16, left: 0, bottom: 28 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis
                dataKey="status"
                tick={{ fill: '#FAF6F0', fontSize: 10 }}
                angle={-25}
                textAnchor="end"
                interval={0}
              />
              <YAxis tick={{ fill: '#FAF6F0', fontSize: 11 }} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1C1C26',
                  borderColor: 'rgba(217,70,143,0.4)',
                  color: '#FAF6F0',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {chartData.map((entry) => (
                  <Cell
                    key={entry.rawStatus}
                    fill={
                      entry.rawStatus === 'VERIFIED'
                        ? '#10B981'
                        : entry.rawStatus === 'UNSIGNED'
                        ? '#F59E0B'
                        : '#D9468F'
                    }
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Key Transparency Log + Verify Chain */}
      <div className="p-5 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/25 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-[#F472B6]" />
              Hash-Chained Key Transparency Log (keyLog)
            </h3>
            <p className="text-[11px] text-[#FAF6F0]/60 mt-0.5">
              Every registration, rotation, and revocation is hash-linked and signed by the server Ed25519 key.
            </p>
          </div>
          <button
            type="button"
            disabled={verifyingChain}
            onClick={handleVerifyChain}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#D9468F] hover:bg-[#B52A70] text-white text-xs font-semibold transition disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            {verifyingChain ? 'Verifying Chain...' : 'Verify Chain'}
          </button>
        </div>

        {chainVerifyResult && (
          <div
            className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
              chainVerifyResult.ok
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200'
                : 'bg-red-500/15 border-red-500/40 text-red-200'
            }`}
          >
            {chainVerifyResult.ok ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            )}
            <span>
              <strong>{chainVerifyResult.ok ? 'PASS' : 'FAIL'}:</strong> {chainVerifyResult.reason}
            </span>
          </div>
        )}

        <div className="overflow-x-auto max-h-64 overflow-y-auto border border-white/10 rounded-lg">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-black/40 text-[#FAF6F0]/60 text-[10px] uppercase">
              <tr>
                <th className="p-2.5">#</th>
                <th className="p-2.5">Type</th>
                <th className="p-2.5">User ID</th>
                <th className="p-2.5">Key ID</th>
                <th className="p-2.5">Entry Hash</th>
                <th className="p-2.5">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {keyLog.map((e) => (
                <tr key={`${e.index}-${e.entryHash}`} className="hover:bg-white/5">
                  <td className="p-2.5 text-[#F472B6]">{e.index}</td>
                  <td className="p-2.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] ${
                        e.type === 'REVOKE'
                          ? 'bg-red-500/20 text-red-300'
                          : e.type === 'ROTATE'
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-emerald-500/20 text-emerald-300'
                      }`}
                    >
                      {e.type}
                    </span>
                  </td>
                  <td className="p-2.5 max-w-[140px] truncate">{e.userId}</td>
                  <td className="p-2.5 text-[#F472B6]">{e.kid}</td>
                  <td className="p-2.5 max-w-[160px] truncate text-[#FAF6F0]/70">{e.entryHash}</td>
                  <td className="p-2.5 text-[11px] text-[#FAF6F0]/60">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Provenance Quarantine List (Metadata Only) */}
      <div className="p-5 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/25 space-y-3">
        <h3 className="text-sm font-bold flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          Provenance Quarantine (Metadata-Only, Zero Plaintext)
        </h3>
        {quarantine.length === 0 ? (
          <div className="text-xs text-[#FAF6F0]/60">No quarantined provenance failures recorded yet.</div>
        ) : (
          <div className="overflow-x-auto max-h-60 overflow-y-auto border border-white/10 rounded-lg">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/40 text-[#FAF6F0]/60 text-[10px] uppercase font-mono">
                <tr>
                  <th className="p-2.5">Result</th>
                  <th className="p-2.5">Message ID</th>
                  <th className="p-2.5">Key ID</th>
                  <th className="p-2.5">Reason</th>
                  <th className="p-2.5">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {quarantine.map((q) => (
                  <tr key={q.id} className="hover:bg-white/5">
                    <td className="p-2.5 font-mono text-[11px] text-red-300 font-bold">
                      {q.verificationResult}
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-[#FAF6F0]/80">
                      {q.messageId || '—'}
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-[#F472B6]">{q.kid || 'none'}</td>
                    <td className="p-2.5 text-xs text-[#FAF6F0]/80 max-w-md truncate">{q.reason}</td>
                    <td className="p-2.5 font-mono text-[11px] text-[#FAF6F0]/55">
                      {new Date(q.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Provenance Attack Simulator (Demo Mode OFF by default) */}
      <div className="p-5 rounded-xl bg-[#16161D] text-[#FAF6F0] border border-[#D9468F]/35 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-[#F472B6]" />
              Zero-Trust Provenance Attack Simulator (Scenarios a–l)
            </h3>
            <p className="text-[11px] text-[#FAF6F0]/65 mt-0.5">
              Tests unsigned high-priority rejection, payload/metadata tampering, replay, rotation, revocation, TOFU pin mismatch, chain tampering, and KeyLog tamper detection on isolated demo accounts.
            </p>
          </div>
          <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-white/15 cursor-pointer text-xs font-semibold">
            <input
              type="checkbox"
              checked={demoMode}
              onChange={(e) => setDemoMode(e.target.checked)}
              className="accent-[#D9468F]"
            />
            <span>Demo Mode {demoMode ? 'ON' : 'OFF'}</span>
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            disabled={!demoMode || simRunning}
            onClick={() => handleRunSimulator()}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#D9468F] hover:bg-[#B52A70] text-white text-xs font-semibold transition disabled:opacity-40"
          >
            {demoMode ? <Play className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
            {simRunning ? 'Running 12 Scenarios...' : 'Run All 12 Scenarios (a–l)'}
          </button>

          {simReport && (
            <>
              <button
                type="button"
                onClick={handleExportReportJson}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-semibold"
              >
                <Download className="w-3.5 h-3.5" /> Export JSON
              </button>
              <button
                type="button"
                onClick={handleExportReportHtml}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white/10 hover:bg-white/20 text-xs font-semibold"
              >
                <Download className="w-3.5 h-3.5" /> Export HTML Report
              </button>
            </>
          )}
        </div>

        {simError && (
          <div className="p-3 rounded-lg bg-red-500/15 border border-red-500/40 text-xs text-red-200">
            {simError}
          </div>
        )}

        {simReport && (
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-black/40 border border-white/10 text-xs">
              <span className="font-bold">
                Scorecard:{' '}
                <span className={simReport.allPassed ? 'text-emerald-400' : 'text-amber-300'}>
                  {simReport.passedCount} / {simReport.totalCount} PASS
                </span>
              </span>
              <span className="font-mono text-[#FAF6F0]/60">
                {new Date(simReport.ranAt).toLocaleString()}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {simReport.steps.map((step) => (
                <div
                  key={step.id}
                  className={`p-3 rounded-lg border text-xs space-y-1 ${
                    step.passed
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-red-500/10 border-red-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-[#FAF6F0]">{step.label}</span>
                    <span
                      className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                        step.passed ? 'bg-emerald-500/25 text-emerald-300' : 'bg-red-500/25 text-red-300'
                      }`}
                    >
                      {step.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-[#FAF6F0]/75">
                    Expected: {step.expectedStatus} | Actual: {step.actualStatus}
                  </div>
                  <div className="text-[11px] text-[#FAF6F0]/65 line-clamp-2">{step.details}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Honest "How provenance works" Info Panel */}
      <div className="p-5 rounded-xl bg-[#FAF6F0] text-[#16161D] border border-[#16161D]/15 space-y-2">
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Info className="w-4 h-4 text-[#D9468F]" />
          How provenance works (Honest Security Boundaries)
        </h3>
        <ul className="list-disc pl-5 text-xs space-y-1.5 text-[#16161D]/80 leading-relaxed">
          <li>
            <strong>Authenticity & Integrity vs. Confidentiality:</strong> Ed25519 signatures prove
            who created an alert and that no fields (priority, recipient, ciphertext) changed.
            Ed25519 does <em>not</em> hide contents; confidentiality relies on ECDH + AES-256-GCM.
          </li>
          <li>
            <strong>Gateway-attested vs. End-to-End Signed:</strong> Webhook/external app alerts are
            verified by HMAC on the gateway and receive a yellow <em>Gateway-attested</em> server
            Ed25519 hop. Direct user messages signed in your browser carry a green{' '}
            <em>Verified (Ed25519)</em> origin signature whose private seed never leaves the device.
          </li>
          <li>
            <strong>Key Pinning & Transparency Log Limits:</strong> Clients pin each sender’s key in
            IndexedDB (TOFU) and verify any key change against a chained <code>ROTATE</code> entry
            in <code>keyLog</code>. Remaining trust assumption: if an attacker compromised BOTH the
            server signing key AND registry before a recipient’s very first contact, an attacker
            could equivocate unless users compare key fingerprints out-of-band.
          </li>
        </ul>
      </div>
    </div>
  );
}
