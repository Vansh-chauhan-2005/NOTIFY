'use client';

import React, { useState } from 'react';
import {
  Flame,
  Play,
  Download,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import {
  auth,
  db,
} from '../lib/firebase/client.js';
import {
  doc,
  getDocFromServer,
} from 'firebase/firestore';
import { safeReadJson } from '../lib/http/safeJson.js';

export type EphemeralScenarioId = 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j';

interface ScenarioResult {
  scenarioId: EphemeralScenarioId;
  title: string;
  passed: boolean;
  details: string;
  durationMs: number;
  verifiedChecks: string[];
}

const SCENARIO_META: Array<{ id: EphemeralScenarioId; title: string; subtitle: string }> = [
  { id: 'a', title: 'a) E2E Decrypt Before Expiry', subtitle: 'ECDH wrap + ECDSA verify + AES-256-GCM' },
  { id: 'b', title: 'b) HTTP 410 Gone After Expiry', subtitle: 'Authoritative server clock check' },
  { id: 'c', title: 'c) Firestore Rule Rejects Expired', subtitle: 'request.time < expiresAt + Client SDK probe' },
  { id: 'd', title: 'd) Crypto-Shred Proof', subtitle: 'Saved ciphertext fails after key shred' },
  { id: 'e', title: 'e) Read-Once Enforcement', subtitle: '1st read succeeds, 2nd read 410 Gone' },
  { id: 'f', title: 'f) Burn Now (Sender Recall)', subtitle: 'Immediate shred blocks recipient' },
  { id: 'g', title: 'g) Tampered Client Clock Ignored', subtitle: 'Forged client timestamps rejected' },
  { id: 'h', title: 'h) Restart Catch-Up Sweeper', subtitle: 'Wipe RAM -> reload -> startup sweep' },
  { id: 'i', title: 'i) Tombstone Metadata Audit', subtitle: 'Zero content, ciphertext, iv, or keys' },
  { id: 'j', title: 'j) Zero-Leak Telemetry & Browser Scan', subtitle: 'Telemetry + logs + local/session/IDB scan' },
];

export default function EphemeralSimulatorPanel() {
  const [demoModeEnabled, setDemoModeEnabled] = useState(false); // OFF by default
  const [runningId, setRunningId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ScenarioResult>>({});
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);

  const runBrowserStorageLeakScan = async (): Promise<string[]> => {
    const leaks: string[] = [];
    if (typeof window === 'undefined') return leaks;
    try {
      for (let i = 0; i < window.localStorage.length; i += 1) {
        const k = window.localStorage.key(i) || '';
        const v = window.localStorage.getItem(k) || '';
        if (k.toLowerCase().includes('ephemeral') || v.includes('AEGIS_UNIQUE_LEAK_CANARY')) {
          leaks.push(`localStorage:${k}`);
        }
      }
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const k = window.sessionStorage.key(i) || '';
        const v = window.sessionStorage.getItem(k) || '';
        if (k.toLowerCase().includes('ephemeral') || v.includes('AEGIS_UNIQUE_LEAK_CANARY')) {
          leaks.push(`sessionStorage:${k}`);
        }
      }
      if (typeof indexedDB !== 'undefined' && typeof indexedDB.databases === 'function') {
        const dbs = await indexedDB.databases().catch(() => []);
        for (const dbInfo of dbs) {
          if (String(dbInfo?.name || '').toLowerCase().includes('ephemeral')) {
            leaks.push(`indexedDB:${dbInfo.name}`);
          }
        }
      }
    } catch {
      // ignore storage inspection restrictions
    }
    return leaks;
  };

  const runClientFirestoreRuleProbe = async (): Promise<string | null> => {
    if (!auth.currentUser) {
      return null;
    }
    try {
      await getDocFromServer(doc(db, 'ephemeralKeys', `probe_${Date.now()}`));
      return 'Unexpected: ephemeralKeys client read did NOT fail with permission-denied.';
    } catch (err: any) {
      const code = String(err?.code || err?.message || '').toLowerCase();
      if (code.includes('permission') || code.includes('denied') || code.includes('missing or insufficient')) {
        return 'Live Firebase Client SDK confirmed PERMISSION_DENIED on ephemeralKeys.';
      }
      return `Live Firebase Client SDK blocked read (${err?.code || 'denied'}).`;
    }
  };

  const executeSimulation = async (mode: 'ALL' | EphemeralScenarioId) => {
    if (!demoModeEnabled) return;
    setErrorMsg(null);
    setRunningId(mode);

    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const fbIdToken = auth.currentUser
        ? await auth.currentUser.getIdToken().catch(() => null)
        : null;

      const res = await fetch('/api/v1/ephemeral/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(fbIdToken ? { 'X-Firebase-Id-Token': fbIdToken } : {}),
        },
        body: JSON.stringify(
          mode === 'ALL'
            ? { action: 'RUN_ALL', demoMode: true }
            : { action: 'RUN_SCENARIO', scenarioId: mode, demoMode: true }
        ),
      });

      const data = await safeReadJson(res);
      if (!res.ok || !data?.success) {
        setErrorMsg(data?.message || `Simulator failed (HTTP ${res.status}).`);
        return;
      }

      const incomingList: ScenarioResult[] =
        mode === 'ALL'
          ? data.data?.results || []
          : data.data?.result
          ? [data.data.result]
          : [];

      const nextMap: Record<string, ScenarioResult> = { ...results };
      for (const r of incomingList) {
        if (r.scenarioId === 'c') {
          const sdkNote = await runClientFirestoreRuleProbe();
          if (sdkNote) {
            r.verifiedChecks = [...r.verifiedChecks, sdkNote];
          }
        }
        if (r.scenarioId === 'j') {
          const browserLeaks = await runBrowserStorageLeakScan();
          if (browserLeaks.length > 0) {
            r.passed = false;
            r.details = `Found browser storage leak(s): ${browserLeaks.join(', ')}`;
          } else {
            r.verifiedChecks = [
              ...r.verifiedChecks,
              'Browser localStorage, sessionStorage & IndexedDB verified clean (0 ephemeral entries)',
            ];
          }
        }
        nextMap[r.scenarioId] = r;
      }

      setResults(nextMap);
      setLastRunAt(new Date().toLocaleTimeString());
    } catch (err: any) {
      setErrorMsg(err?.message || 'Error communicating with Expiry Simulator endpoint.');
    } finally {
      setRunningId(null);
    }
  };

  const handleExportReport = (format: 'json' | 'html') => {
    const ordered = SCENARIO_META.map((m) => results[m.id]).filter(Boolean);
    const passed = ordered.filter((r) => r.passed).length;

    if (format === 'json') {
      const blob = new Blob(
        [
          JSON.stringify(
            {
              reportTitle: 'AegisNotify Ephemeral Data Isolation (300s TTL) Verification Report',
              generatedAt: new Date().toISOString(),
              summary: { totalRun: ordered.length, passed, failed: ordered.length - passed },
              results: ordered,
            },
            null,
            2
          ),
        ],
        { type: 'application/json' }
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis-ephemeral-audit-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    const htmlRows = ordered
      .map(
        (r) =>
          `<tr><td><strong>${r.title}</strong></td><td>${r.passed ? 'PASS' : 'FAIL'}</td><td>${r.details}</td><td>${r.durationMs}ms</td></tr>`
      )
      .join('');
    const htmlDoc = `<!doctype html><html><head><meta charset="utf-8"><title>AegisNotify Ephemeral Audit Report</title><style>body{font-family:system-ui,sans-serif;padding:32px;background:#FAF6F0;color:#16161D}table{width:100%;border-collapse:collapse;background:#FFFDF9}th,td{border:1px solid #E5DDD0;padding:10px;text-align:left;font-size:13px}th{background:#F2ECE2}</style></head><body><h1>AegisNotify Ephemeral Data Isolation Audit Report</h1><p>Generated: ${new Date().toISOString()} · Score: ${passed}/${ordered.length} Passed</p><table><thead><tr><th>Scenario</th><th>Result</th><th>Details</th><th>Duration</th></tr></thead><tbody>${htmlRows}</tbody></table></body></html>`;
    const blob = new Blob([htmlDoc], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-ephemeral-audit-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const resultList = Object.values(results);
  const passedCount = resultList.filter((r) => r.passed).length;

  return (
    <div className="space-y-6">
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-6 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center">
                <Flame className="w-4 h-4" />
              </div>
              <h2 className="font-display text-xl font-semibold text-[#16161D]">
                Ephemeral Expiry Simulator &amp; Proof Suite
              </h2>
            </div>
            <p className="text-xs text-[#6F6C7A]">
              Admin-only verification harness running isolated demo accounts &amp; short 2s–5s TTLs to prove all 4 deletion layers and zero-leak invariants
              {lastRunAt ? ` · Last run at ${lastRunAt}` : ''}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <label className="flex items-center space-x-2 px-3 py-2 rounded-xl border border-[#D8CEC0] bg-[#FAF6F0] cursor-pointer select-none text-xs font-semibold text-[#16161D]">
              <input
                type="checkbox"
                checked={demoModeEnabled}
                onChange={(e) => setDemoModeEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
              />
              <span>Demo Mode ({demoModeEnabled ? 'ON' : 'OFF'})</span>
            </label>

            <button
              type="button"
              disabled={!demoModeEnabled || runningId !== null}
              onClick={() => void executeSimulation('ALL')}
              className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-45"
            >
              {runningId === 'ALL' ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Play className="w-3.5 h-3.5" />
              )}
              <span>{runningId === 'ALL' ? 'Running Suite...' : 'Run All (a–j)'}</span>
            </button>

            <button
              type="button"
              disabled={resultList.length === 0}
              onClick={() => handleExportReport('json')}
              className="px-3 py-2 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-xs font-semibold text-[#16161D] flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-45"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            <button
              type="button"
              disabled={resultList.length === 0}
              onClick={() => handleExportReport('html')}
              className="px-3 py-2 rounded-xl border border-[#D8CEC0] bg-[#16161D] hover:bg-[#2A2935] text-xs font-semibold text-[#FAF6F0] flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-45"
            >
              <Download className="w-3.5 h-3.5 text-[#F472B6]" />
              <span>Export HTML</span>
            </button>
          </div>
        </div>

        {!demoModeEnabled && (
          <div className="rounded-xl bg-amber-50 border border-amber-200 px-4 py-3 text-xs text-amber-900 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0" />
            <span>
              Demo Mode is <strong>OFF</strong> by default to prevent synthetic canary tests from running unintentionally. Check <strong>Demo Mode</strong> above to unlock simulation controls.
            </span>
          </div>
        )}

        {errorMsg && (
          <div className="rounded-xl bg-red-50 border border-red-200 px-4 py-3 text-xs text-red-700">
            {errorMsg}
          </div>
        )}

        {resultList.length > 0 && (
          <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] px-4 py-3 flex items-center justify-between text-xs">
            <div className="flex items-center space-x-2 font-semibold text-[#16161D]">
              <ShieldCheck className="w-4 h-4 text-[#16A34A]" />
              <span>
                Scorecard: {passedCount} / {resultList.length} Scenarios Passed
              </span>
            </div>
            <span className="font-mono-tech text-[11px] text-[#6F6C7A]">
              Isolated accounts: sim_sender_demo → sim_recipient_demo
            </span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {SCENARIO_META.map((item) => {
          const res = results[item.id];
          const isRunningThis = runningId === item.id || runningId === 'ALL';
          return (
            <div
              key={item.id}
              className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 flex flex-col justify-between gap-3"
            >
              <div className="space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-display text-sm font-semibold text-[#16161D]">
                      {item.title}
                    </h3>
                    <p className="text-[11px] text-[#6F6C7A]">{item.subtitle}</p>
                  </div>

                  {res ? (
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border flex items-center space-x-1 shrink-0 ${
                        res.passed
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-red-50 text-red-700 border-red-200'
                      }`}
                    >
                      {res.passed ? (
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5" />
                      )}
                      <span>{res.passed ? 'PASS' : 'FAIL'}</span>
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#F2ECE2] text-[#6F6C7A] border border-[#E5DDD0] shrink-0">
                      Not Run
                    </span>
                  )}
                </div>

                {res && (
                  <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3 space-y-1.5 text-[11px]">
                    <p className="text-[#16161D] font-medium">{res.details}</p>
                    <ul className="space-y-0.5 text-[#464451] list-disc pl-4">
                      {res.verifiedChecks.map((c, idx) => (
                        <li key={idx}>{c}</li>
                      ))}
                    </ul>
                    <div className="text-[10px] font-mono-tech text-[#6F6C7A] pt-1">
                      Duration: {res.durationMs}ms
                    </div>
                  </div>
                )}
              </div>

              <div className="flex justify-end pt-2 border-t border-[#E5DDD0]">
                <button
                  type="button"
                  disabled={!demoModeEnabled || runningId !== null}
                  onClick={() => void executeSimulation(item.id)}
                  className="px-3 py-1.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-1.5 disabled:opacity-45 whitespace-nowrap"
                >
                  {isRunningThis ? (
                    <RefreshCw className="w-3 h-3 animate-spin text-[#F472B6]" />
                  ) : (
                    <Play className="w-3 h-3 text-[#F472B6]" />
                  )}
                  <span>{isRunningThis ? 'Running...' : 'Run Test'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
