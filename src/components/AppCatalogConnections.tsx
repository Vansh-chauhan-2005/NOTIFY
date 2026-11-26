'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Search,
  Scan,
  Info,
  ExternalLink,
  Plug,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Trash2,
  Send,
  ShieldCheck,
  KeyRound,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  X,
  RefreshCw,
} from 'lucide-react';
import {
  APP_CATALOG,
  APP_CATEGORIES,
  AppCategory,
  CatalogApp,
} from '../data/appCatalog';
import {
  AppCatalogState,
  AppDetectionStatus,
  DeviceScanResult,
  clearLocalCatalogStates,
  isRelatedAppsApiSupported,
  loadLocalCatalogStates,
  resolveHonestAppStatus,
  saveLocalCatalogStates,
  scanCatalogOnDevice,
  triggerSafeSchemeOrWebLink,
} from '../lib/integrations/appDetection';
import {
  UserPrivacyConsentState,
  loadAppCatalogStatesFromFirestore,
  saveAppCatalogStateInFirestore,
  saveOnboardingAndConsent,
} from '../lib/firebase/client';
import AppIconBadge from './AppIconBadge';

export interface PublicDirectConnection {
  id: string;
  appId: string;
  appName: string;
  category: string;
  connectionType: CatalogApp['connectionType'];
  label: string;
  secretMask: string;
  hasBotToken: boolean;
  botTokenMask?: string;
  externalWebhookUrl?: string;
  telegramChatId?: string;
  webhookRegistered?: boolean;
  webhookNote?: string;
  enabled: boolean;
  receivedCount: number;
  lastReceivedAt?: string;
  createdAt: string;
  ingestPath: string;
}

interface AppCatalogConnectionsProps {
  userId: string;
  consentState: UserPrivacyConsentState | null;
  onConsentUpdated: (state: UserPrivacyConsentState) => void;
  onSimulatedNotification?: (app: CatalogApp, title: string, message: string) => Promise<void> | void;
  onIngestSuccess?: () => void;
  externalConnectionsVersion?: number;
}

async function safeJsonFetch<T = any>(
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
    const raw = await res.text();
    if (!raw) {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: `Empty response (HTTP ${res.status}).`,
      };
    }
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: raw.trimStart().startsWith('<')
          ? `Server returned HTML instead of JSON (HTTP ${res.status}).`
          : `Malformed JSON response (HTTP ${res.status}).`,
      };
    }
    if (!res.ok || !parsed?.success) {
      return {
        ok: false,
        status: res.status,
        data: null,
        message: parsed?.message || `Request failed (HTTP ${res.status}).`,
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
      message: err?.message || 'Network error.',
    };
  }
}

async function signPayloadHmacSha256Hex(
  secret: string,
  timestampRaw: string,
  rawBody: string
): Promise<string> {
  const enc = new TextEncoder();
  const key = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await window.crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(`${timestampRaw}.${rawBody}`)
  );
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function statusBadgeStyle(status: AppDetectionStatus): string {
  switch (status) {
    case 'Detected':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'Marked by you':
      return 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC]';
    case 'Launchable':
      return 'bg-[#F2ECE2] text-[#464451] border-[#D8CEC0]';
    case 'Unknown':
      return 'bg-[#FAF6F0] text-[#6F6C7A] border-[#E5DDD0]';
  }
}

export default function AppCatalogConnections({
  userId,
  consentState,
  onConsentUpdated,
  onSimulatedNotification,
  onIngestSuccess,
  externalConnectionsVersion = 0,
}: AppCatalogConnectionsProps) {
  const consentGranted = Boolean(consentState?.consentGranted && !consentState?.revoked);

  const [selectedCategory, setSelectedCategory] = useState<'All' | AppCategory>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | AppDetectionStatus>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [showHowItWorks, setShowHowItWorks] = useState(false);

  const [catalogStates, setCatalogStates] = useState<Record<string, AppCatalogState>>({});
  const [pendingDeepLinkAppId, setPendingDeepLinkAppId] = useState<string | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<DeviceScanResult | null>(null);

  const [connections, setConnections] = useState<PublicDirectConnection[]>([]);
  const [connectionsLoading, setConnectionsLoading] = useState(true);
  const [connectionsError, setConnectionsError] = useState<string | null>(null);

  // Connect Drawer state
  const [activeApp, setActiveApp] = useState<CatalogApp | null>(null);
  const [connLabel, setConnLabel] = useState('');
  const [botTokenInput, setBotTokenInput] = useState('');
  const [telegramChatIdInput, setTelegramChatIdInput] = useState('');
  const [externalWebhookInput, setExternalWebhookInput] = useState('');
  const [creatingConn, setCreatingConn] = useState(false);
  const [drawerError, setDrawerError] = useState<string | null>(null);
  const [drawerNotice, setDrawerNotice] = useState<string | null>(null);

  // One-time revealed secret held strictly in ephemeral component state (cleared on close)
  const [createdSecretOnce, setCreatedSecretOnce] = useState<{
    connectionId: string;
    secret: string;
    ingestUrl: string;
  } | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [testingConnId, setTestingConnId] = useState<string | null>(null);
  const [sendingSimulated, setSendingSimulated] = useState(false);
  const [grantingConsent, setGrantingConsent] = useState(false);

  const loadConnections = useCallback(async () => {
    setConnectionsLoading(true);
    setConnectionsError(null);
    const res = await safeJsonFetch<{ connections: PublicDirectConnection[] }>(
      '/api/v1/connections'
    );
    setConnectionsLoading(false);
    if (!res.ok) {
      setConnectionsError(res.message);
      return;
    }
    setConnections(res.data?.connections || []);
  }, []);

  useEffect(() => {
    void loadConnections();
  }, [loadConnections, externalConnectionsVersion]);

  // Load saved catalog states (local + Firestore)
  useEffect(() => {
    let active = true;
    const local = loadLocalCatalogStates(userId);
    setCatalogStates(local);

    void (async () => {
      try {
        const fsStates = await loadAppCatalogStatesFromFirestore(userId);
        if (!active || Object.keys(fsStates).length === 0) return;
        const merged: Record<string, AppCatalogState> = { ...local };
        for (const [appId, rec] of Object.entries(fsStates)) {
          merged[appId] = {
            appId: rec.appId,
            markedByUser: rec.markedByUser,
            deepLinkConfirmed: rec.deepLinkConfirmed,
            relatedAppDetected: rec.relatedAppDetected,
            updatedAt: rec.updatedAt,
          };
        }
        setCatalogStates(merged);
        saveLocalCatalogStates(userId, merged);
      } catch {
        // Non-fatal if user isn't Firebase-authenticated (e.g. admin session)
      }
    })();

    return () => {
      active = false;
    };
  }, [userId, externalConnectionsVersion]);

  const persistSingleAppState = async (app: CatalogApp, nextState: AppCatalogState) => {
    const updatedMap = {
      ...catalogStates,
      [app.id]: nextState,
    };
    setCatalogStates(updatedMap);
    saveLocalCatalogStates(userId, updatedMap);
    try {
      await saveAppCatalogStateInFirestore(userId, {
        appId: app.id,
        status: resolveHonestAppStatus(app, nextState),
        markedByUser: nextState.markedByUser,
        deepLinkConfirmed: nextState.deepLinkConfirmed,
        relatedAppDetected: nextState.relatedAppDetected,
      });
    } catch {
      // Local state still saved cleanly
    }
  };

  const handleToggleUseApp = (app: CatalogApp) => {
    if (!consentGranted) return;
    const prev = catalogStates[app.id];
    const nextMarked = !(prev?.markedByUser ?? false);
    const nextState: AppCatalogState = {
      appId: app.id,
      markedByUser: nextMarked,
      deepLinkConfirmed: prev?.deepLinkConfirmed || 'untested',
      relatedAppDetected: prev?.relatedAppDetected || false,
      updatedAt: new Date().toISOString(),
    };
    void persistSingleAppState(app, nextState);
  };

  const handleTestDeepLink = (app: CatalogApp) => {
    if (!app.deepLink) return;
    triggerSafeSchemeOrWebLink(app.deepLink);
    setPendingDeepLinkAppId(app.id);
  };

  const handleDeepLinkConfirmation = (app: CatalogApp, opened: boolean) => {
    setPendingDeepLinkAppId(null);
    const prev = catalogStates[app.id];
    const nextState: AppCatalogState = {
      appId: app.id,
      markedByUser: opened ? true : prev?.markedByUser || false,
      deepLinkConfirmed: opened ? 'yes' : 'no',
      relatedAppDetected: prev?.relatedAppDetected || false,
      updatedAt: new Date().toISOString(),
    };
    void persistSingleAppState(app, nextState);
  };

  const handleScanDevice = async () => {
    setIsScanning(true);
    const result = await scanCatalogOnDevice();
    setScanResult(result);

    const nextMap = { ...catalogStates };
    for (const app of APP_CATALOG) {
      const detected = result.detectedIds.includes(app.id);
      const prev = nextMap[app.id];
      if (detected || prev?.relatedAppDetected) {
        nextMap[app.id] = {
          appId: app.id,
          markedByUser: prev?.markedByUser || false,
          deepLinkConfirmed: prev?.deepLinkConfirmed || 'untested',
          relatedAppDetected: detected,
          updatedAt: result.scannedAt,
        };
      }
    }
    setCatalogStates(nextMap);
    saveLocalCatalogStates(userId, nextMap);

    // Log honest device scan telemetry
    void safeJsonFetch('/api/v1/telemetry/client-event', {
      method: 'POST',
      body: JSON.stringify({
        eventType: 'DEVICE_SCAN_RUN',
        result: 'success',
        details: result.apiSupported
          ? `Device scan checked getInstalledRelatedApps(): ${result.detectedIds.length} catalog match(es).`
          : 'Device scan checked browser support: getInstalledRelatedApps() unavailable.',
      }),
    });

    setIsScanning(false);
  };

  const handleQuickGrantConsent = async () => {
    setGrantingConsent(true);
    try {
      const updated = await saveOnboardingAndConsent(userId, {
        allowCatalogAndConnections: true,
        allowEncryptedConnectionStorage: true,
        browserNotificationsChoice: consentState?.browserNotificationsChoice || 'default',
        revoked: false,
      });
      onConsentUpdated(updated);
      void safeJsonFetch('/api/v1/telemetry/client-event', {
        method: 'POST',
        body: JSON.stringify({
          eventType: 'CONSENT_GRANTED',
          result: 'success',
          details: 'User granted App Catalog and encrypted connection storage consent.',
        }),
      });
    } finally {
      setGrantingConsent(false);
    }
  };

  const openDrawerForApp = (app: CatalogApp) => {
    setActiveApp(app);
    setConnLabel(`${app.name} Alerts`);
    setBotTokenInput('');
    setTelegramChatIdInput('');
    setExternalWebhookInput('');
    setDrawerError(null);
    setDrawerNotice(null);
    setCreatedSecretOnce(null);
  };

  const closeDrawer = () => {
    setActiveApp(null);
    setBotTokenInput('');
    setCreatedSecretOnce(null);
    setDrawerError(null);
    setDrawerNotice(null);
  };

  const handleCopy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedField(label);
      setTimeout(() => setCopiedField(null), 1800);
    } catch {
      // Fallback ignored safely
    }
  };

  const handleCreateConnection = async (e: React.FormEvent, registerWebhook = false) => {
    e.preventDefault();
    if (!activeApp || !consentGranted) return;

    setCreatingConn(true);
    setDrawerError(null);
    setDrawerNotice(null);

    const res = await safeJsonFetch<{
      connection: PublicDirectConnection;
      signingSecretShownOnce: string;
      ingestUrl: string;
    }>('/api/v1/connections', {
      method: 'POST',
      body: JSON.stringify({
        appId: activeApp.id,
        label: connLabel.trim() || `${activeApp.name} Alerts`,
        ...(botTokenInput.trim() ? { botToken: botTokenInput.trim() } : {}),
        ...(telegramChatIdInput.trim() ? { telegramChatId: telegramChatIdInput.trim() } : {}),
        ...(externalWebhookInput.trim()
          ? { externalWebhookUrl: externalWebhookInput.trim() }
          : {}),
        registerWebhook,
      }),
    });

    setCreatingConn(false);

    if (!res.ok || !res.data) {
      setDrawerError(res.message);
      return;
    }

    // Never keep Bot Token in React state after submission
    setBotTokenInput('');
    setCreatedSecretOnce({
      connectionId: res.data.connection.id,
      secret: res.data.signingSecretShownOnce,
      ingestUrl: res.data.ingestUrl,
    });
    setDrawerNotice(
      res.data.connection.webhookNote ||
        'Connection saved with encrypted secret. Copy your signing secret below now.'
    );
    await loadConnections();
  };

  const handleDeleteConnection = async (connectionId: string) => {
    setDrawerError(null);
    const res = await safeJsonFetch(`/api/v1/connections?id=${encodeURIComponent(connectionId)}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      setDrawerError(res.message);
      return;
    }
    if (createdSecretOnce?.connectionId === connectionId) {
      setCreatedSecretOnce(null);
    }
    setDrawerNotice('Connection disconnected and secret deleted.');
    await loadConnections();
  };

  const handleSendSignedTestIngest = async (connection: PublicDirectConnection, secret: string) => {
    if (!activeApp) return;
    setTestingConnId(connection.id);
    setDrawerError(null);
    setDrawerNotice(null);

    try {
      const timestamp = String(Date.now());
      const bodyStr = JSON.stringify({
        title: `${activeApp.name} Test Alert`,
        message: `Verified HMAC-SHA256 webhook check from ${activeApp.name} connection.`,
        priority: 'HIGH',
        simulated: true,
      });

      const sigHex = await signPayloadHmacSha256Hex(secret, timestamp, bodyStr);

      const res = await safeJsonFetch<{ notificationId: string; priority: string }>(
        connection.ingestPath,
        {
          method: 'POST',
          headers: {
            'X-Aegis-Timestamp': timestamp,
            'X-Aegis-Signature': `sha256=${sigHex}`,
          },
          body: bodyStr,
        }
      );

      if (!res.ok) {
        setDrawerError(res.message);
      } else {
        setDrawerNotice(
          `Signed test accepted (${res.data?.priority || 'HIGH'}). Dispatched to Live Inbox.`
        );
        await loadConnections();
        onIngestSuccess?.();
      }
    } catch (err: any) {
      setDrawerError(err?.message || 'Unable to compute HMAC test signature in this browser.');
    } finally {
      setTestingConnId(null);
    }
  };

  const handleSendSimulatedNotification = async (app: CatalogApp) => {
    if (!onSimulatedNotification) return;
    setSendingSimulated(true);
    setDrawerError(null);
    try {
      await onSimulatedNotification(
        app,
        `${app.name} (Simulated)`,
        `Simulated test alert for ${app.name}. Launch-only apps cannot push directly without an official bot or webhook.`
      );
      setDrawerNotice(`Simulated test notification sent to your Live Inbox for ${app.name}.`);
    } catch (err: any) {
      setDrawerError(err?.message || 'Failed to dispatch simulated notification.');
    } finally {
      setSendingSimulated(false);
    }
  };

  const filteredApps = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return APP_CATALOG.filter((app) => {
      if (selectedCategory !== 'All' && app.category !== selectedCategory) return false;
      const status = resolveHonestAppStatus(app, catalogStates[app.id]);
      if (statusFilter !== 'All' && status !== statusFilter) return false;
      if (
        q &&
        !app.name.toLowerCase().includes(q) &&
        !app.category.toLowerCase().includes(q) &&
        !app.connectionType.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [selectedCategory, statusFilter, searchQuery, catalogStates]);

  const connectionsByAppId = useMemo(() => {
    const grouped: Record<string, PublicDirectConnection[]> = {};
    for (const c of connections) {
      if (!grouped[c.appId]) grouped[c.appId] = [];
      grouped[c.appId].push(c);
    }
    return grouped;
  }, [connections]);

  const activeAppConnections = activeApp ? connectionsByAppId[activeApp.id] || [] : [];

  return (
    <div className="space-y-6">
      {/* Header & Honest Device Scan Bar */}
      <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <h2 className="font-display text-2xl font-semibold text-[#16161D] tracking-tight">
              App Catalog &amp; Connections
            </h2>
            <p className="text-xs text-[#6F6C7A]">
              Curated catalog of {APP_CATALOG.length} popular apps · {connections.length} active encrypted connection{connections.length === 1 ? '' : 's'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              type="button"
              onClick={() => setShowHowItWorks((v) => !v)}
              className="px-3.5 py-2 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap"
            >
              <Info className="w-3.5 h-3.5 text-[#D9468F]" />
              <span>How detection works</span>
              {showHowItWorks ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>

            <button
              type="button"
              onClick={() => void handleScanDevice()}
              disabled={isScanning}
              className="px-4 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] disabled:opacity-60 text-[#FAF6F0] text-xs font-semibold flex items-center space-x-2 whitespace-nowrap transition-colors"
            >
              <Scan className={`w-3.5 h-3.5 ${isScanning ? 'animate-pulse text-[#D9468F]' : ''}`} />
              <span>{isScanning ? 'Checking browser API...' : 'Scan this device'}</span>
            </button>
          </div>
        </div>

        {/* Honest "How detection works" Info Panel */}
        {showHowItWorks && (
          <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-2.5 text-xs text-[#464451]">
            <p className="font-semibold text-[#16161D]">
              Why browsers cannot list your installed apps — and what these badges honestly mean
            </p>
            <p className="leading-relaxed">
              For privacy and security, modern browsers do <strong>not</strong> allow any website to read the list of apps installed on your phone or computer. AegisNotify never fakes detection or probes files outside this {APP_CATALOG.length}-app catalog.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 pt-1">
              <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-2.5">
                <span className="font-semibold text-emerald-700">Detected</span>
                <p className="text-[11px] text-[#6F6C7A] mt-0.5">
                  Shown only if <code className="font-mono-tech">navigator.getInstalledRelatedApps()</code> reports a manifest-verified match.
                </p>
              </div>
              <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-2.5">
                <span className="font-semibold text-[#16161D]">Launchable</span>
                <p className="text-[11px] text-[#6F6C7A] mt-0.5">
                  A known URL scheme exists so you can click &quot;Test deep link&quot; to try opening it. Never claims it is installed.
                </p>
              </div>
              <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-2.5">
                <span className="font-semibold text-[#B52A70]">Marked by you</span>
                <p className="text-[11px] text-[#6F6C7A] mt-0.5">
                  You toggled &quot;I use this app&quot; or confirmed &quot;Yes&quot; after testing its deep link.
                </p>
              </div>
              <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-2.5">
                <span className="font-semibold text-[#6F6C7A]">Unknown</span>
                <p className="text-[11px] text-[#6F6C7A] mt-0.5">
                  Web-first app with no deep-link check or browser report yet.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Scan Result Banner */}
        {scanResult && (
          <div
            className={`rounded-2xl border px-4 py-3 flex items-start justify-between gap-3 text-xs ${
              scanResult.apiSupported
                ? 'bg-[#FFFDF9] border-[#E5DDD0] text-[#16161D]'
                : 'bg-amber-50 border-amber-200 text-amber-900'
            }`}
          >
            <div className="flex items-start space-x-2.5">
              <Info className="w-4 h-4 shrink-0 mt-0.5 text-[#D9468F]" />
              <div>
                <p className="font-semibold">
                  {scanResult.apiSupported
                    ? 'Best-effort related-app check completed'
                    : 'Browser does not support related-app detection'}
                </p>
                <p className="text-[11px] opacity-90 mt-0.5">{scanResult.message}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setScanResult(null)}
              className="text-[#6F6C7A] hover:text-[#16161D] shrink-0"
              aria-label="Dismiss scan message"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Consent Guard Banner */}
        {!consentGranted && (
          <div className="rounded-2xl bg-[#FCECF4] border border-[#F2C4DC] p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="w-5 h-5 text-[#B52A70] shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-[#16161D]">
                  Catalog &amp; encrypted connection storage consent is currently disabled
                </p>
                <p className="text-[11px] text-[#464451] mt-0.5">
                  Grant consent to mark apps you use and create encrypted webhook or bot connections.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void handleQuickGrantConsent()}
              disabled={grantingConsent}
              className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold whitespace-nowrap shrink-0 disabled:opacity-60"
            >
              {grantingConsent ? 'Saving...' : 'Allow Catalog & Connections'}
            </button>
          </div>
        )}

        {/* Search, Status Filter, and Category Tabs */}
        <div className="flex flex-col md:flex-row md:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-[#6F6C7A] absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search apps by name, category, or webhook type..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs text-[#16161D] placeholder:text-[#6F6C7A] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
            />
          </div>

          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as 'All' | AppDetectionStatus)}
            className="px-3.5 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
          >
            <option value="All">All Statuses</option>
            <option value="Detected">Detected ({isRelatedAppsApiSupported() ? 'API' : '0'})</option>
            <option value="Launchable">Launchable</option>
            <option value="Marked by you">Marked by you</option>
            <option value="Unknown">Unknown</option>
          </select>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
          {(['All', ...APP_CATEGORIES] as const).map((cat) => {
            const active = selectedCategory === cat;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition-all whitespace-nowrap shrink-0 border ${
                  active
                    ? 'bg-[#D9468F] text-[#FFFDF9] border-[#D9468F]'
                    : 'bg-[#FFFDF9] text-[#464451] border-[#E5DDD0] hover:bg-[#F2ECE2]'
                }`}
              >
                {cat}
              </button>
            );
          })}
        </div>
      </div>

      {/* Connections Loading / Error */}
      {connectionsError && (
        <div className="rounded-2xl bg-red-50 border border-red-200 px-4 py-3 flex items-center justify-between text-xs text-red-700">
          <span>{connectionsError}</span>
          <button
            type="button"
            onClick={() => void loadConnections()}
            className="px-3 py-1 rounded-lg bg-red-700 text-white font-semibold whitespace-nowrap"
          >
            Retry
          </button>
        </div>
      )}

      {/* Catalog Grid */}
      {filteredApps.length === 0 ? (
        <div className="glass-panel rounded-2xl border border-[#E5DDD0] p-10 text-center space-y-2">
          <p className="text-sm font-semibold text-[#16161D]">No matching apps found</p>
          <p className="text-xs text-[#6F6C7A]">
            Try clearing your search or switching category filters.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredApps.map((app) => {
            const state = catalogStates[app.id];
            const status = resolveHonestAppStatus(app, state);
            const appConns = connectionsByAppId[app.id] || [];
            const isMarked = Boolean(state?.markedByUser || state?.deepLinkConfirmed === 'yes');
            const showingDeepLinkPrompt = pendingDeepLinkAppId === app.id;

            return (
              <div
                key={app.id}
                className="glass-panel rounded-2xl border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3.5 hover:border-[#D9468F]/40 transition-colors"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center space-x-3 min-w-0">
                      <AppIconBadge appId={app.id} size="md" />
                      <div className="min-w-0">
                        <h3 className="text-sm font-semibold text-[#16161D] truncate">
                          {app.name}
                        </h3>
                        <p className="text-[11px] text-[#6F6C7A] truncate">
                          {app.category} · {app.connectionType}
                        </p>
                      </div>
                    </div>

                    <span
                      className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border whitespace-nowrap shrink-0 ${statusBadgeStyle(
                        status
                      )}`}
                    >
                      {status}
                    </span>
                  </div>

                  <p className="text-xs text-[#464451] leading-relaxed line-clamp-2">
                    {app.description}
                  </p>

                  {/* Active Connection Indicator */}
                  {!connectionsLoading && appConns.length > 0 && (
                    <div className="rounded-xl bg-emerald-50 border border-emerald-200 px-3 py-1.5 flex items-center justify-between text-[11px] text-emerald-800">
                      <span className="flex items-center space-x-1.5 font-medium truncate">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-emerald-600" />
                        <span className="truncate">
                          {appConns.length} active ({appConns[0].secretMask})
                        </span>
                      </span>
                      <span className="font-mono-tech text-[10px] shrink-0">
                        {appConns.reduce((acc, c) => acc + c.receivedCount, 0)} events
                      </span>
                    </div>
                  )}

                  {/* Honest Deep Link Feedback Prompt */}
                  {showingDeepLinkPrompt && (
                    <div className="rounded-xl bg-[#FCECF4] border border-[#F2C4DC] p-2.5 flex items-center justify-between gap-2 text-xs">
                      <span className="text-[#16161D] font-medium">Did the app open?</span>
                      <div className="flex items-center space-x-1.5 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleDeepLinkConfirmation(app, true)}
                          className="px-2.5 py-1 rounded-lg bg-[#16161D] text-[#FAF6F0] text-[11px] font-semibold"
                        >
                          Yes
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeepLinkConfirmation(app, false)}
                          className="px-2.5 py-1 rounded-lg bg-[#FFFDF9] border border-[#D8CEC0] text-[#464451] text-[11px] font-semibold"
                        >
                          No
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Card Footer Actions */}
                <div className="pt-2 border-t border-[#E5DDD0]/80 flex flex-wrap items-center justify-between gap-2">
                  <label className="flex items-center space-x-1.5 text-[11px] text-[#464451] cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={isMarked}
                      disabled={!consentGranted}
                      onChange={() => handleToggleUseApp(app)}
                      className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F] disabled:opacity-40"
                    />
                    <span>I use this app</span>
                  </label>

                  <div className="flex items-center space-x-1.5">
                    {app.deepLink && (
                      <button
                        type="button"
                        onClick={() => handleTestDeepLink(app)}
                        className="px-2.5 py-1.5 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] text-[11px] font-semibold whitespace-nowrap shrink-0"
                      >
                        Test deep link
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => openDrawerForApp(app)}
                      className="px-3 py-1.5 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-[11px] font-semibold flex items-center space-x-1 whitespace-nowrap shrink-0 transition-colors"
                    >
                      <Plug className="w-3 h-3" />
                      <span>{appConns.length > 0 ? 'Manage' : 'Connect'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Direct Connect Drawer */}
      {activeApp && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-[#16161D]/55 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          aria-label={`Connect ${activeApp.name}`}
        >
          <div className="w-full max-w-lg bg-[#FFFDF9] border-l border-[#E5DDD0] h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between gap-3 pb-4 border-b border-[#E5DDD0]">
              <div className="flex items-center space-x-3">
                <AppIconBadge appId={activeApp.id} size="lg" />
                <div>
                  <h3 className="font-display text-xl font-semibold text-[#16161D]">
                    {activeApp.name}
                  </h3>
                  <p className="text-xs text-[#6F6C7A]">
                    {activeApp.category} · Mode:{' '}
                    <span className="font-mono-tech font-semibold text-[#16161D]">
                      {activeApp.connectionType}
                    </span>
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={closeDrawer}
                className="p-2 rounded-xl border border-[#E5DDD0] text-[#464451] hover:bg-[#F2ECE2]"
                aria-label="Close drawer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {drawerError && (
              <div className="rounded-xl bg-red-50 border border-red-200 p-3 text-xs text-red-700 flex items-start space-x-2">
                <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{drawerError}</span>
              </div>
            )}

            {drawerNotice && (
              <div className="rounded-xl bg-emerald-50 border border-emerald-200 p-3 text-xs text-emerald-800 flex items-start space-x-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-600" />
                <span>{drawerNotice}</span>
              </div>
            )}

            {/* One-Time Revealed Signing Secret */}
            {createdSecretOnce && (
              <div className="rounded-2xl bg-[#16161D] text-[#FAF6F0] p-4 space-y-3 border border-[#2A2935]">
                <div className="flex items-center space-x-2 text-xs font-semibold text-[#F9A8D4]">
                  <KeyRound className="w-4 h-4" />
                  <span>Copy your HMAC signing secret now — shown once</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase tracking-wider text-[#B6B1C2]">
                    Ingest Endpoint URL
                  </span>
                  <div className="flex items-center justify-between gap-2 bg-[#23232E] rounded-xl px-3 py-2">
                    <code className="text-[11px] font-mono-tech break-all text-[#FAF6F0]">
                      {createdSecretOnce.ingestUrl}
                    </code>
                    <button
                      type="button"
                      onClick={() => void handleCopy('url', createdSecretOnce.ingestUrl)}
                      className="p-1.5 rounded-lg bg-[#2E2E3B] hover:bg-[#3A3A4A] shrink-0"
                      title="Copy ingest URL"
                    >
                      {copiedField === 'url' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase tracking-wider text-[#B6B1C2]">
                    Signing Secret (Encrypted on server after this)
                  </span>
                  <div className="flex items-center justify-between gap-2 bg-[#23232E] rounded-xl px-3 py-2">
                    <code className="text-[11px] font-mono-tech break-all text-[#F9A8D4]">
                      {createdSecretOnce.secret}
                    </code>
                    <button
                      type="button"
                      onClick={() => void handleCopy('secret', createdSecretOnce.secret)}
                      className="p-1.5 rounded-lg bg-[#2E2E3B] hover:bg-[#3A3A4A] shrink-0"
                      title="Copy signing secret"
                    >
                      {copiedField === 'secret' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {(() => {
                  const matchedConn = connections.find(
                    (c) => c.id === createdSecretOnce.connectionId
                  );
                  if (!matchedConn) return null;
                  return (
                    <button
                      type="button"
                      onClick={() =>
                        void handleSendSignedTestIngest(matchedConn, createdSecretOnce.secret)
                      }
                      disabled={testingConnId === matchedConn.id}
                      className="w-full py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold flex items-center justify-center space-x-2"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>
                        {testingConnId === matchedConn.id
                          ? 'Sending signed test...'
                          : 'Send Signed HMAC Test Ingest'}
                      </span>
                    </button>
                  );
                })()}
              </div>
            )}

            {/* Launch-Only & Manual Flow */}
            {(activeApp.connectionType === 'launch-only' ||
              activeApp.connectionType === 'manual') && (
              <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-3">
                <p className="text-xs font-semibold text-[#16161D]">
                  Direct App Launch &amp; Simulated Testing
                </p>
                <p className="text-xs text-[#464451] leading-relaxed">
                  {activeApp.name} does not provide a personal incoming webhook API for third-party web dashboards. You can launch it directly and send a clearly labeled simulated test alert to verify your inbox rules.
                </p>

                <div className="flex flex-wrap items-center gap-2.5 pt-1">
                  <button
                    type="button"
                    onClick={() =>
                      triggerSafeSchemeOrWebLink(activeApp.deepLink || activeApp.webUrl)
                    }
                    className="px-4 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    <span>Open app</span>
                  </button>

                  <a
                    href={activeApp.webUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-4 py-2 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] text-xs font-semibold whitespace-nowrap"
                  >
                    Open web app
                  </a>
                </div>

                <div className="pt-3 border-t border-[#E5DDD0] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5">
                  <div>
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-semibold">
                      Simulated
                    </span>
                    <p className="text-[11px] text-[#6F6C7A] mt-1">
                      Generates a mock alert inside Aegis (not from {activeApp.name} servers).
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleSendSimulatedNotification(activeApp)}
                    disabled={sendingSimulated}
                    className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] disabled:opacity-60 text-[#FFFDF9] text-xs font-semibold whitespace-nowrap shrink-0"
                  >
                    {sendingSimulated ? 'Sending...' : 'Send me a test notification'}
                  </button>
                </div>
              </div>
            )}

            {/* Server-Ingested Connection Flows: telegram | discord | slack | github | webhook */}
            {activeApp.connectionType !== 'launch-only' &&
              activeApp.connectionType !== 'manual' && (
                <form
                  onSubmit={(e) =>
                    void handleCreateConnection(e, activeApp.connectionType === 'telegram')
                  }
                  className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-4"
                >
                  {activeApp.connectionType === 'telegram' && (
                    <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 text-xs text-[#464451] space-y-1">
                      <p className="font-semibold text-[#16161D]">
                        BotFather Setup Guide
                      </p>
                      <ol className="list-decimal list-inside space-y-0.5 text-[11px]">
                        <li>Open @BotFather in Telegram and run <code className="font-mono-tech">/newbot</code>.</li>
                        <li>Copy the Bot Token and paste it below.</li>
                        <li>Aegis encrypts your token on the server with AES-256-GCM and never stores it in your browser.</li>
                      </ol>
                    </div>
                  )}

                  {(activeApp.connectionType === 'discord' ||
                    activeApp.connectionType === 'slack') && (
                    <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 text-xs text-[#464451] space-y-1">
                      <p className="font-semibold text-[#16161D]">
                        {activeApp.name} Incoming &amp; Ingest Setup
                      </p>
                      <p className="text-[11px] leading-relaxed">
                        Create an HMAC-signed Aegis ingest URL for {activeApp.name} workflows. You can also optionally attach an official {activeApp.name} HTTPS webhook URL.
                      </p>
                    </div>
                  )}

                  {activeApp.connectionType === 'github' && (
                    <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 text-xs text-[#464451] space-y-1">
                      <p className="font-semibold text-[#16161D]">GitHub Webhook Guide</p>
                      <ol className="list-decimal list-inside space-y-0.5 text-[11px]">
                        <li>Create the connection below to generate your Payload URL &amp; secret.</li>
                        <li>In GitHub Repo → Settings → Webhooks, choose <code className="font-mono-tech">application/json</code>.</li>
                        <li>Paste the Payload URL and Secret (Aegis verifies <code className="font-mono-tech">X-Hub-Signature-256</code>).</li>
                      </ol>
                    </div>
                  )}

                  {activeApp.connectionType === 'whatsapp' && (
                    <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 text-xs text-[#464451] space-y-1.5">
                      <p className="font-semibold text-[#16161D]">
                        Meta WhatsApp Business Cloud API Setup
                      </p>
                      <ol className="list-decimal list-inside space-y-0.5 text-[11px]">
                        <li>Create the connection below to generate your Callback URL (<code className="font-mono-tech">/api/v1/ingest/:connectionId</code>) and Signing Secret.</li>
                        <li>In Meta App Dashboard → WhatsApp → Configuration, paste the Callback URL and set Verify Token to your Signing Secret (or <code className="font-mono-tech">WHATSAPP_VERIFY_TOKEN</code>).</li>
                        <li>Subscribe to the <code className="font-mono-tech">messages</code> webhook field (Aegis verifies <code className="font-mono-tech">X-Hub-Signature-256</code> via HMAC-SHA256).</li>
                      </ol>
                    </div>
                  )}

                  {activeApp.connectionType === 'webhook' && (
                    <div className="rounded-xl bg-[#FFFDF9] border border-[#E5DDD0] p-3 text-xs text-[#464451] space-y-1.5">
                      <p className="font-semibold text-[#16161D]">
                        {activeApp.id === 'email-alerts' ? 'Inbound Email Webhook Bridge' : 'Signed Webhook Endpoint'}
                      </p>
                      <p className="text-[11px] leading-relaxed">
                        Creates a dedicated <code className="font-mono-tech">/api/v1/ingest/:connectionId</code> URL secured with HMAC-SHA256 (<code className="font-mono-tech">X-Aegis-Signature</code>) and a 5-minute replay window (<code className="font-mono-tech">X-Aegis-Timestamp</code>).
                      </p>
                      {activeApp.id === 'email-alerts' && (
                        <p className="text-[11px] leading-relaxed text-[#6F6C7A]">
                          Forward from Gmail Apps Script, Zapier, Mailgun, or SendGrid using JSON fields{' '}
                          <code className="font-mono-tech">{'{"subject", "from", "text", "priority"}'}</code>.
                        </p>
                      )}
                    </div>
                  )}

                  <div className="space-y-3">
                    <div>
                      <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                        Connection Label
                      </label>
                      <input
                        type="text"
                        value={connLabel}
                        onChange={(e) => setConnLabel(e.target.value)}
                        maxLength={80}
                        placeholder={`${activeApp.name} Production Alerts`}
                        className="w-full px-3.5 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                      />
                    </div>

                    {activeApp.connectionType === 'telegram' && (
                      <>
                        <div>
                          <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                            Telegram Bot Token (sent once, encrypted on server)
                          </label>
                          <input
                            type="password"
                            autoComplete="off"
                            value={botTokenInput}
                            onChange={(e) => setBotTokenInput(e.target.value)}
                            placeholder="123456789:AAH..."
                            className="w-full px-3.5 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs font-mono-tech text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                            required
                          />
                        </div>
                        <div>
                          <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                            Optional Chat ID (for reference)
                          </label>
                          <input
                            type="text"
                            value={telegramChatIdInput}
                            onChange={(e) => setTelegramChatIdInput(e.target.value)}
                            placeholder="e.g. -1001234567890"
                            className="w-full px-3.5 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs font-mono-tech text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                          />
                        </div>
                      </>
                    )}

                    {(activeApp.connectionType === 'discord' ||
                      activeApp.connectionType === 'slack') && (
                      <div>
                        <label className="block text-[11px] font-semibold text-[#464451] mb-1">
                          Optional Official {activeApp.name} Webhook URL
                        </label>
                        <input
                          type="url"
                          value={externalWebhookInput}
                          onChange={(e) => setExternalWebhookInput(e.target.value)}
                          placeholder={
                            activeApp.connectionType === 'discord'
                              ? 'https://discord.com/api/webhooks/...'
                              : 'https://hooks.slack.com/services/...'
                          }
                          className="w-full px-3.5 py-2 rounded-xl bg-[#FFFDF9] border border-[#D8CEC0] text-xs font-mono-tech text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                        />
                      </div>
                    )}
                  </div>

                  {!consentGranted && (
                    <p className="text-[11px] text-[#B52A70] font-medium">
                      Grant App Catalog &amp; Encrypted Storage consent first to create connections.
                    </p>
                  )}

                  <button
                    type="submit"
                    disabled={creatingConn || !consentGranted}
                    className="w-full py-2.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] disabled:opacity-50 text-[#FAF6F0] text-xs font-semibold flex items-center justify-center space-x-2"
                  >
                    <ShieldCheck className="w-4 h-4 text-[#D9468F]" />
                    <span>
                      {creatingConn
                        ? 'Encrypting & Creating...'
                        : activeApp.connectionType === 'telegram'
                        ? 'Encrypt Token & Register Webhook'
                        : `Generate Signed ${activeApp.name} Ingest Endpoint`}
                    </span>
                  </button>
                </form>
              )}

            {/* Existing Connections List for Selected App */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[#6F6C7A]">
                  Saved Connections ({activeAppConnections.length})
                </h4>
                <button
                  type="button"
                  onClick={() => void loadConnections()}
                  className="text-xs text-[#6F6C7A] hover:text-[#16161D] flex items-center space-x-1"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Refresh</span>
                </button>
              </div>

              {activeAppConnections.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-[#D8CEC0] p-5 text-center text-xs text-[#6F6C7A]">
                  No server connections created for {activeApp.name} yet.
                </div>
              ) : (
                activeAppConnections.map((conn) => (
                  <div
                    key={conn.id}
                    className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-2.5"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="text-xs font-semibold text-[#16161D]">{conn.label}</p>
                        <p className="text-[11px] font-mono-tech text-[#6F6C7A]">
                          Secret: {conn.secretMask}
                          {conn.botTokenMask ? ` · Bot Token: ${conn.botTokenMask}` : ''}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => void handleDeleteConnection(conn.id)}
                        className="p-1.5 rounded-lg border border-red-200 bg-red-50 text-red-700 hover:bg-red-100"
                        title="Disconnect and delete secret"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="text-[11px] font-mono-tech bg-[#FFFDF9] border border-[#E5DDD0] rounded-xl px-3 py-1.5 flex items-center justify-between gap-2">
                      <span className="truncate text-[#464451]">{conn.ingestPath}</span>
                      <button
                        type="button"
                        onClick={() =>
                          void handleCopy(
                            conn.id,
                            `${typeof window !== 'undefined' ? window.location.origin : ''}${conn.ingestPath}`
                          )
                        }
                        className="text-[#D9468F] hover:text-[#B52A70] shrink-0 font-sans font-semibold"
                      >
                        {copiedField === conn.id ? 'Copied' : 'Copy URL'}
                      </button>
                    </div>

                    {conn.webhookNote && (
                      <p className="text-[11px] text-[#464451]">{conn.webhookNote}</p>
                    )}

                    <div className="flex items-center justify-between text-[11px] text-[#6F6C7A]">
                      <span>{conn.receivedCount} verified events received</span>
                      <span>
                        {conn.lastReceivedAt
                          ? `Last: ${new Date(conn.lastReceivedAt).toLocaleTimeString()}`
                          : 'Waiting for first event'}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
