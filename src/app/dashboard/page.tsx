'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Bell,
  SlidersHorizontal,
  Layers,
  Clock,
  Search,
  Filter,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  XCircle,
  Lock,
  RefreshCw,
  Copy,
  Check,
  ChevronRight,
  Plus,
  X,
  Zap,
  Power,
  Send,
  MessageSquare,
  GitBranch,
  CreditCard,
  CheckSquare,
  Mail,
  Globe,
  Laptop,
  Smartphone,
  Eye,
  Sliders,
  Volume2,
  VolumeX,
  Bot,
  Database,
  Save,
  Activity,
  LayoutGrid,
  Trash2,
  Flame,
  EyeOff,
  ThumbsUp,
  ThumbsDown,
  Split,
  Cpu,
  Download,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { ConnectedApp } from '../../lib/integrations/store.js';
import { QuarantinedAlert } from '../../lib/quarantine/store.js';
import { AegisGlyphLogo, NothingAppLogo } from '../../components/NothingLogos.js';
import GeminiChatbot from '../../components/GeminiChatbot.js';
import SecurityTelemetryPage from '../../components/SecurityTelemetryPage.js';
import ErrorBoundary from '../../components/ErrorBoundary.js';
import OnboardingModal from '../../components/OnboardingModal.js';
import AppCatalogConnections from '../../components/AppCatalogConnections.js';
import AppIconBadge from '../../components/AppIconBadge.js';
import EphemeralVaultSection from '../../components/EphemeralVaultSection.js';
import type { CatalogApp } from '../../data/appCatalog.js';
import { clearLocalCatalogStates } from '../../lib/integrations/appDetection.js';
import {
  resolveEffectiveDeliveryPlan,
  formatChannelPlanLabel,
} from '../../lib/delivery/policies.js';
import { ALLOWED_EPHEMERAL_TTL_PRESETS } from '../../lib/ephemeral/constants.js';
import { encryptAndWrapEphemeralMessage } from '../../lib/ephemeral/crypto.js';
import {
  ensureClientEphemeralKeyRing,
  resolveRecipientEcdhPublicJwk,
} from '../../lib/ephemeral/clientMemory.js';
import {
  auth,
  onAuthStateChanged,
  loadUserPreferencesFromFirestore,
  saveUserPreferencesToFirestore,
  syncFirebaseUserProfile,
  ensureUserProfileInFirestore,
  linkVerifiedPhoneInFirestore,
  loadUserPhoneStatusFromFirestore,
  loadOnboardingAndConsent,
  saveOnboardingAndConsent,
  deleteAllAppCatalogStatesInFirestore,
  syncDeliveryJobToFirestore,
  syncDedupThreadToFirestore,
  deleteDedupThreadFromFirestore,
  loadDedupSettingsFromFirestore,
  type UserPrivacyConsentState,
  type User as FirebaseUser,
} from '../../lib/firebase/client.js';
import { safeReadJson } from '../../lib/http/safeJson.js';
import {
  createSignedProvenanceEnvelopeBrowser,
  type UnlockedSigningKey,
} from '../../lib/provenance/browserCrypto.js';
import {
  ProvenanceDetailsDrawer,
  ProvenanceStatusBadge,
} from '../../components/ProvenanceBadgeAndDrawer.js';
import SigningKeysSettingsSection from '../../components/SigningKeysSettingsSection.js';
import AccountSecuritySettingsSection from '../../components/AccountSecuritySettingsSection.js';
import { PriorityWhyDrawer } from '../../components/PriorityWhyDrawer.js';
import MyPrioritiesSettingsSection from '../../components/MyPrioritiesSettingsSection.js';
import DedupSettingsSection from '../../components/DedupSettingsSection.js';
import DedupWhyDrawer, { type InspectedDedupTarget } from '../../components/DedupWhyDrawer.js';
import {
  invalidateClientProvenanceCaches,
  rescorePriorityOnRecipientDevice,
  verifyItemProvenanceOnClient,
} from '../../lib/provenance/clientVerify.js';
import {
  computeTextImportanceScore,
  computeUserContextFactor,
} from '../../lib/priority/features.js';
import { shouldUsePersonalizedWeights } from '../../lib/priority/learning.js';
import {
  DEFAULT_BIAS,
  DEFAULT_WEIGHTS,
  toLegacyNotificationPriority,
} from '../../lib/priority/math.js';
import { globalClientDedupWindow } from '../../lib/dedup/pipeline.js';
import {
  embedTextInBrowser,
  getEmbedderSnapshot,
  prewarmOnnxEmbedder,
  subscribeEmbedderSnapshot,
  disposeClientEmbedder,
  type ClientEmbedderSnapshot,
} from '../../lib/dedup/clientEmbedder.js';
import { minProvenanceTrust } from '../../lib/dedup/guards.js';
import type {
  ProvenanceEnvelopeV1,
  ProvenanceVerificationReport,
} from '../../lib/provenance/types.js';
import type {
  PriorityFeedbackKind,
  PriorityScoreBreakdown,
  UserPriorityModelState,
} from '../../lib/priority/types.js';
import type {
  DedupDecisionResult,
  DedupProvenanceTrust,
  DedupThreadMetadata,
  UserDedupSettings,
} from '../../lib/dedup/types.js';

interface NotificationItem {
  notificationId: string;
  userId: string;
  eventType: string;
  rawText: string;
  dispatchScore: number;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  signature: string;
  sanitizedPayload?: Record<string, any>;
  metadata?: Record<string, any>;
  channelsUsed?: string[];
  status?: string;
  timestamp: string;
  verified?: boolean;
  ackState?: 'PENDING' | 'ACKED' | 'TIMEOUT_ESCALATED';
  provenanceEnvelope?: ProvenanceEnvelopeV1 | null;
  provenanceReport?: ProvenanceVerificationReport | null;
  priorityEngine?: PriorityScoreBreakdown | null;
  dedupThreadId?: string;
  dedupDecision?: DedupDecisionResult | null;
}

interface AnalyticsData {
  overview: {
    totalIngested: number;
    deduplicatedCount: number;
    dedupItemsReceived?: number;
    deduplicationRatePercent: number | null;
    averageDispatchWeight: number;
    activeSocketConnections: number;
    fallbackEscalationRatePercent: number;
  };
  statusBreakdown: Record<string, number>;
}

interface DashboardUser {
  id: string;
  phoneNumber?: string;
  email?: string;
  role?: string;
}

interface DashboardProps {
  user?: DashboardUser | null;
  initialUnlockedSigningKey?: UnlockedSigningKey | null;
  onLogout?: () => void;
}

export default function MinimalistAegisDashboard({
  user,
  initialUnlockedSigningKey = null,
  onLogout,
}: DashboardProps = {}) {
  const isAdmin = String(user?.role || '').toUpperCase() === 'ADMIN';

  // Navigation Tabs (supports /security-telemetry route for ADMIN users)
  const [activeTab, setActiveTabState] = useState<'feed' | 'quarantine' | 'catalog' | 'integrations' | 'channels' | 'rules' | 'history' | 'telemetry' | 'chat'>(() => {
    if (typeof window !== 'undefined' && isAdmin && window.location.pathname === '/security-telemetry') {
      return 'telemetry';
    }
    return 'feed';
  });

  const setActiveTab = (tab: 'feed' | 'quarantine' | 'catalog' | 'integrations' | 'channels' | 'rules' | 'history' | 'telemetry' | 'chat') => {
    setActiveTabState(tab);
    if (typeof window !== 'undefined') {
      const targetPath = tab === 'telemetry' ? '/security-telemetry' : '/';
      if (window.location.pathname !== targetPath) {
        window.history.replaceState(null, '', targetPath);
      }
    }
  };

  // Core Data
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [quarantinedAlerts, setQuarantinedAlerts] = useState<QuarantinedAlert[]>([]);
  const [connectedApps, setConnectedApps] = useState<ConnectedApp[]>([]);
  const [socketStatus, setSocketStatus] = useState<'CONNECTED' | 'DISCONNECTED' | 'CONNECTING'>('CONNECTING');
  const [serverPublicKey, setServerPublicKey] = useState<string>('');
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);

  // Priority Filter & Management
  const [priorityFilter, setPriorityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [minPriorityThreshold, setMinPriorityThreshold] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('LOW');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoAck, setAutoAck] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [updatingPriorityId, setUpdatingPriorityId] = useState<string | null>(null);
  const [priorityFeedback, setPriorityFeedback] = useState<string | null>(null);

  // Persisted User Preferences (Firestore + Local Fallback)
  const [firebaseUser, setFirebaseUser] = useState<FirebaseUser | null>(() => auth.currentUser);
  const [dndEnabled, setDndEnabled] = useState(false);
  const [quietHoursStart, setQuietHoursStart] = useState('22:00');
  const [quietHoursEnd, setQuietHoursEnd] = useState('07:00');
  const [preferredChannel, setPreferredChannel] = useState<'WEBSOCKET' | 'EMAIL' | 'SMS' | 'WEBPUSH' | 'WHATSAPP'>('WEBSOCKET');
  const [allowCriticalBypassQuietHours, setAllowCriticalBypassQuietHours] = useState(true);
  const [optOutPush, setOptOutPush] = useState(false);
  const [optOutWhatsapp, setOptOutWhatsapp] = useState(false);
  const [optOutSms, setOptOutSms] = useState(false);
  const [optOutEmail, setOptOutEmail] = useState(false);
  const [whatsappPhone, setWhatsappPhone] = useState('');
  const [whatsappPrefsError, setWhatsappPrefsError] = useState<string | null>(null);
  const [isSavingPrefs, setIsSavingPrefs] = useState(false);
  const [prefsFeedback, setPrefsFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Quarantine State & Modal
  const [selectedQuarantineAlert, setSelectedQuarantineAlert] = useState<QuarantinedAlert | null>(null);
  const [selectedQuarantineIds, setSelectedQuarantineIds] = useState<string[]>([]);
  const [showBulkDeleteQuarantineModal, setShowBulkDeleteQuarantineModal] = useState(false);
  const [isBulkDeletingQuarantine, setIsBulkDeletingQuarantine] = useState(false);
  const [isSimulatingThreat, setIsSimulatingThreat] = useState(false);
  const [quarantineFeedback, setQuarantineFeedback] = useState<string | null>(null);

  // Integration Controls & Modals
  const [selectedApp, setSelectedApp] = useState<ConnectedApp | null>(null);
  const [showAddAppModal, setShowAddAppModal] = useState(false);
  const [newAppName, setNewAppName] = useState('');
  const [newAppCategory, setNewAppCategory] = useState<'Dev' | 'Payments' | 'Chat' | 'Security' | 'Custom'>('Custom');
  const [newAppDesc, setNewAppDesc] = useState('');
  const [testingAppId, setTestingAppId] = useState<string | null>(null);

  // Manual Alert Simulation & Ephemeral Compose Options
  const [simApp, setSimApp] = useState('slack');
  const [simTitle, setSimTitle] = useState('Critical infrastructure vulnerability identified');
  const [simUrgency, setSimUrgency] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('HIGH');
  const [simOtp, setSimOtp] = useState('');
  const [trackInDeliveryPipeline, setTrackInDeliveryPipeline] = useState(true);
  const [simEphemeralMode, setSimEphemeralMode] = useState(false);
  const [simEphemeralTtl, setSimEphemeralTtl] = useState<60 | 300 | 900>(300);
  const [simEphemeralReadOnce, setSimEphemeralReadOnce] = useState(false);
  const [simEphemeralRecipientId, setSimEphemeralRecipientId] = useState('');
  const [ephemeralRefreshTick, setEphemeralRefreshTick] = useState(0);
  const [privacyShieldEnabled, setPrivacyShieldEnabled] = useState(true);
  const [isWindowBlurred, setIsWindowBlurred] = useState(false);
  const [isSubmittingSim, setIsSubmittingSim] = useState(false);
  const [simResult, setSimResult] = useState<any>(null);

  // Fallback Channel Diagnostics & Instant Testing
  const [channelTestTargetEmail, setChannelTestTargetEmail] = useState('');
  const [channelTestTargetWhatsapp, setChannelTestTargetWhatsapp] = useState('');
  const [channelTestTargetPhone, setChannelTestTargetPhone] = useState(user?.phoneNumber || '9876543210');
  const [activeTargetPhoneDisplay, setActiveTargetPhoneDisplay] = useState<string>(user?.phoneNumber || '');
  const [isSavingTargetPhone, setIsSavingTargetPhone] = useState(false);
  const [savePhoneFeedback, setSavePhoneFeedback] = useState<string | null>(null);
  const [testingChannel, setTestingChannel] = useState<'EMAIL' | 'WEBPUSH' | 'FAST2SMS' | 'WHATSAPP' | 'ALL' | null>(null);
  const [channelTestResult, setChannelTestResult] = useState<any>(null);
  const [webPushPermission, setWebPushPermission] = useState<NotificationPermission | 'unsupported'>('default');
  const [isSubscribedPush, setIsSubscribedPush] = useState(false);

  // Settings: Verify Your Phone (Twilio Verify / Mock SMS Linking)
  const [smsStatus, setSmsStatus] = useState<{
    smsConfigured: boolean;
    mode: 'mock' | 'twilio';
    demoMode: boolean;
    allowedCountries: string[];
  }>({
    smsConfigured: true,
    mode: 'mock',
    demoMode: true,
    allowedCountries: ['+91'],
  });
  const [channelGatewayStatus, setChannelGatewayStatus] = useState<{
    loaded: boolean;
    emailConfigured: boolean;
    emailSmtpConfigured: boolean;
    emailVerified: boolean;
    whatsappConfigured: boolean;
    fast2smsConfigured: boolean;
    firebasePhoneAuthConfigured: boolean;
    twilioConfigured: boolean;
    smsDemoMode: boolean;
    dbLive: boolean;
    dbMode: string;
  }>({
    loaded: false,
    emailConfigured: false,
    emailSmtpConfigured: false,
    emailVerified: false,
    whatsappConfigured: false,
    fast2smsConfigured: false,
    firebasePhoneAuthConfigured: false,
    twilioConfigured: false,
    smsDemoMode: true,
    dbLive: false,
    dbMode: 'local_json_fallback',
  });
  const [phoneLinkCountry, setPhoneLinkCountry] = useState('+91');
  const [phoneLinkInput, setPhoneLinkInput] = useState('');
  const [phoneLinkStep, setPhoneLinkStep] = useState<'enter' | 'verify'>('enter');
  const [phoneLinkCode, setPhoneLinkCode] = useState('');
  const [phoneLinkCooldown, setPhoneLinkCooldown] = useState(0);
  const [isSendingLinkSms, setIsSendingLinkSms] = useState(false);
  const [isVerifyingLinkSms, setIsVerifyingLinkSms] = useState(false);
  const [phoneLinkFeedback, setPhoneLinkFeedback] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [verifiedPhoneInfo, setVerifiedPhoneInfo] = useState<{
    phoneVerified: boolean;
    maskedPhone?: string;
  } | null>(() => {
    if (user?.phoneNumber) {
      return { phoneVerified: true, maskedPhone: user.phoneNumber };
    }
    return null;
  });

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  // First-Run Onboarding, Consent & Permissions State
  const effectiveUserId = firebaseUser?.uid || user?.id || 'usr_sec_admin_01';
  const vaultUserId = user?.id || 'usr_sec_admin_01';
  const [consentState, setConsentState] = useState<UserPrivacyConsentState | null>(null);
  const [showOnboardingModal, setShowOnboardingModal] = useState(false);
  const [privacyActionBusy, setPrivacyActionBusy] = useState(false);
  const [privacyFeedback, setPrivacyFeedback] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [catalogConnectionsVersion, setCatalogConnectionsVersion] = useState(0);

  // Zero-Trust Ed25519 Provenance State (unlocked seed lives strictly in volatile RAM)
  const [unlockedSigningKey, setUnlockedSigningKey] = useState<UnlockedSigningKey | null>(
    initialUnlockedSigningKey
  );
  const unlockedSigningKeyRef = useRef<UnlockedSigningKey | null>(initialUnlockedSigningKey);
  const [inspectedProvenanceReport, setInspectedProvenanceReport] =
    useState<ProvenanceVerificationReport | null>(null);
  const [revealedUnverifiedIds, setRevealedUnverifiedIds] = useState<Record<string, boolean>>({});
  const [inspectedPriorityItem, setInspectedPriorityItem] = useState<NotificationItem | null>(null);
  const [userPriorityModel, setUserPriorityModel] = useState<UserPriorityModelState | null>(null);
  const escalatedNotifTransitionsRef = useRef<Set<string>>(new Set());

  // On-Device Semantic Deduplication (Web Worker ONNX + TF-IDF Fallback + Zero-Text/Zero-Vector Metadata)
  const [userDedupSettings, setUserDedupSettings] = useState<UserDedupSettings | null>(null);
  const userDedupSettingsRef = useRef<UserDedupSettings | null>(null);
  const [dedupThreadsById, setDedupThreadsById] = useState<Record<string, DedupThreadMetadata>>({});
  const [notifThreadMap, setNotifThreadMap] = useState<Record<string, string>>({});
  const [notifDecisionMap, setNotifDecisionMap] = useState<Record<string, DedupDecisionResult>>({});
  const [expandedThreadIds, setExpandedThreadIds] = useState<Record<string, boolean>>({});
  const [inspectedDedupTarget, setInspectedDedupTarget] = useState<InspectedDedupTarget | null>(null);
  const [embedderSnapshot, setEmbedderSnapshot] = useState<ClientEmbedderSnapshot>(() =>
    getEmbedderSnapshot()
  );
  const firebaseUidRef = useRef<string | null>(firebaseUser?.uid || null);
  const vaultUserIdRef = useRef<string>(vaultUserId);

  useEffect(() => {
    unlockedSigningKeyRef.current = unlockedSigningKey;
  }, [unlockedSigningKey]);

  useEffect(() => {
    userDedupSettingsRef.current = userDedupSettings;
  }, [userDedupSettings]);

  useEffect(() => {
    firebaseUidRef.current = firebaseUser?.uid || null;
  }, [firebaseUser]);

  useEffect(() => {
    vaultUserIdRef.current = vaultUserId;
  }, [vaultUserId]);

  useEffect(() => {
    return subscribeEmbedderSnapshot(setEmbedderSnapshot);
  }, []);

  // Wipe ephemeral dedup vectors from RAM whenever ephemeral items expire or burn
  useEffect(() => {
    globalClientDedupWindow.wipeEphemeralItem(vaultUserId);
  }, [ephemeralRefreshTick, vaultUserId]);

  // Shared on-device dedup + metadata-only backend sync (idempotent across HTTP ingest + WS dispatch)
  const processedDedupDecisionsRef = useRef<Map<string, DedupDecisionResult>>(new Map());
  const inFlightDedupRef = useRef<Map<string, Promise<DedupDecisionResult | null>>>(new Map());

  const runClientDedupAndSync = async (params: {
    notificationId: string;
    eventType: string;
    rawText: string;
    priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    sourceId: string;
    senderId: string;
    timestamp?: string;
    categoryHint?: string;
    isEphemeral?: boolean;
    isPriorityFloorAlert?: boolean;
    trust: DedupProvenanceTrust;
    provenanceFailed?: boolean;
    verifiedForToast?: boolean;
    appName?: string;
    title?: string;
    sendBrowserNotification?: boolean;
  }): Promise<DedupDecisionResult | null> => {
    const nid = String(params.notificationId || '').trim();
    if (!nid) return null;

    const cached = processedDedupDecisionsRef.current.get(nid);
    if (cached) return cached;

    const existingPromise = inFlightDedupRef.current.get(nid);
    if (existingPromise) return existingPromise;

    const task = (async (): Promise<DedupDecisionResult | null> => {
      try {
        const rawEventLower = `${params.eventType || ''} ${params.rawText || ''}`.toLowerCase();
        const inferredCategory =
          (params.categoryHint || '').toLowerCase() ||
          (rawEventLower.includes('otp')
            ? 'otp'
            : rawEventLower.includes('login') || rawEventLower.includes('password')
            ? 'auth'
            : rawEventLower.includes('security') || rawEventLower.includes('breach')
            ? 'security'
            : rawEventLower.includes('payment') ||
              rawEventLower.includes('debited') ||
              rawEventLower.includes('rs ')
            ? 'finance'
            : 'work');

        const isOtpLoginOrKey = /\b(otp|one[- ]time|2fa|verification code|login code|key[- ]?change|pin[- ]?mismatch)\b/i.test(
          rawEventLower
        );

        const activeUser = vaultUserIdRef.current;
        const activeCfg = userDedupSettingsRef.current;
        const decision = await globalClientDedupWindow.processNotification({
          incoming: {
            notificationId: nid,
            userId: activeUser,
            sourceId: params.sourceId || params.eventType || 'direct',
            senderId: params.senderId || params.sourceId || 'gateway',
            category: inferredCategory,
            priority: params.priority,
            trust: params.trust,
            timestampMs: (params.timestamp ? Date.parse(params.timestamp) : Date.now()) || Date.now(),
            isEphemeral: Boolean(params.isEphemeral),
            isOtpOrLoginOrKeyChange: isOtpLoginOrKey,
            isPriorityFloorAlert: Boolean(
              params.isPriorityFloorAlert || params.priority === 'CRITICAL'
            ),
            provenanceFailed: Boolean(params.provenanceFailed),
          },
          rawTextInMemory: String(params.rawText || ''),
          embedder: embedTextInBrowser,
          options: activeCfg
            ? {
                dedupEnabled: activeCfg.dedupEnabled,
                mergeThreshold: activeCfg.effectiveMergeThreshold,
                reviewThreshold: activeCfg.reviewThreshold,
                windowMinutes: activeCfg.windowMinutes,
                neverMergeCategories: activeCfg.neverMergeCategories,
              }
            : undefined,
        });

        processedDedupDecisionsRef.current.set(nid, decision);
        if (processedDedupDecisionsRef.current.size > 500) {
          const oldestKey = processedDedupDecisionsRef.current.keys().next().value;
          if (oldestKey) processedDedupDecisionsRef.current.delete(oldestKey);
        }

        setDedupThreadsById((prev) => ({
          ...prev,
          [decision.threadId]: decision.threadMetadata,
        }));
        setNotifThreadMap((prev) => ({
          ...prev,
          [nid]: decision.threadId,
        }));
        setNotifDecisionMap((prev) => ({
          ...prev,
          [nid]: decision,
        }));
        setNotifications((prev) =>
          prev.map((item) =>
            item.notificationId === nid
              ? { ...item, dedupThreadId: decision.threadId, dedupDecision: decision }
              : item
          )
        );

        if (params.priority === 'CRITICAL' && decision.shouldPlayAlert) {
          playCriticalAlertSound();
        }

        if (
          params.sendBrowserNotification &&
          decision.shouldSendBrowserNotification &&
          typeof window !== 'undefined' &&
          'Notification' in window &&
          Notification.permission === 'granted'
        ) {
          try {
            const title =
              params.title ||
              (params.appName
                ? `${params.appName} · ${params.priority}`
                : `Aegis · ${params.eventType}`);
            new Notification(title, {
              body: params.verifiedForToast
                ? String(params.rawText || '').slice(0, 180)
                : 'Unverified security alert received — open AegisNotify to inspect provenance.',
              tag: String(decision.threadId || nid),
            });
          } catch {
            // Browser notification display error is non-fatal
          }
        }

        const authToken =
          typeof window !== 'undefined'
            ? window.localStorage.getItem('aegis_auth_token')
            : null;
        if (authToken) {
          await fetch('/api/v1/dedup/threads', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${authToken}`,
            },
            body: JSON.stringify({
              notificationId: nid,
              action: decision.action,
              stageMatched: decision.stageMatched,
              similarity: decision.similarity,
              blockedByGuard: decision.blockedByGuard,
              perSourceCapHit: decision.guards.some(
                (g) => g.guard === 'PER_SOURCE_CAP' && !g.passed
              ),
              priorityEscalatedInThread: decision.priorityEscalatedInThread,
              threadMetadata: decision.threadMetadata,
            }),
          }).catch(() => {});
        }

        if (firebaseUidRef.current && !params.isEphemeral) {
          void syncDedupThreadToFirestore(
            firebaseUidRef.current,
            decision.threadMetadata
          ).catch(() => {});
        }

        return decision;
      } finally {
        inFlightDedupRef.current.delete(nid);
      }
    })();

    inFlightDedupRef.current.set(nid, task);
    return task;
  };

  const runClientDedupAndSyncRef = useRef(runClientDedupAndSync);
  runClientDedupAndSyncRef.current = runClientDedupAndSync;

  // Load user's Sigmoid Priority Model & Semantic Deduplication settings
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const token = window.localStorage.getItem('aegis_auth_token');
    if (!token) return;
    fetch('/api/v1/priority/model', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => safeReadJson(res).then((json) => ({ ok: res.ok, json })))
      .then(({ ok, json }) => {
        if (ok && json?.success && json?.data?.model) {
          setUserPriorityModel(json.data.model);
        }
      })
      .catch(() => {});

    fetch('/api/v1/dedup/config', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => safeReadJson(res).then((json) => ({ ok: res.ok, json })))
      .then(({ ok, json }) => {
        if (ok && json?.success && json?.data?.settings) {
          setUserDedupSettings(json.data.settings);
        }
      })
      .catch(() => {});
  }, [vaultUserId]);

  // Dynamic time-escalation tick (every 10s) strictly for unacked items; stops on ACK
  useEffect(() => {
    const timer = setInterval(() => {
      const model = userPriorityModel;
      const usePersonal = model
        ? shouldUsePersonalizedWeights(model.feedbackCount, model.personalizationEnabled)
        : false;
      const weights = usePersonal && model ? model.weights : DEFAULT_WEIGHTS;
      const bias = usePersonal && model ? model.bias : DEFAULT_BIAS;
      const userCtx = computeUserContextFactor(model?.quietHours);

      setNotifications((prev) =>
        prev.map((item) => {
          if (item.ackState !== 'PENDING' || !item.priorityEngine?.features) {
            return item;
          }
          const createdMs = Date.parse(item.timestamp);
          if (!Number.isFinite(createdMs)) return item;
          const elapsedSeconds = Math.max(0, Math.floor((Date.now() - createdMs) / 1000));
          const prevBreakdown = item.priorityEngine;
          const nextBreakdown = rescorePriorityOnRecipientDevice({
            baseFeatures: prevBreakdown.features,
            provenanceEnvelope: item.provenanceEnvelope,
            provenanceVerified: Boolean(item.provenanceReport?.verified),
            elapsedSeconds,
            isAcked: false,
            userContext: userCtx,
            previousLabel: prevBreakdown.label,
            weights,
            bias,
          });

          if (nextBreakdown.label !== prevBreakdown.label) {
            const transitionKey = `${item.notificationId}:${nextBreakdown.label}`;
            if (!escalatedNotifTransitionsRef.current.has(transitionKey)) {
              escalatedNotifTransitionsRef.current.add(transitionKey);
              const token =
                typeof window !== 'undefined'
                  ? window.localStorage.getItem('aegis_auth_token')
                  : null;
              if (token) {
                void fetch('/api/v1/priority/score', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                  },
                  body: JSON.stringify({
                    notificationId: item.notificationId,
                    previousLabel: prevBreakdown.label,
                    elapsedSeconds,
                    isAcked: false,
                    features: nextBreakdown.features,
                  }),
                }).catch(() => {});
              }
            }
          }

          return {
            ...item,
            priority: toLegacyNotificationPriority(nextBreakdown.label),
            dispatchScore: Math.max(item.dispatchScore, nextBreakdown.p),
            priorityEngine: nextBreakdown,
          };
        })
      );
    }, 10000);

    return () => clearInterval(timer);
  }, [userPriorityModel]);

  // Wipe volatile signing key seed from RAM on unmount
  useEffect(() => {
    return () => {
      unlockedSigningKeyRef.current?.wipe();
    };
  }, []);

  const handleSecureLogout = () => {
    unlockedSigningKeyRef.current?.wipe();
    setUnlockedSigningKey(null);
    invalidateClientProvenanceCaches();
    globalClientDedupWindow.clearUser(vaultUserId);
    disposeClientEmbedder();
    setDedupThreadsById({});
    setNotifThreadMap({});
    setNotifDecisionMap({});
    onLogout?.();
  };

  // Register volatile ECDH/ECDSA public key bundle & wire Privacy Shield blur listeners
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const token = window.localStorage.getItem('aegis_auth_token');
    void ensureClientEphemeralKeyRing(vaultUserId, token).catch(() => {});

    const onBlur = () => setIsWindowBlurred(true);
    const onFocus = () => setIsWindowBlurred(false);
    const onVisibility = () => setIsWindowBlurred(document.visibilityState !== 'visible');

    window.addEventListener('blur', onBlur);
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.removeEventListener('blur', onBlur);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [vaultUserId]);

  // Audio Notification Toggle & Synthesis for CRITICAL Priority Alerts
  const [audioAlertsEnabled, setAudioAlertsEnabled] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('aegis_audio_alerts_enabled');
      return saved !== null ? saved === 'true' : true;
    }
    return true;
  });
  const audioAlertsRef = useRef<boolean>(audioAlertsEnabled);

  useEffect(() => {
    audioAlertsRef.current = audioAlertsEnabled;
    if (typeof window !== 'undefined') {
      localStorage.setItem('aegis_audio_alerts_enabled', String(audioAlertsEnabled));
    }
  }, [audioAlertsEnabled]);

  // Hydrate User Preferences from localStorage & Firestore when signed into Firebase Auth
  useEffect(() => {
    if (typeof window !== 'undefined') {
      try {
        const localRaw = localStorage.getItem('aegis_user_preferences');
        if (localRaw) {
          const parsed = JSON.parse(localRaw);
          if (typeof parsed.dndEnabled === 'boolean') setDndEnabled(parsed.dndEnabled);
          if (typeof parsed.quietHoursStart === 'string') setQuietHoursStart(parsed.quietHoursStart);
          if (typeof parsed.quietHoursEnd === 'string') setQuietHoursEnd(parsed.quietHoursEnd);
          if (['WEBSOCKET', 'EMAIL', 'SMS', 'WEBPUSH', 'WHATSAPP'].includes(parsed.preferredChannel)) {
            setPreferredChannel(parsed.preferredChannel);
          }
          if (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(parsed.minPriorityThreshold)) {
            setMinPriorityThreshold(parsed.minPriorityThreshold);
          }
          if (typeof parsed.allowCriticalBypassQuietHours === 'boolean') {
            setAllowCriticalBypassQuietHours(parsed.allowCriticalBypassQuietHours);
          }
          if (typeof parsed.optOutPush === 'boolean') setOptOutPush(parsed.optOutPush);
          if (typeof parsed.optOutWhatsapp === 'boolean') setOptOutWhatsapp(parsed.optOutWhatsapp);
          if (typeof parsed.optOutSms === 'boolean') setOptOutSms(parsed.optOutSms);
          if (typeof parsed.optOutEmail === 'boolean') setOptOutEmail(parsed.optOutEmail);
          if (typeof parsed.whatsappPhone === 'string') {
            setWhatsappPhone(parsed.whatsappPhone);
            setChannelTestTargetWhatsapp((prev) => prev || parsed.whatsappPhone);
          }
        }
      } catch {
        // Ignore malformed localStorage preferences
      }
    }

    const unsub = onAuthStateChanged(auth, async (fbUser) => {
      setFirebaseUser(fbUser);
      if (!fbUser) return;
      try {
        await ensureUserProfileInFirestore(fbUser.uid).catch(() => false);
        const prefs = await loadUserPreferencesFromFirestore(fbUser.uid);
        if (prefs) {
          setDndEnabled(prefs.dndEnabled);
          setQuietHoursStart(prefs.quietHoursStart);
          setQuietHoursEnd(prefs.quietHoursEnd);
          setPreferredChannel(prefs.preferredChannel);
          setMinPriorityThreshold(prefs.minPriorityThreshold);
          setAudioAlertsEnabled(prefs.audioAlertsEnabled);
          if (typeof prefs.allowCriticalBypassQuietHours === 'boolean') {
            setAllowCriticalBypassQuietHours(prefs.allowCriticalBypassQuietHours);
          }
          if (typeof prefs.optOutPush === 'boolean') setOptOutPush(prefs.optOutPush);
          if (typeof prefs.optOutWhatsapp === 'boolean') setOptOutWhatsapp(prefs.optOutWhatsapp);
          if (typeof prefs.optOutSms === 'boolean') setOptOutSms(prefs.optOutSms);
          if (typeof prefs.optOutEmail === 'boolean') setOptOutEmail(prefs.optOutEmail);
          if (typeof prefs.whatsappPhone === 'string') {
            setWhatsappPhone(prefs.whatsappPhone);
            setChannelTestTargetWhatsapp((prev) => prev || prefs.whatsappPhone || '');
          }
        }
        const phoneStatus = await loadUserPhoneStatusFromFirestore(fbUser.uid);
        if (phoneStatus?.phoneVerified) {
          setVerifiedPhoneInfo(phoneStatus);
        }
        const fsDedup = await loadDedupSettingsFromFirestore(fbUser.uid).catch(() => null);
        if (fsDedup) {
          setUserDedupSettings((prev) =>
            prev
              ? {
                  ...prev,
                  dedupEnabled: fsDedup.dedupEnabled,
                  mergeThreshold: fsDedup.mergeThreshold,
                  reviewThreshold: fsDedup.reviewThreshold,
                  effectiveMergeThreshold: fsDedup.effectiveMergeThreshold,
                  windowMinutes: fsDedup.windowMinutes,
                  neverMergeCategories: fsDedup.neverMergeCategories,
                }
              : null
          );
        }
      } catch (err) {
        console.warn('[Firestore] Failed to load user preferences:', err);
      }
    });

    void Promise.allSettled([
      fetch('/api/v1/auth/sms/status').then((res) => safeReadJson(res)),
      fetch('/api/v1/auth/otp/send').then((res) => safeReadJson(res)),
      fetch('/api/v1/analytics/health').then((res) => safeReadJson(res)),
    ]).then(([smsRes, otpRes, healthRes]) => {
      const smsData = smsRes.status === 'fulfilled' ? smsRes.value : null;
      const otpData = otpRes.status === 'fulfilled' ? otpRes.value : null;
      const healthData = healthRes.status === 'fulfilled' ? healthRes.value : null;

      if (smsData?.success && smsData?.data) {
        const allowed =
          Array.isArray(smsData.data.allowedCountries) && smsData.data.allowedCountries.length > 0
            ? smsData.data.allowedCountries
            : ['+91'];
        setSmsStatus({
          smsConfigured: Boolean(smsData.data.smsConfigured),
          mode: smsData.data.mode === 'twilio' ? 'twilio' : 'mock',
          demoMode: Boolean(smsData.data.demoMode ?? smsData.data.mode === 'mock'),
          allowedCountries: allowed,
        });
        if (!allowed.includes(phoneLinkCountry)) {
          setPhoneLinkCountry(allowed[0]);
        }
      }

      const persistence = healthData?.persistence || {};
      const dbLive = Boolean(
        persistence.mongodbConnected ||
          persistence.upstashConfigured ||
          persistence.redisConnected ||
          persistence.redisConfigured
      );

      setChannelGatewayStatus({
        loaded: true,
        emailConfigured: Boolean(otpData?.emailConfigured),
        emailSmtpConfigured: Boolean(persistence.emailSmtpConfigured),
        emailVerified: Boolean(otpData?.emailVerified),
        whatsappConfigured: Boolean(persistence.whatsappConfigured),
        fast2smsConfigured: Boolean(otpData?.fast2smsConfigured),
        firebasePhoneAuthConfigured: Boolean(otpData?.firebasePhoneAuthConfigured),
        twilioConfigured: Boolean(smsData?.data?.twilioConfigured),
        smsDemoMode: Boolean(smsData?.data?.demoMode ?? true),
        dbLive,
        dbMode: String(persistence.mode || 'local_json_fallback'),
      });
    });

    return () => unsub();
  }, []);

  useEffect(() => {
    const resolvedEmail = user?.email || firebaseUser?.email || '';
    if (resolvedEmail && !channelTestTargetEmail) {
      setChannelTestTargetEmail(resolvedEmail);
    }
    const resolvedWa = whatsappPhone || user?.phoneNumber || '';
    if (resolvedWa && !channelTestTargetWhatsapp) {
      setChannelTestTargetWhatsapp(resolvedWa);
    }
  }, [user?.email, firebaseUser?.email, whatsappPhone, user?.phoneNumber]);

  useEffect(() => {
    if (phoneLinkCooldown <= 0) return;
    const t = setInterval(() => {
      setPhoneLinkCooldown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(t);
  }, [phoneLinkCooldown]);

  // Check first-run onboarding & privacy consent state per user
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if ('Notification' in window) {
      setWebPushPermission(Notification.permission);
    } else {
      setWebPushPermission('unsupported');
    }

    let cancelled = false;
    void (async () => {
      const state = await loadOnboardingAndConsent(effectiveUserId);
      if (cancelled) return;
      setConsentState(state);
      if (!state || !state.onboardingCompleted) {
        setShowOnboardingModal(true);
      } else {
        setShowOnboardingModal(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [effectiveUserId]);

  const handleSavePreferences = async () => {
    setWhatsappPrefsError(null);
    const cleanWhatsappPhone = whatsappPhone.trim();
    if (cleanWhatsappPhone && !/^\+[1-9]\d{6,14}$/.test(cleanWhatsappPhone)) {
      const msg = 'WhatsApp number must use E.164 format (e.g. +919876543210).';
      setWhatsappPrefsError(msg);
      setPrefsFeedback({ type: 'error', message: msg });
      return;
    }

    setIsSavingPrefs(true);
    setPrefsFeedback(null);
    const snapshot = {
      dndEnabled,
      quietHoursStart,
      quietHoursEnd,
      preferredChannel,
      minPriorityThreshold,
      audioAlertsEnabled,
      allowCriticalBypassQuietHours,
      optOutPush,
      optOutWhatsapp,
      optOutSms,
      optOutEmail,
      whatsappPhone: cleanWhatsappPhone,
    };

    try {
      if (typeof window !== 'undefined') {
        localStorage.setItem('aegis_user_preferences', JSON.stringify(snapshot));
      }

      const authToken =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (authToken) {
        await fetch('/api/v1/users/preferences', {
          method: 'PUT',
          headers: getAegisAuthHeaders(true),
          body: JSON.stringify({
            dndEnabled,
            quietHoursStart,
            quietHoursEnd,
            preferredChannel,
            whatsappPhone: cleanWhatsappPhone,
            optOutWhatsapp,
          }),
        }).catch(() => null);
      }

      if (firebaseUser) {
        await syncFirebaseUserProfile(
          firebaseUser,
          firebaseUser.phoneNumber && !firebaseUser.email ? 'phone' : 'google'
        );
        await saveUserPreferencesToFirestore(firebaseUser.uid, snapshot);
        setPrefsFeedback({
          type: 'success',
          message: 'Preferences saved and synced to Firestore cloud database.',
        });
      } else {
        setPrefsFeedback({
          type: 'success',
          message: 'Preferences saved locally. Sign in with Google or Firebase Phone Auth to sync across devices.',
        });
      }
    } catch (err: any) {
      let msg = err?.message || 'Failed to save preferences.';
      try {
        const parsed = JSON.parse(msg);
        if (parsed?.error) msg = parsed.error;
      } catch {
        // Keep original string
      }
      setPrefsFeedback({ type: 'error', message: msg });
    } finally {
      setIsSavingPrefs(false);
    }
  };

  // Subtle Harmonic Dual-Tone Chime Generator (Web Audio API)
  const playCriticalAlertSound = (force = false) => {
    if (!force && !audioAlertsRef.current) return;
    try {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();

      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const now = ctx.currentTime;

      // Primary Chime: Clean, high-frequency subtle sine tone (A5 -> E6)
      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();

      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(880, now); // A5 (880Hz)
      osc1.frequency.exponentialRampToValueAtTime(1318.51, now + 0.09); // E6 (1318.51Hz)

      gain1.gain.setValueAtTime(0.08, now); // Soft, non-intrusive volume
      gain1.gain.exponentialRampToValueAtTime(0.0001, now + 0.42);

      osc1.connect(gain1);
      gain1.connect(ctx.destination);

      // Warm Subtle Harmonic Undertone
      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();

      osc2.type = 'triangle';
      osc2.frequency.setValueAtTime(440, now);
      osc2.frequency.exponentialRampToValueAtTime(659.25, now + 0.09);

      gain2.gain.setValueAtTime(0.035, now);
      gain2.gain.exponentialRampToValueAtTime(0.0001, now + 0.45);

      osc2.connect(gain2);
      gain2.connect(ctx.destination);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.45);
      osc2.stop(now + 0.45);
    } catch (err) {
      console.warn('[Aegis] Audio alert chime failed to play:', err);
    }
  };

  const getAegisAuthHeaders = (includeJson = false): Record<string, string> => {
    const token =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    return {
      ...(includeJson ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  };

  // Fetch Quarantined Unauthenticated Alerts
  const fetchQuarantine = async () => {
    try {
      const res = await fetch('/api/v1/notifications/quarantine', {
        headers: getAegisAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setQuarantinedAlerts(data.alerts || []);
      }
    } catch (err) {
      console.warn('Failed to load quarantine log:', err);
    }
  };

  // Fetch Integrations
  const fetchIntegrations = async () => {
    try {
      const res = await fetch('/api/v1/integrations', {
        headers: getAegisAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setConnectedApps(data.apps || []);
      }
    } catch (err) {
      console.warn('Failed to load connected apps:', err);
    }
  };

  // Fetch Telemetry & History
  const fetchTelemetry = async () => {
    try {
      const authHeaders = getAegisAuthHeaders();
      const [authRes, metricsRes, historyRes] = await Promise.all([
        fetch('/api/v1/auth/me', { headers: authHeaders }),
        fetch('/api/v1/analytics/metrics', { headers: authHeaders }),
        fetch('/api/v1/notifications/history?limit=30', { headers: authHeaders }),
      ]);

      if (authRes.ok) {
        const authData = await authRes.json();
        if (authData.serverPublicKey) {
          setServerPublicKey(authData.serverPublicKey);
        }
      }

      if (metricsRes.ok) {
        const metricsData = await metricsRes.json();
        setAnalytics(metricsData);
      }

      if (historyRes.ok) {
        const historyData = await historyRes.json();
        if (historyData.logs && historyData.logs.length > 0) {
          const logs = historyData.logs as any[];
          setNotifications((prev) => {
            if (prev.length === 0) {
              return logs.map((log: any) => ({
                notificationId: log._id,
                userId: log.userId,
                eventType: log.eventType,
                rawText: log.rawText,
                dispatchScore: log.dispatchScore,
                priority: log.priority || (log.dispatchScore >= 0.9 ? 'CRITICAL' : log.dispatchScore >= 0.75 ? 'HIGH' : 'MEDIUM'),
                signature: log.signature,
                metadata: log.metadata,
                channelsUsed: log.channelsUsed,
                status: log.status,
                timestamp: log.createdAt,
                verified: Boolean(log.provenanceReport?.verified),
                ackState: log.status === 'ESCALATED_FALLBACK' ? 'TIMEOUT_ESCALATED' : 'ACKED',
                provenanceEnvelope: log.provenanceEnvelope || null,
                provenanceReport: log.provenanceReport || null,
                priorityEngine: log.metadata?.priorityEngine || null,
              }));
            }
            return prev;
          });

          // Independently re-verify every notification's Ed25519 provenance envelope on client device
          for (const log of logs) {
            void verifyItemProvenanceOnClient({
              envelope: log.provenanceEnvelope || null,
              serverReport: log.provenanceReport || null,
              expectedRecipientId: log.provenanceEnvelope?.payload?.recipientId || log.userId,
              expectedMessageId: log._id,
              expectedDigestInput: log.rawText,
              itemTimestamp: log.createdAt,
            }).then((clientReport) => {
              setNotifications((prev) =>
                prev.map((item) =>
                  item.notificationId === log._id
                    ? { ...item, provenanceReport: clientReport, verified: clientReport.verified }
                    : item
                )
              );
            });
          }
        }
      }
    } catch (err) {
      console.warn('Error fetching telemetry:', err);
    }
  };

  // Set Priority of a Notification
  const handleSetPriority = async (notificationId: string, newPriority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') => {
    setUpdatingPriorityId(notificationId);
    try {
      const res = await fetch('/api/v1/notifications/priority', {
        method: 'PATCH',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ notificationId, priority: newPriority }),
      });

      if (res.ok) {
        const data = await res.json();
        setNotifications((prev) =>
          prev.map((n) =>
            n.notificationId === notificationId
              ? { ...n, priority: newPriority, dispatchScore: data.dispatchScore }
              : n
          )
        );
        setPriorityFeedback(`Priority set to ${newPriority}`);
        setTimeout(() => setPriorityFeedback(null), 2500);
      }
    } catch (err) {
      console.warn('Failed to update priority:', err);
    } finally {
      setUpdatingPriorityId(null);
    }
  };

  // Quarantine Action (Dismiss, Block, Whitelist)
  const handleQuarantineAction = async (alertId: string, newStatus: QuarantinedAlert['status']) => {
    try {
      const res = await fetch('/api/v1/notifications/quarantine', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ action: 'UPDATE_STATUS', alertId, newStatus }),
      });

      if (res.ok) {
        setQuarantinedAlerts((prev) =>
          prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
        );
        if (selectedQuarantineAlert?.id === alertId) {
          setSelectedQuarantineAlert({ ...selectedQuarantineAlert, status: newStatus });
        }
      }
    } catch (err) {
      console.warn('Failed to update quarantine status:', err);
    }
  };

  const toggleQuarantineSelection = (alertId: string) => {
    setSelectedQuarantineIds((prev) =>
      prev.includes(alertId) ? prev.filter((id) => id !== alertId) : [...prev, alertId]
    );
  };

  const toggleSelectAllQuarantine = () => {
    if (quarantinedAlerts.length === 0) return;
    const allIds = quarantinedAlerts.map((a) => a.id);
    const allSelected = allIds.every((id) => selectedQuarantineIds.includes(id));
    setSelectedQuarantineIds(allSelected ? [] : allIds);
  };

  const handleBulkDeleteQuarantine = async () => {
    const idsToDelete = selectedQuarantineIds.filter((id) =>
      quarantinedAlerts.some((a) => a.id === id)
    );
    if (idsToDelete.length === 0) {
      setShowBulkDeleteQuarantineModal(false);
      return;
    }

    setIsBulkDeletingQuarantine(true);
    setQuarantineFeedback(null);
    try {
      const res = await fetch('/api/v1/notifications/quarantine', {
        method: 'DELETE',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ alertIds: idsToDelete }),
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data?.success) {
        throw new Error(data?.message || 'Failed to delete selected quarantined items.');
      }

      const deletedSet = new Set<string>(data.deletedIds || idsToDelete);
      if (Array.isArray(data.alerts)) {
        setQuarantinedAlerts(data.alerts);
      } else {
        setQuarantinedAlerts((prev) => prev.filter((a) => !deletedSet.has(a.id)));
      }
      if (selectedQuarantineAlert && deletedSet.has(selectedQuarantineAlert.id)) {
        setSelectedQuarantineAlert(null);
      }
      setSelectedQuarantineIds((prev) => prev.filter((id) => !deletedSet.has(id)));
      setShowBulkDeleteQuarantineModal(false);
      setQuarantineFeedback(
        data.message || `Removed ${deletedSet.size} quarantined item(s) from the security log.`
      );
      setTimeout(() => setQuarantineFeedback(null), 4000);
    } catch (err: any) {
      setQuarantineFeedback(err?.message || 'Unable to delete selected quarantined items.');
      setTimeout(() => setQuarantineFeedback(null), 4000);
    } finally {
      setIsBulkDeletingQuarantine(false);
    }
  };

  const handleExportQuarantineCsv = () => {
    if (quarantinedAlerts.length === 0) return;

    const escapeCsvCell = (rawValue: unknown): string => {
      const str =
        rawValue === null || rawValue === undefined
          ? ''
          : typeof rawValue === 'string'
          ? rawValue
          : JSON.stringify(rawValue);
      // Prevent CSV formula injection in spreadsheet apps
      const formulaSafe = /^[=+\-@\t\r]/.test(str) ? `'${str}` : str;
      return `"${formulaSafe.replace(/"/g, '""')}"`;
    };

    const headers = [
      'ID',
      'Timestamp',
      'Classification',
      'Reason Code',
      'Source App',
      'Source IP',
      'Risk Level',
      'Status',
      'Description',
      'Raw Payload',
    ];

    const rows = quarantinedAlerts.map((alert) =>
      [
        alert.id,
        alert.timestamp,
        alert.reasonLabel,
        alert.reason,
        alert.sourceApp,
        alert.sourceIp,
        alert.riskLevel,
        alert.status,
        alert.description,
        alert.rawPayload,
      ]
        .map(escapeCsvCell)
        .join(',')
    );

    const csvContent = `\uFEFF${[headers.map(escapeCsvCell).join(','), ...rows].join('\r\n')}`;
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const dateStamp = new Date().toISOString().slice(0, 10);

    const link = document.createElement('a');
    link.href = url;
    link.download = `aegis-quarantine-history-${dateStamp}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    setQuarantineFeedback(
      `Exported ${quarantinedAlerts.length} quarantined item(s) to CSV.`
    );
    setTimeout(() => setQuarantineFeedback(null), 4000);
  };

  // Simulate an Unauthenticated / Miscellaneous Threat
  const handleSimulateUnauthenticatedThreat = async () => {
    setIsSimulatingThreat(true);
    setQuarantineFeedback(null);
    try {
      const res = await fetch('/api/v1/notifications/quarantine', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ action: 'SIMULATE' }),
      });
      const data = await safeReadJson(res);
      if (res.ok && data.success && data.alert) {
        setQuarantinedAlerts((prev) => [data.alert, ...prev]);
        setQuarantineFeedback(`Intercepted: ${data.alert.reasonLabel} logged to security quarantine!`);
        setTimeout(() => setQuarantineFeedback(null), 4000);
      }
    } catch (err: any) {
      console.warn('Simulation failed:', err);
    } finally {
      setIsSimulatingThreat(false);
    }
  };

  // Run SMS or Connection Ingest Attack Simulations (isolated test accounts/connections only)
  const handleRunSmsSimulation = async (
    simulationType:
      | 'SMS_BRUTE_FORCE'
      | 'SMS_SEND_FLOOD'
      | 'INGEST_FORGED_SIGNATURE'
      | 'INGEST_REPLAY_TIMESTAMP'
  ) => {
    setIsSimulatingThreat(true);
    setQuarantineFeedback(null);
    try {
      const res = await fetch('/api/v1/notifications/quarantine', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ action: 'SIMULATE', simulationType }),
      });
      const data = await safeReadJson(res);
      if (res.ok && data.success) {
        if (data.alert) {
          setQuarantinedAlerts((prev) => [data.alert, ...prev]);
        } else {
          void fetchQuarantine();
        }
        setQuarantineFeedback(data.message || `${simulationType} simulation completed.`);
        setTimeout(() => setQuarantineFeedback(null), 5000);
      } else {
        setQuarantineFeedback(data.message || 'Attack simulation failed.');
        setTimeout(() => setQuarantineFeedback(null), 4000);
      }
    } catch (err: any) {
      setQuarantineFeedback(`Simulation error: ${err?.message || 'Unknown error'}`);
    } finally {
      setIsSimulatingThreat(false);
    }
  };

  // Simulated manual notification from App Catalog launch-only/manual apps
  const handleSendCatalogSimulatedNotification = async (
    app: CatalogApp,
    title: string,
    message: string
  ) => {
    const res = await fetch('/api/v1/notifications/ingest', {
      method: 'POST',
      headers: getAegisAuthHeaders(true),
      body: JSON.stringify({
        userId: user?.id || 'usr_sec_admin_01',
        eventType: `${app.id.toUpperCase()}_SIMULATED`,
        rawText: `[${app.name} · Simulated] ${message}`,
        priority: 'MEDIUM',
        riskScore: 0.55,
        metadata: {
          appId: app.id,
          appName: app.name,
          title,
          simulated: true,
        },
      }),
    });
    const data = await safeReadJson(res);
    if (!res.ok || !data.success) {
      throw new Error(data.message || 'Unable to dispatch simulated alert.');
    }
    const provStatus = data?.provenance?.status;
    const provTrust: DedupProvenanceTrust =
      provStatus === 'VERIFIED'
        ? 'VERIFIED'
        : provStatus === 'GATEWAY_ATTESTED' || data?.provenance?.badgeVariant === 'gateway'
        ? 'GATEWAY_ATTESTED'
        : 'UNVERIFIED';
    if (data?.notificationId) {
      await runClientDedupAndSyncRef.current({
        notificationId: String(data.notificationId),
        eventType: `${app.id.toUpperCase()}_SIMULATED`,
        rawText: `[${app.name} · Simulated] ${message}`,
        priority: 'MEDIUM',
        sourceId: app.id,
        senderId: user?.id || 'usr_sec_admin_01',
        trust: provTrust,
        verifiedForToast: Boolean(data?.provenance?.verified),
        appName: app.name,
        title,
      });
    }
    fetchTelemetry();
  };

  // Permissions & Privacy actions (Settings tab)
  const handleReRequestNotifications = async () => {
    setPrivacyFeedback(null);
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setWebPushPermission('unsupported');
      setPrivacyFeedback({
        type: 'error',
        message: 'Browser notifications are not supported in this browser.',
      });
      return;
    }
    try {
      const perm = await Notification.requestPermission();
      setWebPushPermission(perm);
      setPrivacyFeedback({
        type: perm === 'granted' ? 'success' : 'error',
        message:
          perm === 'granted'
            ? 'Browser notifications are now allowed.'
            : perm === 'denied'
            ? 'Notifications remain blocked in browser site settings.'
            : 'Notification prompt dismissed without choosing.',
      });
    } catch {
      setPrivacyFeedback({
        type: 'error',
        message: 'Unable to open browser notification prompt.',
      });
    }
  };

  const handleTogglePrivacyConsent = async (grant: boolean) => {
    setPrivacyActionBusy(true);
    setPrivacyFeedback(null);
    try {
      const updated = await saveOnboardingAndConsent(effectiveUserId, {
        allowCatalogAndConnections: grant,
        allowEncryptedConnectionStorage: grant,
        browserNotificationsChoice:
          webPushPermission === 'granted' ||
          webPushPermission === 'denied' ||
          webPushPermission === 'default' ||
          webPushPermission === 'unsupported'
            ? webPushPermission
            : 'default',
        revoked: !grant,
      });
      setConsentState(updated);

      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (token) {
        await fetch('/api/v1/telemetry/client-event', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            eventType: grant ? 'CONSENT_GRANTED' : 'CONSENT_DENIED',
            result: grant ? 'success' : 'blocked',
            details: grant
              ? 'User enabled App Catalog & encrypted connection storage consent in Settings.'
              : 'User revoked App Catalog & encrypted connection storage consent in Settings.',
          }),
        }).catch(() => {});
      }

      setPrivacyFeedback({
        type: 'success',
        message: grant
          ? 'Consent granted. App Catalog & Connections enabled.'
          : 'Consent revoked. Creating new connections is now disabled.',
      });
    } catch (err: any) {
      setPrivacyFeedback({
        type: 'error',
        message: err?.message || 'Unable to update privacy consent.',
      });
    } finally {
      setPrivacyActionBusy(false);
    }
  };

  const handleDisconnectAllConnections = async () => {
    setPrivacyActionBusy(true);
    setPrivacyFeedback(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch('/api/v1/connections?scope=all', {
        method: 'DELETE',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data.success) {
        setPrivacyFeedback({
          type: 'error',
          message: data.message || 'Could not disconnect server connections.',
        });
        return;
      }
      setCatalogConnectionsVersion((v) => v + 1);
      setPrivacyFeedback({
        type: 'success',
        message: data.message || 'All connections disconnected.',
      });
    } catch (err: any) {
      setPrivacyFeedback({
        type: 'error',
        message: err?.message || 'Error disconnecting connections.',
      });
    } finally {
      setPrivacyActionBusy(false);
    }
  };

  const handleDeleteAllConnectionData = async () => {
    setPrivacyActionBusy(true);
    setPrivacyFeedback(null);
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      await fetch('/api/v1/connections?scope=all', {
        method: 'DELETE',
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      }).catch(() => {});

      clearLocalCatalogStates(effectiveUserId);
      await deleteAllAppCatalogStatesInFirestore(effectiveUserId).catch(() => {});

      const updated = await saveOnboardingAndConsent(effectiveUserId, {
        allowCatalogAndConnections: false,
        allowEncryptedConnectionStorage: false,
        browserNotificationsChoice: 'default',
        revoked: true,
      });
      setConsentState(updated);
      setCatalogConnectionsVersion((v) => v + 1);

      if (token) {
        await fetch('/api/v1/telemetry/client-event', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            eventType: 'CONSENT_DENIED',
            result: 'blocked',
            details: 'User deleted all connection data, app catalog states, and revoked consent.',
          }),
        }).catch(() => {});
      }

      setPrivacyFeedback({
        type: 'success',
        message: 'All connection secrets, saved app statuses, and catalog consents deleted.',
      });
    } catch (err: any) {
      setPrivacyFeedback({
        type: 'error',
        message: err?.message || 'Failed to delete connection data.',
      });
    } finally {
      setPrivacyActionBusy(false);
    }
  };

  const fullLinkPhone = `${phoneLinkCountry}${phoneLinkInput.trim().replace(/\D/g, '')}`;

  // Settings: Send SMS verification code to link phone number
  const handleSendPhoneLinkSms = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setPhoneLinkFeedback(null);
    const digits = phoneLinkInput.trim().replace(/\D/g, '');
    if (digits.length < 7) {
      setPhoneLinkFeedback({ type: 'error', message: 'Please enter a valid mobile number.' });
      return;
    }

    setIsSendingLinkSms(true);
    try {
      const res = await fetch('/api/v1/auth/sms/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: fullLinkPhone }),
      });
      const data = await safeReadJson(res);
      if (!res.ok || !data.success) {
        if (data.data?.cooldownSeconds) {
          setPhoneLinkCooldown(data.data.cooldownSeconds);
        }
        setPhoneLinkFeedback({
          type: 'error',
          message: data.message || 'Unable to send SMS code.',
        });
        return;
      }

      setPhoneLinkStep('verify');
      setPhoneLinkCode('');
      setPhoneLinkCooldown(data.data?.cooldownSeconds || 60);
      setPhoneLinkFeedback({
        type: 'success',
        message: data.message || `SMS verification code sent to ${data.data?.maskedPhone || fullLinkPhone}.`,
      });
    } catch (err: any) {
      setPhoneLinkFeedback({
        type: 'error',
        message: `Network error: ${err?.message || 'Failed to send SMS code.'}`,
      });
    } finally {
      setIsSendingLinkSms(false);
    }
  };

  // Settings: Verify 6-digit SMS code and link phone to Firestore + server account
  const handleVerifyPhoneLinkSms = async (e: React.FormEvent) => {
    e.preventDefault();
    setPhoneLinkFeedback(null);
    const cleanCode = phoneLinkCode.trim().replace(/\D/g, '');
    if (cleanCode.length !== 6) {
      setPhoneLinkFeedback({ type: 'error', message: 'Please enter the exact 6-digit SMS code.' });
      return;
    }

    setIsVerifyingLinkSms(true);
    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch('/api/v1/auth/sms/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          phone: fullLinkPhone,
          code: cleanCode,
          linkOnly: true,
          email: user?.email || firebaseUser?.email || undefined,
          displayName: firebaseUser?.displayName || undefined,
          firebaseUid: firebaseUser?.uid || undefined,
        }),
      });

      const data = await safeReadJson(res);
      if (!res.ok || !data.success) {
        setPhoneLinkFeedback({
          type: 'error',
          message: data.message || 'SMS verification failed.',
        });
        return;
      }

      const masked = data.data?.maskedPhone || fullLinkPhone;
      const hash = data.data?.phoneHash;

      if (firebaseUser && hash) {
        await linkVerifiedPhoneInFirestore(firebaseUser.uid, masked, hash).catch((err) => {
          console.warn('[Firestore] Phone link sync warning:', err);
        });
      }

      if (typeof window !== 'undefined') {
        try {
          const rawUser = localStorage.getItem('aegis_user');
          if (rawUser) {
            const parsedUser = JSON.parse(rawUser);
            parsedUser.phoneNumber = masked;
            parsedUser.phoneVerified = true;
            localStorage.setItem('aegis_user', JSON.stringify(parsedUser));
          }
        } catch {
          // ignore storage error
        }
      }

      setVerifiedPhoneInfo({ phoneVerified: true, maskedPhone: masked });
      setPhoneLinkStep('enter');
      setPhoneLinkCode('');
      setPhoneLinkFeedback({
        type: 'success',
        message: `Phone ${masked} verified and linked! You can now sign in with SMS OTP.`,
      });
    } catch (err: any) {
      setPhoneLinkFeedback({
        type: 'error',
        message: `Verification error: ${err?.message || 'Unexpected error.'}`,
      });
    } finally {
      setIsVerifyingLinkSms(false);
    }
  };

  // Quick numeric-only online feedback for a notification
  const handleQuickPriorityFeedback = async (
    notif: NotificationItem,
    feedbackKind: PriorityFeedbackKind
  ) => {
    if (!notif.priorityEngine?.features) return;
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (!token) {
        setPriorityFeedback('Sign in to record priority feedback.');
        setTimeout(() => setPriorityFeedback(null), 2500);
        return;
      }
      const res = await fetch('/api/v1/priority/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          feedbackKind,
          features: notif.priorityEngine.features,
        }),
      });
      const json = await safeReadJson(res);
      if (res.ok && json?.success && json?.data?.updatedState) {
        setUserPriorityModel(json.data.updatedState);
        setPriorityFeedback(
          `Feedback recorded (${feedbackKind}) · ${json.data.updatedState.feedbackCount} samples · Mode: ${json.data.activeMode}`
        );
        setTimeout(() => setPriorityFeedback(null), 3000);
      }
    } catch {
      // ignore transient errors
    }
  };

  // Acknowledge notification (and immediately freeze dynamic age escalation)
  const handleAck = async (notificationId: string) => {
    try {
      const res = await fetch(`/api/v1/notifications/ack/${notificationId}`, {
        method: 'POST',
        headers: getAegisAuthHeaders(),
      });
      if (res.ok) {
        setNotifications((prev) =>
          prev.map((n) => {
            if (n.notificationId !== notificationId) return n;
            const frozenBreakdown = n.priorityEngine
              ? rescorePriorityOnRecipientDevice({
                  baseFeatures: n.priorityEngine.features,
                  provenanceEnvelope: n.provenanceEnvelope,
                  provenanceVerified: Boolean(n.provenanceReport?.verified),
                  elapsedSeconds: 0,
                  isAcked: true,
                  previousLabel: n.priorityEngine.label,
                })
              : n.priorityEngine;
            return {
              ...n,
              ackState: 'ACKED',
              status: 'DISPATCHED_PRIMARY',
              priorityEngine: frozenBreakdown,
            };
          })
        );
      }
    } catch (err) {
      console.warn('ACK error:', err);
    }
  };

  // Deduplication Thread Controls (Ungroup, Not a Duplicate, Manual Merge)
  const syncRamThreadsIntoState = () => {
    const list = globalClientDedupWindow.getThreadMetadataList(vaultUserId);
    const nextThreads: Record<string, DedupThreadMetadata> = {};
    const nextMap: Record<string, string> = {};
    for (const thr of list) {
      nextThreads[thr.threadId] = thr;
      for (const mid of thr.memberIds) {
        nextMap[mid] = thr.threadId;
      }
    }
    setDedupThreadsById((prev) => ({ ...prev, ...nextThreads }));
    setNotifThreadMap((prev) => ({ ...prev, ...nextMap }));
  };

  const handleUngroupThread = async (threadId: string) => {
    const splitThreads = globalClientDedupWindow.ungroupThread(vaultUserId, threadId);
    if (splitThreads.length > 0) {
      setDedupThreadsById((prev) => {
        const copy = { ...prev };
        delete copy[threadId];
        for (const t of splitThreads) copy[t.threadId] = t;
        return copy;
      });
      setNotifThreadMap((prev) => {
        const copy = { ...prev };
        for (const t of splitThreads) {
          for (const mid of t.memberIds) copy[mid] = t.threadId;
        }
        return copy;
      });
    }

    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch(
        `/api/v1/dedup/threads/${encodeURIComponent(threadId)}/ungroup`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify({}),
        }
      );
      const json = await safeReadJson(res);
      if (res.ok && json?.data?.settings) {
        setUserDedupSettings(json.data.settings);
      }
      if (firebaseUidRef.current) {
        void deleteDedupThreadFromFirestore(firebaseUidRef.current, threadId).catch(() => {});
      }
      setPriorityFeedback('Thread ungrouped into separate alerts and personal threshold adapted.');
      setTimeout(() => setPriorityFeedback(null), 3000);
      fetchTelemetry();
    } catch {
      // non-fatal
    }
  };

  const handleMarkNotDuplicate = async (threadId: string) => {
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      const res = await fetch('/api/v1/dedup/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          feedbackKind: 'NOT_DUPLICATE',
          threadId,
        }),
      });
      const json = await safeReadJson(res);
      if (res.ok && json?.data?.settings) {
        setUserDedupSettings(json.data.settings);
      }
      const meta = dedupThreadsById[threadId];
      if (meta && meta.memberCount > 1) {
        await handleUngroupThread(threadId);
      } else {
        setPriorityFeedback('Feedback recorded ("Not a duplicate"). Merge threshold tightened.');
        setTimeout(() => setPriorityFeedback(null), 3000);
      }
    } catch {
      // non-fatal
    }
  };

  const handleManualMergeThreads = async (
    targetThreadId: string,
    sourceThreadId: string,
    similarity: number
  ) => {
    const merged = globalClientDedupWindow.mergeTwoThreads(
      vaultUserId,
      targetThreadId,
      sourceThreadId,
      similarity
    );
    if (!merged) return;
    syncRamThreadsIntoState();
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      await fetch('/api/v1/dedup/threads', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          action: 'MERGE',
          stageMatched: merged.stageMatched,
          similarity: merged.lastSimilarity,
          notificationId: merged.memberIds[merged.memberIds.length - 1],
          threadMetadata: merged,
        }),
      });
      await fetch('/api/v1/dedup/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          feedbackKind: 'CONFIRM_MERGE',
          threadId: merged.threadId,
        }),
      });
      if (firebaseUidRef.current) {
        void syncDedupThreadToFirestore(firebaseUidRef.current, merged).catch(() => {});
        void deleteDedupThreadFromFirestore(firebaseUidRef.current, sourceThreadId).catch(() => {});
      }
      setPriorityFeedback(`Merged related alerts into ${merged.threadId} (${merged.memberCount} items).`);
      setTimeout(() => setPriorityFeedback(null), 3000);
      fetchTelemetry();
    } catch {
      // non-fatal
    }
  };

  // Toggle App Enabled
  const handleToggleApp = async (app: ConnectedApp) => {
    try {
      const updatedEnabled = !app.enabled;
      const res = await fetch(`/api/v1/integrations/${app.id}`, {
        method: 'PUT',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ enabled: updatedEnabled }),
      });
      if (res.ok) {
        setConnectedApps((prev) =>
          prev.map((a) => (a.id === app.id ? { ...a, enabled: updatedEnabled } : a))
        );
      }
    } catch (err) {
      console.warn('Failed to toggle app:', err);
    }
  };

  // Update App Rules
  const handleUpdateAppRules = async (appId: string, rulePatch: Partial<ConnectedApp['rules']>) => {
    const targetApp = connectedApps.find((a) => a.id === appId);
    if (!targetApp) return;

    const newRules = { ...targetApp.rules, ...rulePatch };
    try {
      const res = await fetch(`/api/v1/integrations/${appId}`, {
        method: 'PUT',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ rules: newRules }),
      });
      if (res.ok) {
        setConnectedApps((prev) =>
          prev.map((a) => (a.id === appId ? { ...a, rules: newRules } : a))
        );
        if (selectedApp?.id === appId) {
          setSelectedApp({ ...selectedApp, rules: newRules });
        }
      }
    } catch (err) {
      console.warn('Failed to update app rules:', err);
    }
  };

  // Send Test Alert from Connected App
  const handleTestApp = async (appId: string) => {
    setTestingAppId(appId);
    try {
      const res = await fetch('/api/v1/integrations/test', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ appId }),
      });
      if (res.ok) {
        fetchIntegrations();
        fetchTelemetry();
      }
    } catch (err: any) {
      console.warn('Test failed:', err);
    } finally {
      setTestingAppId(null);
    }
  };

  // Manual notification dispatch (supports isolated Ephemeral Mode with client-side ECDH + AES-GCM)
  const handleManualSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingSim(true);
    setSimResult(null);

    try {
      if (simEphemeralMode) {
        const authToken =
          typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
        if (!authToken) {
          throw new Error('Authentication session missing. Please sign in again.');
        }

        const senderId = vaultUserId;
        const recipientId = simEphemeralRecipientId.trim() || senderId;
        const ownKeyRing = await ensureClientEphemeralKeyRing(senderId, authToken);
        const recipientPubJwk = await resolveRecipientEcdhPublicJwk(
          recipientId,
          senderId,
          ownKeyRing,
          authToken
        );

        const ephId = `eph_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
        const plaintextBody = simOtp.trim()
          ? `[${simApp.toUpperCase()}] ${simTitle} · Code: ${simOtp.trim()}`
          : `[${simApp.toUpperCase()}] ${simTitle}`;
        const approxExpIso = new Date(Date.now() + simEphemeralTtl * 1000).toISOString();

        const encrypted = await encryptAndWrapEphemeralMessage({
          id: ephId,
          senderId,
          recipientId,
          priority: simUrgency,
          expiresAt: approxExpIso,
          readOnce: simEphemeralReadOnce,
          plaintext: plaintextBody,
          senderKeyRing: ownKeyRing,
          recipientEcdhPublicJwk: recipientPubJwk,
        });

        const ephProvenanceEnvelope =
          unlockedSigningKey && !unlockedSigningKey.isWiped()
            ? await createSignedProvenanceEnvelopeBrowser({
                unlockedKey: unlockedSigningKey,
                messageId: ephId,
                recipientId,
                source: 'ephemeral',
                priority: simUrgency,
                ciphertext: encrypted.envelope.ciphertext,
                iv: encrypted.envelope.iv,
                ttlSeconds: simEphemeralTtl,
                expiresAt: approxExpIso,
              })
            : null;

        const fbIdToken = firebaseUser ? await firebaseUser.getIdToken().catch(() => null) : null;
        const res = await fetch('/api/v1/ephemeral', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${authToken}`,
            ...(fbIdToken ? { 'X-Firebase-Id-Token': fbIdToken } : {}),
          },
          body: JSON.stringify({
            id: ephId,
            recipientId,
            ciphertext: encrypted.envelope.ciphertext,
            iv: encrypted.envelope.iv,
            signature: encrypted.envelope.signature,
            wrappedDek: encrypted.keyMaterial.wrappedDek,
            wrapIv: encrypted.keyMaterial.wrapIv,
            senderEcdhPubJwk: encrypted.envelope.senderEcdhPubJwk,
            senderEcdsaPubJwk: encrypted.envelope.senderEcdsaPubJwk,
            ...(ephProvenanceEnvelope ? { provenanceEnvelope: ephProvenanceEnvelope } : {}),
            priority: simUrgency,
            ttlSeconds: simEphemeralTtl,
            readOnce: simEphemeralReadOnce,
            deliverAlert: trackInDeliveryPipeline,
            recipientEmail: user?.email || firebaseUser?.email || channelTestTargetEmail,
            recipientPhone: channelTestTargetPhone || activeTargetPhoneDisplay || user?.phoneNumber,
            recipientWhatsappPhone:
              channelTestTargetWhatsapp || whatsappPhone || user?.phoneNumber || undefined,
            userPreferences: {
              dndEnabled,
              quietHoursStart,
              quietHoursEnd,
              preferredChannel,
              allowCriticalBypassQuietHours,
              optOutPush,
              optOutWhatsapp,
              optOutSms,
              optOutEmail,
            },
          }),
        });

        const data = await safeReadJson(res);
        if (!res.ok || !data?.success) {
          throw new Error(data?.message || `Ephemeral upload failed (HTTP ${res.status}).`);
        }

        setSimResult({
          success: true,
          ephemeral: true,
          message: data.message,
          pipelineJob: data.data?.deliveryJob || null,
        });
        setEphemeralRefreshTick((v) => v + 1);
        return;
      }

      const riskMapping: Record<string, number> = {
        LOW: 0.2,
        MEDIUM: 0.5,
        HIGH: 0.85,
        CRITICAL: 0.98,
      };

      const notifId = `notif_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const targetUserId = vaultUserId;
      const rawText = `[${simApp.toUpperCase()}] ${simTitle}`;
      const inMemoryTextSignal = computeTextImportanceScore(
        rawText,
        userPriorityModel?.urgentKeywords || []
      );
      const directProvenanceEnvelope =
        unlockedSigningKey && !unlockedSigningKey.isWiped()
          ? await createSignedProvenanceEnvelopeBrowser({
              unlockedKey: unlockedSigningKey,
              messageId: notifId,
              recipientId: targetUserId,
              source: simApp || 'direct',
              priority: simUrgency,
              ciphertext: rawText,
              iv: '',
              textScore: inMemoryTextSignal.textScore,
              signedPriorityLabel: simUrgency,
            })
          : null;

      const payload: Record<string, any> = {
        notificationId: notifId,
        userId: targetUserId,
        eventType: `${simApp.toUpperCase()}_ALERT`,
        rawText,
        priority: simUrgency,
        riskScore: riskMapping[simUrgency] || 0.6,
        recipientPhone: channelTestTargetPhone || activeTargetPhoneDisplay || user?.phoneNumber,
        metadata: {
          simulated: true,
          appId: simApp,
        },
        ...(directProvenanceEnvelope ? { provenanceEnvelope: directProvenanceEnvelope } : {}),
      };

      if (simOtp.trim()) {
        payload.otp = simOtp.trim();
      }

      const res = await fetch('/api/v1/notifications/ingest', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        setSimResult({
          success: false,
          status: data?.status,
          error: data?.message || data?.error || `Ingest rejected (HTTP ${res.status})`,
        });
        fetchTelemetry();
        return;
      }
      let pipelineJobInfo: { id: string; state: string; channel: string } | null = null;

      if (trackInDeliveryPipeline && data?.success && data?.status !== 'DEDUPLICATED') {
        try {
          const authToken =
            typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
          if (authToken) {
            const fbIdToken = firebaseUser ? await firebaseUser.getIdToken().catch(() => null) : null;
            const jobRes = await fetch('/api/v1/delivery/jobs', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${authToken}`,
                ...(fbIdToken ? { 'X-Firebase-Id-Token': fbIdToken } : {}),
              },
              body: JSON.stringify({
                notificationId: data.notificationId || `notif_${Date.now()}`,
                userId: effectiveUserId,
                priority: simUrgency,
                title: simTitle,
                sourceApp: simApp,
                recipientEmail: user?.email || firebaseUser?.email || channelTestTargetEmail,
                recipientPhone: channelTestTargetPhone || activeTargetPhoneDisplay || user?.phoneNumber,
                recipientWhatsappPhone:
                  channelTestTargetWhatsapp || whatsappPhone || user?.phoneNumber || undefined,
                userPreferences: {
                  dndEnabled,
                  quietHoursStart,
                  quietHoursEnd,
                  preferredChannel,
                  allowCriticalBypassQuietHours,
                  optOutPush,
                  optOutWhatsapp,
                  optOutSms,
                  optOutEmail,
                },
              }),
            });
            const jobData = await safeReadJson(jobRes);
            if (jobRes.ok && jobData?.success && jobData?.data?.job) {
              const job = jobData.data.job;
              pipelineJobInfo = { id: job.id, state: job.state, channel: job.channel };
              if (firebaseUser) {
                void syncDeliveryJobToFirestore(firebaseUser.uid, job).catch(() => {});
              }
            }
          }
        } catch {
          // Non-fatal pipeline sync
        }
      }

      setSimResult({ ...data, pipelineJob: pipelineJobInfo });
      const ingestTrust: DedupProvenanceTrust =
        data?.provenance?.badgeVariant === 'verified'
          ? 'VERIFIED'
          : data?.provenance?.badgeVariant === 'gateway' ||
            data?.provenance?.status === 'GATEWAY_ATTESTED'
          ? 'GATEWAY_ATTESTED'
          : 'UNVERIFIED';
      const resolvedPriority = (
        ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(String(data?.priority || simUrgency))
          ? String(data?.priority || simUrgency)
          : simUrgency
      ) as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

      await runClientDedupAndSyncRef.current({
        notificationId: String(data?.notificationId || notifId),
        eventType: payload.eventType,
        rawText,
        priority: resolvedPriority,
        sourceId: simApp || 'direct',
        senderId: targetUserId,
        trust: ingestTrust,
        isPriorityFloorAlert: Boolean(
          data?.priorityEngine?.appliedRules?.some((r: any) => r.rule === 'SECURITY_FLOOR') ||
            resolvedPriority === 'CRITICAL'
        ),
        verifiedForToast: Boolean(data?.provenance?.verified),
      });

      fetchTelemetry();
      fetchIntegrations();
    } catch (err: any) {
      setSimResult({ error: err.message });
    } finally {
      setIsSubmittingSim(false);
    }
  };

  // Set and persist FAST2SMS_TARGET_PHONE to the user's mobile number
  const handleSaveFast2SmsTargetPhone = async (phoneToSave?: string) => {
    const rawNumber = (phoneToSave !== undefined ? phoneToSave : channelTestTargetPhone).trim();
    if (!rawNumber) return;
    setIsSavingTargetPhone(true);
    setSavePhoneFeedback(null);
    try {
      const res = await fetch('/api/v1/notifications/fallback/target-phone', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ targetPhone: rawNumber }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActiveTargetPhoneDisplay(data.targetPhone);
        setChannelTestTargetPhone(data.targetPhone);
        setSavePhoneFeedback('FAST2SMS_TARGET_PHONE updated!');
        setTimeout(() => setSavePhoneFeedback(null), 3500);
      } else {
        setSavePhoneFeedback(data.message || 'Failed to update target phone');
      }
    } catch (err: any) {
      setSavePhoneFeedback(`Failed: ${err.message}`);
    } finally {
      setIsSavingTargetPhone(false);
    }
  };

  // Test Fallback Channels (Nodemailer, WebPush, WhatsApp Cloud API, Fast2SMS)
  const handleTestFallbackChannel = async (
    channel: 'EMAIL' | 'WEBPUSH' | 'FAST2SMS' | 'WHATSAPP' | 'ALL'
  ) => {
    setTestingChannel(channel);
    setChannelTestResult(null);
    try {
      const targetPhoneForTest =
        channel === 'WHATSAPP'
          ? channelTestTargetWhatsapp || whatsappPhone || channelTestTargetPhone
          : channel === 'ALL'
          ? channelTestTargetWhatsapp || whatsappPhone || channelTestTargetPhone
          : channelTestTargetPhone;
      const res = await fetch('/api/v1/notifications/fallback/test', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({
          channel,
          targetEmail: channelTestTargetEmail,
          targetPhone: targetPhoneForTest,
          title: 'Aegis Sentinel Security Test',
          message:
            'Direct verification dispatch for Nodemailer Email, WebPush, WhatsApp Cloud API, and Fast2SMS channels.',
        }),
      });
      const data = await res.json();
      setChannelTestResult(data);
      if (data.targetPhone && channel !== 'WHATSAPP') {
        setActiveTargetPhoneDisplay(data.targetPhone);
      }
    } catch (err: any) {
      setChannelTestResult({ error: err.message });
    } finally {
      setTestingChannel(null);
    }
  };

  // Subscribe to Instant WebPush Device Notifications via Service Worker
  const handleSubscribeWebPush = async () => {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
      alert('WebPush is not supported on this browser.');
      return;
    }

    try {
      const permission = await Notification.requestPermission();
      setWebPushPermission(permission);

      if (permission !== 'granted') {
        alert('Notification permission was not granted.');
        return;
      }

      // Fetch VAPID public key
      const keyRes = await fetch('/api/v1/users/push-subscription', {
        headers: getAegisAuthHeaders(),
      });
      const keyData = await keyRes.json();
      const vapidPublicKey = keyData.vapidPublicKey;

      if (!vapidPublicKey) {
        alert('VAPID public key not available from server.');
        return;
      }

      // Register Service Worker
      const reg = await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;

      // Convert VAPID key to Uint8Array
      const padding = '='.repeat((4 - (vapidPublicKey.length % 4)) % 4);
      const base64 = (vapidPublicKey + padding).replace(/\-/g, '+').replace(/_/g, '/');
      const rawData = window.atob(base64);
      const outputArray = new Uint8Array(rawData.length);
      for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
      }

      // Subscribe to PushManager
      const subscription = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: outputArray,
      });

      // Send subscription to server
      const subJson = subscription.toJSON();
      await fetch('/api/v1/users/push-subscription', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({
          userId: user?.id || 'usr_sec_admin_01',
          subscription: subJson,
        }),
      });

      setIsSubscribedPush(true);
      // Trigger a local test alert
      new Notification('🛡️ Aegis Sentinel WebPush Active', {
        body: 'Device-level instant notification alerts are now paired and enabled.',
        icon: '/assets/logo.png',
      });
    } catch (err: any) {
      console.warn('WebPush registration failed:', err);
      alert(`Push setup note: ${err.message}`);
    }
  };

  // Add new Custom Integration
  const handleAddNewApp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAppName.trim()) return;

    try {
      const res = await fetch('/api/v1/integrations', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({
          name: newAppName.trim(),
          category: newAppCategory,
          description: newAppDesc.trim() || 'Custom application connection',
        }),
      });

      if (res.ok) {
        setShowAddAppModal(false);
        setNewAppName('');
        setNewAppDesc('');
        fetchIntegrations();
      }
    } catch (err) {
      console.warn('Failed to add app:', err);
    }
  };

  // Sync FAST2SMS_TARGET_PHONE with user mobile number
  useEffect(() => {
    const fetchTargetPhone = async () => {
      try {
        const res = await fetch('/api/v1/notifications/fallback/target-phone', {
          headers: getAegisAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          if (data.targetPhone) {
            setActiveTargetPhoneDisplay(data.targetPhone);
            setChannelTestTargetPhone((prev) => (!prev || prev === '9876543210' ? data.targetPhone : prev));
          }
        }
      } catch (err) {
        console.warn('Failed to load target phone:', err);
      }
    };

    if (user?.phoneNumber) {
      setChannelTestTargetPhone(user.phoneNumber);
      setActiveTargetPhoneDisplay(user.phoneNumber);
      fetch('/api/v1/notifications/fallback/target-phone', {
        method: 'POST',
        headers: getAegisAuthHeaders(true),
        body: JSON.stringify({ targetPhone: user.phoneNumber }),
      }).catch(() => {});
    } else {
      fetchTargetPhone();
    }
  }, [user?.phoneNumber]);

  // WebSocket Connection
  useEffect(() => {
    fetchTelemetry();
    fetchIntegrations();
    fetchQuarantine();
    const interval = setInterval(() => {
      fetchTelemetry();
      fetchQuarantine();
    }, 7000);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUserId = user?.id || 'usr_sec_admin_01';
    const wsToken =
      typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
    const wsUrl = `${protocol}//${window.location.host}/ws?userId=${encodeURIComponent(wsUserId)}${
      wsToken ? `&token=${encodeURIComponent(wsToken)}` : ''
    }`;

    const connectWs = () => {
      setSocketStatus('CONNECTING');
      try {
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => setSocketStatus('CONNECTED');

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);

            if (data.type === 'NOTIFICATION_DISPATCH') {
              const determinedPriority =
                data.priority ||
                (data.dispatchScore >= 0.9 ? 'CRITICAL' : data.dispatchScore >= 0.75 ? 'HIGH' : 'MEDIUM');

              const newItem: NotificationItem = {
                notificationId: data.notificationId,
                userId: data.userId,
                eventType: data.eventType,
                rawText: data.rawText,
                dispatchScore: data.dispatchScore,
                priority: determinedPriority,
                signature: data.signature,
                sanitizedPayload: data.sanitizedPayload,
                metadata: data.sanitizedPayload?.metadata,
                channelsUsed: ['WEBSOCKET'],
                status: 'DISPATCHED_PRIMARY',
                timestamp: data.timestamp || new Date().toISOString(),
                verified: Boolean(data.provenanceReport?.verified),
                ackState: 'PENDING',
                provenanceEnvelope: data.provenanceEnvelope || null,
                provenanceReport: data.provenanceReport || null,
                priorityEngine:
                  data.priorityEngine || data.sanitizedPayload?.metadata?.priorityEngine || null,
              };

              setNotifications((prev) => [newItem, ...prev.slice(0, 49)]);

              // Verify Ed25519 provenance FIRST on recipient device, then run On-Device ONNX Dedup Pipeline in RAM
              void verifyItemProvenanceOnClient({
                envelope: newItem.provenanceEnvelope,
                serverReport: newItem.provenanceReport,
                expectedRecipientId:
                  newItem.provenanceEnvelope?.payload?.recipientId || newItem.userId,
                expectedMessageId: newItem.notificationId,
                expectedDigestInput: newItem.rawText,
                itemTimestamp: newItem.timestamp,
              }).then(async (clientReport) => {
                setNotifications((prev) =>
                  prev.map((item) =>
                    item.notificationId === newItem.notificationId
                      ? { ...item, provenanceReport: clientReport, verified: clientReport.verified }
                      : item
                  )
                );

                const effectiveTrust: DedupProvenanceTrust =
                  clientReport.badgeVariant === 'gateway'
                    ? 'GATEWAY_ATTESTED'
                    : clientReport.verified
                    ? 'VERIFIED'
                    : 'UNVERIFIED';

                const decision = await runClientDedupAndSyncRef.current({
                  notificationId: newItem.notificationId,
                  eventType: String(data.eventType || 'DIRECT'),
                  rawText: String(data.rawText || ''),
                  priority: (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(determinedPriority)
                    ? determinedPriority
                    : 'MEDIUM') as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
                  sourceId: String(
                    newItem.metadata?.appId || newItem.eventType || 'direct'
                  ),
                  senderId: String(
                    newItem.provenanceEnvelope?.payload?.senderId ||
                      newItem.metadata?.appId ||
                      'gateway'
                  ),
                  timestamp: newItem.timestamp,
                  categoryHint: String(data.sanitizedPayload?.metadata?.category || ''),
                  isEphemeral: Boolean(newItem.metadata?.isEphemeral),
                  isPriorityFloorAlert: Boolean(
                    newItem.priorityEngine?.appliedRules?.some(
                      (r) => r.rule === 'SECURITY_FLOOR'
                    ) || determinedPriority === 'CRITICAL'
                  ),
                  trust: effectiveTrust,
                  provenanceFailed: clientReport.badgeVariant === 'rejected',
                  verifiedForToast: clientReport.verified,
                  appName: data.sanitizedPayload?.metadata?.appName,
                  title: data.sanitizedPayload?.metadata?.title,
                  sendBrowserNotification: true,
                });

                if (decision) {
                  setNotifications((prev) =>
                    prev.map((item) =>
                      item.notificationId === newItem.notificationId
                        ? { ...item, dedupThreadId: decision.threadId, dedupDecision: decision }
                        : item
                    )
                  );
                }

                fetchTelemetry();
              });

              if (autoAck) {
                handleAck(data.notificationId);
              }
            } else if (data.type === 'FALLBACK_ESCALATION_TRIGGERED') {
              setNotifications((prev) =>
                prev.map((item) =>
                  item.notificationId === data.notificationId
                    ? {
                        ...item,
                        status: 'ESCALATED_FALLBACK',
                        channelsUsed: data.escalatedChannels || ['EMAIL', 'WEBPUSH', 'FAST2SMS'],
                        ackState: 'TIMEOUT_ESCALATED',
                      }
                    : item
                )
              );
            } else if (data.type === 'NOTIFICATION_PRIORITY_UPDATED') {
              setNotifications((prev) =>
                prev.map((item) =>
                  item.notificationId === data.notificationId
                    ? {
                        ...item,
                        priority: data.priority,
                        dispatchScore: data.dispatchScore,
                      }
                    : item
                )
              );
            }
          } catch (e) {
            console.warn('[WS] Error processing alert message:', e);
          }
        };

        ws.onerror = () => setSocketStatus('DISCONNECTED');
        ws.onclose = () => {
          setSocketStatus('DISCONNECTED');
          reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
        };
      } catch {
        setSocketStatus('DISCONNECTED');
        reconnectTimeoutRef.current = setTimeout(connectWs, 3000);
      }
    };

    connectWs();

    return () => {
      if (socketRef.current) socketRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      clearInterval(interval);
    };
  }, [autoAck]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const renderAppIcon = (iconName: string, className = 'w-4 h-4') => {
    return <NothingAppLogo name={iconName} className={className} size={18} />;
  };

  // Filtered Notifications based on priority & search & threshold
  const priorityWeight: Record<string, number> = {
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
  };

  const filteredNotifications = notifications
    .filter((n) => {
      const rawPriority =
        n.priority ||
        (n.dispatchScore >= 0.9 ? 'CRITICAL' : n.dispatchScore >= 0.75 ? 'HIGH' : 'MEDIUM');
      const itemPriority =
        (rawPriority as string) === 'NORMAL' ? 'MEDIUM' : rawPriority;

      // Priority filter check
      if (priorityFilter !== 'ALL' && itemPriority !== priorityFilter) {
        return false;
      }

      // Minimum Threshold check
      const minWeight = priorityWeight[minPriorityThreshold] || 1;
      const currentWeight = priorityWeight[itemPriority] || 2;
      if (currentWeight < minWeight) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          n.rawText.toLowerCase().includes(q) ||
          n.eventType.toLowerCase().includes(q) ||
          n.notificationId.toLowerCase().includes(q)
        );
      }

      return true;
    })
    .sort((a, b) => {
      const scoreA = a.priorityEngine?.p ?? a.dispatchScore ?? 0;
      const scoreB = b.priorityEngine?.p ?? b.dispatchScore ?? 0;
      return scoreB - scoreA;
    });

  return (
    <div className="min-h-screen bg-mesh-subtle bg-dot-grid text-[#16161D] flex flex-col font-sans selection:bg-[#D9468F] selection:text-[#FFFDF9]">
      {/* Editorial Cream & Ink Header */}
      <header className="border-b border-[#E5DDD0] bg-[#FAF6F0]/90 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between gap-8">
          <div className="flex items-center space-x-3 shrink-0">
            <AegisGlyphLogo size={38} />
            <span className="font-display font-semibold text-xl text-[#16161D] tracking-tight whitespace-nowrap shrink-0">
              AegisNotify
            </span>
          </div>

          {/* Header Controls */}
          <div className="flex items-center space-x-2.5 text-xs shrink-0">
            {/* Live Socket Telemetry */}
            <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-[#FFFDF9] border border-[#E5DDD0]">
              <span
                className={`w-2 h-2 rounded-full ${
                  socketStatus === 'CONNECTED'
                    ? 'bg-[#16A34A]'
                    : socketStatus === 'CONNECTING'
                    ? 'bg-[#D97706] animate-pulse'
                    : 'bg-[#D9468F]'
                }`}
              />
              <span className="text-[#464451] font-medium text-[11px] whitespace-nowrap">
                {socketStatus === 'CONNECTED' ? 'Live Stream' : socketStatus === 'CONNECTING' ? 'Connecting...' : 'Offline'}
              </span>
            </div>

            {quarantinedAlerts.filter((q) => q.status === 'FLAGGED').length > 0 && (
              <button
                onClick={() => setActiveTab('quarantine')}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-xs font-semibold hover:bg-[#F8DCEB] transition-all whitespace-nowrap shrink-0"
              >
                <ShieldAlert className="w-3.5 h-3.5 text-[#D9468F]" />
                <span className="tabular-nums">
                  {quarantinedAlerts.filter((q) => q.status === 'FLAGGED').length} Quarantined
                </span>
              </button>
            )}

            {/* Audio Alert Toggle in Header */}
            <button
              id="audio-notification-toggle-header"
              type="button"
              onClick={() => {
                const nextState = !audioAlertsEnabled;
                setAudioAlertsEnabled(nextState);
                if (firebaseUser) {
                  saveUserPreferencesToFirestore(firebaseUser.uid, {
                    audioAlertsEnabled: nextState,
                  }).catch((err) => console.warn('[Firestore] Failed to persist audio toggle:', err));
                }
                if (nextState) {
                  playCriticalAlertSound(true);
                  setPriorityFeedback('Critical audio notification enabled');
                } else {
                  setPriorityFeedback('Critical audio notification muted');
                }
                setTimeout(() => setPriorityFeedback(null), 2500);
              }}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all border whitespace-nowrap shrink-0 ${
                audioAlertsEnabled
                  ? 'bg-[#FCECF4] border-[#F2C4DC] text-[#B52A70] hover:border-[#D9468F]'
                  : 'bg-[#FFFDF9] border-[#E5DDD0] text-[#6F6C7A] hover:text-[#16161D]'
              }`}
              title={
                audioAlertsEnabled
                  ? 'Critical notification sound enabled (click to mute)'
                  : 'Critical notification sound muted (click to enable)'
              }
            >
              {audioAlertsEnabled ? (
                <Volume2 className="w-3.5 h-3.5 text-[#D9468F]" />
              ) : (
                <VolumeX className="w-3.5 h-3.5 text-[#6F6C7A]" />
              )}
              <span className="hidden md:inline">
                {audioAlertsEnabled ? 'Sound: On' : 'Sound: Off'}
              </span>
            </button>

            <button
              onClick={() => {
                fetchTelemetry();
                fetchIntegrations();
                fetchQuarantine();
              }}
              className="p-2 rounded-full bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#464451] hover:text-[#16161D] transition-colors border border-[#E5DDD0] shrink-0"
              title="Refresh Engine Data"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>

            {/* Authenticated User Indicator & Sign Out */}
            {user && (
              <div className="flex items-center space-x-2 pl-2 border-l border-[#E5DDD0] shrink-0">
                <div className="hidden sm:flex items-center px-3 py-1 rounded-full bg-[#FFFDF9] border border-[#E5DDD0] text-xs text-[#464451] font-mono-tech max-w-[180px] truncate">
                  <span className="truncate">{user.phoneNumber || user.email || 'USER'}</span>
                </div>
                {onLogout && (
                  <button
                    onClick={handleSecureLogout}
                    className="px-3.5 py-1.5 rounded-full bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold transition-colors whitespace-nowrap shrink-0"
                    title="Sign Out"
                  >
                    Logout
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Cream & Ink Navigation Bar */}
      <div className="border-b border-[#E5DDD0] bg-[#FAF6F0]/85 backdrop-blur-xl sticky top-18 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4 overflow-x-auto">
          <div className="flex items-center gap-1 p-1 bg-[#F2ECE2] border border-[#E5DDD0] rounded-2xl">
            <button
              onClick={() => setActiveTab('feed')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'feed'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Bell className={`w-3.5 h-3.5 ${activeTab === 'feed' ? 'text-[#F472B6]' : ''}`} />
              <span>Live Feed</span>
              {notifications.length > 0 && (
                <span
                  className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono-tech ${
                    activeTab === 'feed'
                      ? 'bg-[#D9468F] text-[#FFFDF9]'
                      : 'bg-[#E5DDD0] text-[#464451]'
                  }`}
                >
                  {notifications.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('quarantine')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'quarantine'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <ShieldAlert className={`w-3.5 h-3.5 ${activeTab === 'quarantine' ? 'text-[#F472B6]' : ''}`} />
              <span>Quarantine</span>
              <span
                className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono-tech ${
                  activeTab === 'quarantine'
                    ? 'bg-[#D9468F] text-[#FFFDF9]'
                    : 'bg-[#E5DDD0] text-[#464451]'
                }`}
              >
                {quarantinedAlerts.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('catalog')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'catalog'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <LayoutGrid className={`w-3.5 h-3.5 ${activeTab === 'catalog' ? 'text-[#F472B6]' : ''}`} />
              <span>App Catalog</span>
            </button>

            <button
              onClick={() => setActiveTab('integrations')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'integrations'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Layers className={`w-3.5 h-3.5 ${activeTab === 'integrations' ? 'text-[#F472B6]' : ''}`} />
              <span>Connected Apps</span>
              <span
                className={`px-1.5 py-0.5 rounded-full text-[10px] font-mono-tech ${
                  activeTab === 'integrations'
                    ? 'bg-[#D9468F] text-[#FFFDF9]'
                    : 'bg-[#E5DDD0] text-[#464451]'
                }`}
              >
                {connectedApps.filter((a) => a.enabled).length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('channels')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'channels'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Smartphone className={`w-3.5 h-3.5 ${activeTab === 'channels' ? 'text-[#F472B6]' : ''}`} />
              <span>Channels & Fallbacks</span>
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'rules'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <SlidersHorizontal className={`w-3.5 h-3.5 ${activeTab === 'rules' ? 'text-[#F472B6]' : ''}`} />
              <span>Settings &amp; Rules</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'history'
                  ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Clock className={`w-3.5 h-3.5 ${activeTab === 'history' ? 'text-[#F472B6]' : ''}`} />
              <span>Audit Trail</span>
            </button>

            {isAdmin && (
              <button
                onClick={() => setActiveTab('telemetry')}
                className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                  activeTab === 'telemetry'
                    ? 'bg-[#16161D] text-[#FAF6F0] shadow-xs'
                    : 'text-[#464451] hover:text-[#16161D]'
                }`}
              >
                <Activity className={`w-3.5 h-3.5 ${activeTab === 'telemetry' ? 'text-[#F472B6]' : ''}`} />
                <span>Security Telemetry</span>
              </button>
            )}

            <button
              onClick={() => setActiveTab('chat')}
              className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center space-x-2 transition-all whitespace-nowrap shrink-0 ${
                activeTab === 'chat'
                  ? 'bg-[#D9468F] text-[#FFFDF9] shadow-xs'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Bot className="w-3.5 h-3.5" />
              <span>AI Assistant</span>
            </button>
          </div>

          <div className="hidden lg:flex items-center space-x-2 text-xs text-[#6F6C7A] font-medium whitespace-nowrap shrink-0">
            <span>Zero-Trust Notification Hub</span>
          </div>
        </div>
      </div>

      {/* Floating Notifications / Feedback */}
      {priorityFeedback && (
        <div className="bg-[#FCECF4] border-b border-[#F2C4DC] px-4 py-2.5 text-center text-xs text-[#16161D] flex items-center justify-center space-x-2 font-medium">
          <CheckCircle2 className="w-4 h-4 text-[#D9468F]" />
          <span>{priorityFeedback}</span>
        </div>
      )}

      {quarantineFeedback && (
        <div className="bg-[#16161D] border-b border-[#D9468F]/40 px-4 py-2.5 text-center text-xs text-[#FAF6F0] flex items-center justify-center space-x-2 font-medium">
          <ShieldAlert className="w-4 h-4 text-[#F472B6]" />
          <span>{quarantineFeedback}</span>
        </div>
      )}

      {/* Main Workspace */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Cream & Ink Telemetry KPI Strip */}
        {activeTab !== 'telemetry' && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 relative overflow-hidden group">
            <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
              <span>Total Ingested</span>
              <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                <Zap className="w-4 h-4" />
              </div>
            </div>
            <div className="font-display text-3xl font-semibold text-[#16161D] tracking-tight tabular-nums">
              {analytics?.overview?.totalIngested ?? notifications.length}
            </div>
            <div className="text-xs text-[#6F6C7A] font-medium">
              Stream ingestion active
            </div>
          </div>

          <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 relative overflow-hidden group">
            <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
              <span>Critical Dispatch</span>
              <div className="w-7 h-7 rounded-lg bg-[#16161D] text-[#F472B6] flex items-center justify-center">
                <AlertTriangle className="w-4 h-4" />
              </div>
            </div>
            <div className="font-display text-3xl font-semibold text-[#16161D] tracking-tight tabular-nums">
              {notifications.filter((n) => (n.priority || '').toUpperCase() === 'CRITICAL').length}
            </div>
            <div className="text-xs text-[#6F6C7A] font-medium">
              Priority escalation ready
            </div>
          </div>

          <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 relative overflow-hidden group">
            <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
              <span>Noise Suppression</span>
              <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                <ShieldCheck className="w-4 h-4" />
              </div>
            </div>
            <div
              className={`font-display font-semibold text-[#16161D] tracking-tight tabular-nums ${
                analytics?.overview?.dedupItemsReceived &&
                analytics.overview.dedupItemsReceived > 0 &&
                analytics.overview.deduplicationRatePercent !== null
                  ? 'text-3xl'
                  : 'text-2xl'
              }`}
            >
              {analytics?.overview?.dedupItemsReceived &&
              analytics.overview.dedupItemsReceived > 0 &&
              analytics.overview.deduplicationRatePercent !== null
                ? `${analytics.overview.deduplicationRatePercent}%`
                : 'No data yet'}
            </div>
            <div className="text-xs text-[#6F6C7A] font-medium">
              {analytics?.overview?.dedupItemsReceived && analytics.overview.dedupItemsReceived > 0
                ? `${analytics.overview.deduplicatedCount} of ${analytics.overview.dedupItemsReceived} grouped`
                : 'Semantic deduplication'}
            </div>
          </div>

          <div className="glass-panel glass-panel-hover rounded-2xl p-5 space-y-2 relative overflow-hidden group">
            <div className="flex items-center justify-between text-[#464451] text-xs font-semibold">
              <span>Quarantine Vault</span>
              <div className="w-7 h-7 rounded-lg bg-[#F2ECE2] text-[#16161D] flex items-center justify-center">
                <ShieldAlert className="w-4 h-4" />
              </div>
            </div>
            <div className="font-display text-3xl font-semibold text-[#16161D] tracking-tight tabular-nums">
              {quarantinedAlerts.length}
            </div>
            <div className="text-xs text-[#6F6C7A] font-medium">
              Anomalies contained
            </div>
          </div>
        </div>
        )}
        {/* =========================================================================
            TAB 1: LIVE ALERTS FEED WITH PRIORITY MANAGEMENT
        ========================================================================== */}
        {activeTab === 'feed' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Feed & Interactive Priority Controls */}
            <div className="lg:col-span-2 space-y-6">
              {/* Priority Filter & Search Control Panel */}
              <div className="glass-panel rounded-2xl p-5 space-y-4 border border-[#E5DDD0]">
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                  {/* Search Input */}
                  <div className="relative flex-1">
                    <Search className="w-4 h-4 text-[#6F6C7A] absolute left-3.5 top-3" />
                    <input
                      type="text"
                      placeholder="Search notifications by keyword, app, or ID..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2.5 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-sans"
                    />
                  </div>

                  {/* Controls on the right: Auto-read & Audio Chime Toggle */}
                  <div className="flex flex-wrap items-center gap-3 text-xs text-[#464451]">
                    {/* Critical Audio Notification Toggle & Sound Test */}
                    <div className="flex items-center space-x-1.5">
                      <button
                        id="critical-audio-toggle-feed"
                        type="button"
                        onClick={() => {
                          const nextState = !audioAlertsEnabled;
                          setAudioAlertsEnabled(nextState);
                          if (nextState) {
                            playCriticalAlertSound(true);
                            setPriorityFeedback('Critical audio notification enabled');
                          } else {
                            setPriorityFeedback('Critical audio notification muted');
                          }
                          setTimeout(() => setPriorityFeedback(null), 2500);
                        }}
                        className={`flex items-center space-x-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all border ${
                          audioAlertsEnabled
                            ? 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC] hover:border-[#D9468F]'
                            : 'bg-[#FAF6F0] text-[#6F6C7A] border-[#D8CEC0] hover:text-[#16161D]'
                        }`}
                        title="Toggle subtle chime for CRITICAL priority alerts"
                      >
                        {audioAlertsEnabled ? (
                          <Volume2 className="w-3.5 h-3.5 text-[#D9468F]" />
                        ) : (
                          <VolumeX className="w-3.5 h-3.5 text-[#6F6C7A]" />
                        )}
                        <span>
                          Sound: {audioAlertsEnabled ? 'On' : 'Off'}
                        </span>
                      </button>

                      {audioAlertsEnabled && (
                        <button
                          id="test-critical-audio-btn"
                          type="button"
                          onClick={() => playCriticalAlertSound(true)}
                          className="px-2.5 py-1.5 rounded-full text-xs bg-[#FAF6F0] text-[#464451] hover:text-[#16161D] border border-[#D8CEC0] hover:border-[#16161D] transition-colors"
                          title="Play sample critical alert chime"
                        >
                          Test
                        </button>
                      )}
                    </div>

                    {/* Auto-read checkbox */}
                    <div className="border-l border-[#E5DDD0] pl-3">
                      <label className="flex items-center space-x-2 cursor-pointer select-none text-xs text-[#464451] hover:text-[#16161D]">
                        <input
                          type="checkbox"
                          checked={autoAck}
                          onChange={(e) => setAutoAck(e.target.checked)}
                          className="rounded bg-[#FAF6F0] border-[#D8CEC0] text-[#D9468F] focus:ring-0"
                        />
                        <span>Auto-mark read</span>
                      </label>
                    </div>
                  </div>
                </div>

                {/* Priority Selector Toolbar */}
                <div className="pt-3 border-t border-[#E5DDD0] flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="text-[#464451] mr-1 flex items-center space-x-1 text-xs font-medium">
                      <Filter className="w-3.5 h-3.5 text-[#D9468F]" />
                      <span>Priority:</span>
                    </span>
                    {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => {
                      const isActive = priorityFilter === lvl;
                      const activeColors =
                        lvl === 'CRITICAL'
                          ? 'bg-[#D9468F] text-[#FFFDF9]'
                          : lvl === 'HIGH'
                          ? 'bg-[#16161D] text-[#FAF6F0]'
                          : lvl === 'MEDIUM'
                          ? 'bg-[#464451] text-[#FAF6F0]'
                          : lvl === 'LOW'
                          ? 'bg-[#6F6C7A] text-[#FAF6F0]'
                          : 'bg-[#16161D] text-[#FAF6F0]';

                      return (
                        <button
                          key={lvl}
                          onClick={() => setPriorityFilter(lvl)}
                          className={`px-3 py-1 rounded-xl text-xs font-medium transition-all whitespace-nowrap shrink-0 ${
                            isActive
                              ? `${activeColors} shadow-xs`
                              : 'bg-[#FAF6F0] text-[#464451] hover:text-[#16161D] border border-[#E5DDD0]'
                          }`}
                        >
                          {lvl}
                        </button>
                      );
                    })}
                  </div>

                  {/* Minimum Alert Level Threshold */}
                  <div className="flex items-center space-x-2 text-xs">
                    <span className="text-[#464451]">Min Threshold:</span>
                    <select
                      value={minPriorityThreshold}
                      onChange={(e) => setMinPriorityThreshold(e.target.value as any)}
                      className="bg-[#FAF6F0] border border-[#D8CEC0] text-[#16161D] rounded-xl px-2.5 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                    >
                      <option value="LOW">LOW (Show All)</option>
                      <option value="MEDIUM">MEDIUM & Above</option>
                      <option value="HIGH">HIGH & CRITICAL</option>
                      <option value="CRITICAL">CRITICAL Only</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Ephemeral Self-Destruct Vault (300s default TTL) */}
              <EphemeralVaultSection
                userId={vaultUserId}
                refreshSignal={ephemeralRefreshTick}
                privacyShieldEnabled={privacyShieldEnabled}
                isWindowBlurred={isWindowBlurred}
                onChanged={() => setEphemeralRefreshTick((v) => v + 1)}
              />

              {/* On-Device ONNX Semantic Deduplication Status Strip */}
              <div className="rounded-2xl bg-[#FFFDF9] border border-[#E5DDD0] px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <Cpu className="w-4 h-4 text-[#D9468F] shrink-0" />
                  <span className="font-semibold text-[#16161D]">On-Device Semantic Dedup:</span>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                      embedderSnapshot.status === 'ready'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : embedderSnapshot.status === 'lightweight_fallback'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-[#FCECF4] text-[#B52A70] border-[#F2C4DC]'
                    }`}
                  >
                    {embedderSnapshot.status === 'ready'
                      ? `ONNX Ready (${embedderSnapshot.backend.toUpperCase()})`
                      : embedderSnapshot.status === 'loading'
                      ? `Loading ONNX (${embedderSnapshot.progressPercent}%)`
                      : embedderSnapshot.status === 'lightweight_fallback'
                      ? 'Lightweight TF-IDF mode'
                      : 'Idle · TF-IDF active until ONNX loaded'}
                  </span>
                  <span className="text-[11px] text-[#6F6C7A]">
                    Vectors &amp; plaintext stay in browser RAM only
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {embedderSnapshot.status !== 'ready' && embedderSnapshot.status !== 'loading' && (
                    <button
                      type="button"
                      onClick={() => prewarmOnnxEmbedder(false)}
                      className="px-2.5 py-1 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-[11px] font-semibold flex items-center gap-1"
                    >
                      <Download className="w-3 h-3 text-[#F472B6]" />
                      <span>Load ONNX (~23 MB)</span>
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setActiveTab('rules')}
                    className="px-2.5 py-1 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#464451] border border-[#D8CEC0] text-[11px] font-semibold"
                  >
                    Settings
                  </button>
                </div>
              </div>

              {/* Feed List (Grouped by Semantic Deduplication Threads) */}
              {filteredNotifications.length === 0 ? (
                <div className="glass-panel rounded-2xl p-16 text-center space-y-3 border border-[#E5DDD0]">
                  <div className="w-12 h-12 rounded-2xl bg-[#FCECF4] text-[#B52A70] flex items-center justify-center mx-auto">
                    <Bell className="w-6 h-6" />
                  </div>
                  <h3 className="font-display text-[#16161D] text-lg font-semibold">
                    No notifications matching criteria
                  </h3>
                  <p className="text-xs text-[#464451] max-w-sm mx-auto leading-relaxed">
                    Try switching priority filters or dispatch a sample alert from the simulator.
                  </p>
                </div>
              ) : (
                <div className="space-y-3.5">
                  {(() => {
                    const groupsMap = new Map<
                      string,
                      { threadId: string; members: NotificationItem[] }
                    >();
                    for (const item of filteredNotifications) {
                      const tid =
                        notifThreadMap[item.notificationId] ||
                        item.dedupThreadId ||
                        item.notificationId;
                      const existing = groupsMap.get(tid);
                      if (existing) {
                        existing.members.push(item);
                      } else {
                        groupsMap.set(tid, { threadId: tid, members: [item] });
                      }
                    }

                    const threadGroups = Array.from(groupsMap.values());

                    return threadGroups.map(({ threadId, members }) => {
                      const notif = members[0];
                      const threadMeta = dedupThreadsById[threadId];
                      const decision =
                        notifDecisionMap[notif.notificationId] || notif.dedupDecision || undefined;
                      const isGrouped = members.length > 1;
                      const isExpanded = Boolean(expandedThreadIds[threadId]);
                      const isResolved = threadMeta?.status === 'RESOLVED';

                      const currentPriority =
                        notif.priority ||
                        (notif.dispatchScore >= 0.9
                          ? 'CRITICAL'
                          : notif.dispatchScore >= 0.75
                          ? 'HIGH'
                          : 'MEDIUM');
                      const isUpdating = updatingPriorityId === notif.notificationId;

                      // Thread lowest provenance trust across all members
                      const trustValues: DedupProvenanceTrust[] = members.map((m) =>
                        m.provenanceReport?.badgeVariant === 'gateway'
                          ? 'GATEWAY_ATTESTED'
                          : m.provenanceReport?.verified
                          ? 'VERIFIED'
                          : 'UNVERIFIED'
                      );
                      const lowestTrustInGroup = trustValues.reduce<DedupProvenanceTrust>(
                        (acc, cur) => minProvenanceTrust(acc, cur),
                        'VERIFIED'
                      );

                      const effectiveThreadMeta: DedupThreadMetadata = threadMeta || {
                        threadId,
                        userId: notif.userId,
                        createdAt: notif.timestamp,
                        lastMemberAt: notif.timestamp,
                        memberCount: members.length,
                        memberIds: members.map((m) => m.notificationId),
                        sourceId: String(notif.metadata?.appId || notif.eventType || 'direct'),
                        senderId: String(
                          notif.provenanceEnvelope?.payload?.senderId ||
                            notif.metadata?.appId ||
                            'gateway'
                        ),
                        category: 'work',
                        topPriority: (currentPriority as DedupThreadMetadata['topPriority']) || 'MEDIUM',
                        lowestTrust: lowestTrustInGroup,
                        status: 'ACTIVE',
                        stageMatched: decision?.stageMatched || 'NONE',
                        lastSimilarity: decision?.similarity ?? 1,
                      };

                      const openWhyDrawer = () => {
                        setInspectedDedupTarget({
                          thread: effectiveThreadMeta,
                          decision,
                          memberSummaries: members.map((m) => ({
                            notificationId: m.notificationId,
                            preview: m.rawText,
                            priority: m.priority || 'MEDIUM',
                            similarity:
                              effectiveThreadMeta.memberSimilarities?.[m.notificationId] ??
                              decision?.similarity ??
                              1,
                            timestamp: m.timestamp,
                          })),
                        });
                      };

                      const effectiveReport: ProvenanceVerificationReport =
                        notif.provenanceReport || {
                          status: 'UNSIGNED',
                          verified: false,
                          reason:
                            'No Ed25519 provenance envelope attached to this notification.',
                          alg: 'NONE',
                          badgeVariant: 'unverified',
                          chain: [],
                        };
                      const isCollapsed =
                        !effectiveReport.verified &&
                        !revealedUnverifiedIds[notif.notificationId];

                      return (
                        <div
                          key={threadId}
                          className="p-5 rounded-2xl glass-panel glass-panel-hover border border-[#E5DDD0] space-y-3 transition-all"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="space-y-2.5 flex-1">
                              {/* Badges Row */}
                              <div className="flex flex-wrap items-center gap-2.5">
                                {(notif.metadata?.appId ||
                                  notif.sanitizedPayload?.metadata?.appId) && (
                                  <AppIconBadge
                                    appId={String(
                                      notif.metadata?.appId ||
                                        notif.sanitizedPayload?.metadata?.appId
                                    )}
                                    size="sm"
                                  />
                                )}

                                <div className="flex items-center space-x-1.5">
                                  <span className="text-xs text-[#6F6C7A] font-medium">
                                    Priority:
                                  </span>
                                  <select
                                    value={currentPriority}
                                    onChange={(e) =>
                                      handleSetPriority(
                                        notif.notificationId,
                                        e.target.value as any
                                      )
                                    }
                                    disabled={isUpdating}
                                    className={`px-2.5 py-0.5 rounded-lg text-xs font-semibold cursor-pointer focus:outline-none transition-colors border ${
                                      currentPriority === 'CRITICAL'
                                        ? 'bg-[#FCECF4] text-[#B52A70] border-[#D9468F]/45'
                                        : currentPriority === 'HIGH'
                                        ? 'bg-[#16161D] text-[#FAF6F0] border-[#16161D]'
                                        : currentPriority === 'MEDIUM'
                                        ? 'bg-[#F2ECE2] text-[#16161D] border-[#D8CEC0]'
                                        : 'bg-[#FAF6F0] text-[#6F6C7A] border-[#E5DDD0]'
                                    }`}
                                    title="Change priority for this notification"
                                  >
                                    <option value="LOW" className="bg-[#FFFDF9] text-[#16161D]">
                                      LOW
                                    </option>
                                    <option value="MEDIUM" className="bg-[#FFFDF9] text-[#16161D]">
                                      MEDIUM
                                    </option>
                                    <option value="HIGH" className="bg-[#FFFDF9] text-[#16161D]">
                                      HIGH
                                    </option>
                                    <option
                                      value="CRITICAL"
                                      className="bg-[#FFFDF9] text-[#B52A70]"
                                    >
                                      CRITICAL
                                    </option>
                                  </select>
                                </div>

                                {isGrouped && (
                                  <span
                                    className="px-2.5 py-0.5 rounded-full bg-[#16161D] text-[#FAF6F0] text-[11px] font-mono-tech font-semibold flex items-center gap-1"
                                    title={`Grouped into thread ${threadId} via ${effectiveThreadMeta.stageMatched}`}
                                  >
                                    <Layers className="w-3 h-3 text-[#F472B6]" />
                                    <span>&times;{members.length} similar</span>
                                  </span>
                                )}

                                {isResolved && (
                                  <span className="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-semibold">
                                    RESOLVED
                                  </span>
                                )}

                                {(notif.metadata?.simulated ||
                                  notif.sanitizedPayload?.metadata?.simulated) && (
                                  <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-semibold">
                                    Simulated
                                  </span>
                                )}

                                <ProvenanceStatusBadge
                                  report={effectiveReport}
                                  onClick={() => setInspectedProvenanceReport(effectiveReport)}
                                />

                                {isGrouped && lowestTrustInGroup === 'UNVERIFIED' && (
                                  <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-semibold">
                                    Thread Trust: {lowestTrustInGroup}
                                  </span>
                                )}

                                {notif.priorityEngine && (
                                  <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-[#FAF6F0] border border-[#E5DDD0] text-[11px] font-mono tabular-nums text-[#16161D]">
                                    <span className="font-semibold text-[#B52A70]">
                                      p={notif.priorityEngine.p.toFixed(2)}
                                    </span>
                                    <span className="w-10 h-1.5 rounded-full bg-[#E5DDD0] overflow-hidden inline-block">
                                      <span
                                        className="block h-full bg-[#D9468F]"
                                        style={{
                                          width: `${Math.min(
                                            100,
                                            Math.max(4, Math.round(notif.priorityEngine.p * 100))
                                          )}%`,
                                        }}
                                      />
                                    </span>
                                    <button
                                      type="button"
                                      onClick={() => setInspectedPriorityItem(notif)}
                                      className="text-[11px] font-sans font-semibold text-[#16161D] hover:text-[#B52A70] underline underline-offset-2 ml-0.5"
                                    >
                                      Why?
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleQuickPriorityFeedback(notif, 'MORE_IMPORTANT')
                                      }
                                      className="p-0.5 text-[#464451] hover:text-[#15803D]"
                                      aria-label="Mark more important"
                                    >
                                      <ThumbsUp className="w-3 h-3" />
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleQuickPriorityFeedback(notif, 'LESS_IMPORTANT')
                                      }
                                      className="p-0.5 text-[#464451] hover:text-[#B52A70]"
                                      aria-label="Mark less important"
                                    >
                                      <ThumbsDown className="w-3 h-3" />
                                    </button>
                                  </div>
                                )}

                                {(isGrouped || decision) && (
                                  <button
                                    type="button"
                                    onClick={openWhyDrawer}
                                    className="px-2 py-0.5 rounded-lg bg-[#FCECF4] hover:bg-[#F9D8E9] text-[#B52A70] border border-[#F2C4DC] text-[11px] font-semibold"
                                  >
                                    Why grouped?
                                  </button>
                                )}

                                {notif.status === 'ESCALATED_FALLBACK' && (
                                  <span className="text-xs text-[#B52A70] flex items-center space-x-1 font-semibold">
                                    <Smartphone className="w-3.5 h-3.5 text-[#D9468F]" />
                                    <span>Escalated · Email, WebPush &amp; SMS</span>
                                  </span>
                                )}
                              </div>

                              {/* Optional Suggested Merge Banner */}
                              {!isGrouped &&
                                decision?.action === 'SUGGEST' &&
                                decision.relatedThreadId &&
                                dedupThreadsById[decision.relatedThreadId] && (
                                  <div className="rounded-xl bg-[#FCECF4]/60 border border-[#F2C4DC] px-3 py-2 flex flex-wrap items-center justify-between gap-2 text-xs">
                                    <span className="text-[#464451]">
                                      Possibly related to thread{' '}
                                      <strong className="font-mono-tech text-[#16161D]">
                                        {decision.relatedThreadId}
                                      </strong>{' '}
                                      ({Math.round(decision.similarity * 100)}% similarity).
                                    </span>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        void handleManualMergeThreads(
                                          decision.relatedThreadId!,
                                          threadId,
                                          decision.similarity
                                        )
                                      }
                                      className="px-2.5 py-1 rounded-lg bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-[11px] font-semibold"
                                    >
                                      Merge these
                                    </button>
                                  </div>
                                )}

                              {decision?.blockedByGuard === 'NEGATION_STATE_CONFLICT' &&
                                decision.relatedThreadId && (
                                  <div className="rounded-xl bg-emerald-50/70 border border-emerald-200 px-3 py-1.5 text-[11px] text-emerald-900">
                                    State-change update kept separate (original incident{' '}
                                    <span className="font-mono-tech font-semibold">
                                      {decision.relatedThreadId}
                                    </span>{' '}
                                    marked RESOLVED).
                                  </div>
                                )}

                              {/* Message Content with Zero-Trust Provenance Gate */}
                              {isCollapsed ? (
                                <div className="rounded-xl bg-amber-50/80 border border-amber-300/80 p-3 space-y-2 text-xs text-amber-950">
                                  <div className="font-semibold flex items-center gap-1.5">
                                    <AlertTriangle className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                                    <span>
                                      Unverified Content Collapsed [{effectiveReport.status}]
                                    </span>
                                  </div>
                                  <p className="text-[11px] text-amber-900 leading-relaxed">
                                    {effectiveReport.reason}
                                  </p>
                                  <div className="flex flex-wrap items-center gap-2">
                                    <button
                                      type="button"
                                      onClick={() =>
                                        setInspectedProvenanceReport(effectiveReport)
                                      }
                                      className="px-2.5 py-1 rounded-lg bg-[#FFFDF9] border border-amber-300 text-[11px] font-semibold text-amber-950 hover:bg-amber-100"
                                    >
                                      Inspect Provenance
                                    </button>
                                    <button
                                      type="button"
                                      onClick={() =>
                                        setRevealedUnverifiedIds((prev) => ({
                                          ...prev,
                                          [notif.notificationId]: true,
                                        }))
                                      }
                                      className="px-2.5 py-1 rounded-lg bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-[11px] font-semibold"
                                    >
                                      Show Unverified Content Anyway
                                    </button>
                                  </div>
                                </div>
                              ) : (
                                <p className="text-sm font-medium text-[#16161D] leading-relaxed pt-0.5">
                                  {notif.rawText}
                                </p>
                              )}

                              {/* Inline Grouped Controls & Expand Stack */}
                              {isGrouped && (
                                <div className="pt-1 flex flex-wrap items-center gap-2">
                                  <button
                                    type="button"
                                    onClick={() =>
                                      setExpandedThreadIds((prev) => ({
                                        ...prev,
                                        [threadId]: !prev[threadId],
                                      }))
                                    }
                                    className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-[11px] font-semibold text-[#16161D] flex items-center gap-1"
                                  >
                                    {isExpanded ? (
                                      <ChevronUp className="w-3.5 h-3.5" />
                                    ) : (
                                      <ChevronDown className="w-3.5 h-3.5" />
                                    )}
                                    <span>
                                      {isExpanded
                                        ? 'Collapse stack'
                                        : `Expand (${members.length})`}
                                    </span>
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => void handleUngroupThread(threadId)}
                                    className="px-2.5 py-1 rounded-lg bg-[#FAF6F0] hover:bg-[#F2ECE2] border border-[#D8CEC0] text-[11px] font-semibold text-[#16161D] flex items-center gap-1"
                                  >
                                    <Split className="w-3 h-3 text-[#D9468F]" />
                                    <span>Ungroup</span>
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => void handleMarkNotDuplicate(threadId)}
                                    className="px-2.5 py-1 rounded-lg bg-[#FCECF4] hover:bg-[#F9D8E9] border border-[#F2C4DC] text-[11px] font-semibold text-[#B52A70]"
                                  >
                                    Not a duplicate
                                  </button>
                                </div>
                              )}

                              {isGrouped && isExpanded && (
                                <div className="mt-2 pl-3 border-l-2 border-[#D9468F]/40 space-y-2">
                                  {members.map((m) => {
                                    const simPct = Math.round(
                                      (effectiveThreadMeta.memberSimilarities?.[
                                        m.notificationId
                                      ] ??
                                        decision?.similarity ??
                                        1) * 100
                                    );
                                    return (
                                      <div
                                        key={m.notificationId}
                                        className="p-2.5 rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] text-xs space-y-1"
                                      >
                                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono-tech text-[#6F6C7A]">
                                          <span>
                                            {m.priority || 'MEDIUM'} ·{' '}
                                            {new Date(m.timestamp).toLocaleTimeString()}
                                          </span>
                                          <span className="text-[#B52A70] font-semibold">
                                            {simPct}% match
                                          </span>
                                        </div>
                                        <p className="text-[#16161D] leading-snug">
                                          {m.provenanceReport?.verified === false &&
                                          !revealedUnverifiedIds[m.notificationId]
                                            ? `[Unverified content collapsed — ID ${m.notificationId}]`
                                            : m.rawText}
                                        </p>
                                      </div>
                                    );
                                  })}
                                </div>
                              )}

                              {/* Metadata Footer */}
                              <div className="flex flex-wrap items-center gap-2.5 text-xs text-[#6F6C7A] pt-1 font-mono-tech">
                                <span className="text-[#464451]">Event: {notif.eventType}</span>
                                <span aria-hidden="true">·</span>
                                <span>{new Date(notif.timestamp).toLocaleTimeString()}</span>
                                <span aria-hidden="true">·</span>
                                <span className="text-[#B52A70] font-medium">
                                  Score: {notif.dispatchScore}
                                </span>
                                {notif.signature && (
                                  <>
                                    <span aria-hidden="true">·</span>
                                    <span title={notif.signature}>
                                      Sig: {notif.signature.substring(0, 12)}...
                                    </span>
                                  </>
                                )}
                                <span aria-hidden="true">·</span>
                                <span>ID: {notif.notificationId}</span>
                              </div>
                            </div>

                            {/* Action Button */}
                            <div className="shrink-0">
                              {notif.ackState === 'PENDING' ? (
                                <button
                                  onClick={() => handleAck(notif.notificationId)}
                                  className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all shadow-xs active:scale-95 whitespace-nowrap"
                                >
                                  Mark Read
                                </button>
                              ) : (
                                <span className="text-xs text-[#15803D] flex items-center space-x-1.5 py-1 px-2.5 bg-[#F0F7F4] rounded-xl border border-[#16A34A]/25 font-medium">
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  <span>Read</span>
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    });
                  })()}
                </div>
              )}
            </div>

            {/* Right Col: Dispatch Simulation & Quick Testing Panel */}
            <div className="space-y-6">
              {/* Dispatch Simulation */}
              <div className="glass-panel rounded-2xl p-6 space-y-4 border border-[#E5DDD0]">
                <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                      <Zap className="w-3.5 h-3.5" />
                    </div>
                    <h3 className="text-[#16161D] text-xs font-semibold tracking-wide">Dispatch Simulator</h3>
                  </div>
                  <span className="text-[11px] text-[#B52A70] font-mono-tech font-medium">Live Test</span>
                </div>

                <form onSubmit={handleManualSimulate} className="space-y-3.5">
                  <div>
                    <label className="block text-xs font-medium text-[#464451] mb-1">Source Application</label>
                    <select
                      value={simApp}
                      onChange={(e) => setSimApp(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
                    >
                      {connectedApps.map((a) => (
                        <option key={a.id} value={a.id} className="bg-[#FFFDF9]">
                          {a.name} ({a.enabled ? 'Active' : 'Muted'})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-[#464451] mb-1">Payload Content</label>
                    <textarea
                      rows={3}
                      value={simTitle}
                      onChange={(e) => setSimTitle(e.target.value)}
                      placeholder="Notification content..."
                      className="w-full px-3 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] resize-none font-sans"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-[#464451] mb-1">Priority</label>
                      <select
                        value={simUrgency}
                        onChange={(e) => setSimUrgency(e.target.value as any)}
                        className="w-full px-3 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
                      >
                        <option value="LOW" className="bg-[#FFFDF9]">LOW</option>
                        <option value="MEDIUM" className="bg-[#FFFDF9]">MEDIUM</option>
                        <option value="HIGH" className="bg-[#FFFDF9]">HIGH</option>
                        <option value="CRITICAL" className="bg-[#FFFDF9]">CRITICAL</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-xs font-medium text-[#464451] mb-1">
                        Temp OTP Code
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. 841-290"
                        value={simOtp}
                        onChange={(e) => setSimOtp(e.target.value)}
                        className="w-full px-3 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono-tech"
                      />
                    </div>
                  </div>

                  {/* Planned Delivery Path Preview */}
                  {(() => {
                    const previewPlan = resolveEffectiveDeliveryPlan(simUrgency, {
                      dndEnabled,
                      quietHoursStart,
                      quietHoursEnd,
                      preferredChannel,
                      allowCriticalBypassQuietHours,
                      optOutPush,
                      optOutWhatsapp,
                      optOutSms,
                      optOutEmail,
                    });
                    return (
                      <div className="rounded-xl bg-[#FAF6F0] border border-[#E5DDD0] p-3 space-y-1.5">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-semibold text-[#464451] flex items-center space-x-1.5">
                            <GitBranch className="w-3.5 h-3.5 text-[#D9468F]" />
                            <span>Planned Delivery Path</span>
                          </span>
                          <span className="font-mono-tech text-[10px] text-[#6F6C7A]">
                            {previewPlan.requiresAck
                              ? `${Math.round(previewPlan.ackTimeoutMs / 1000)}s ACK · ${previewPlan.maxRetriesPerChannel} retries`
                              : 'No ACK required'}
                          </span>
                        </div>
                        <div className="text-xs font-mono-tech font-semibold text-[#16161D]">
                          {formatChannelPlanLabel(previewPlan.channels)}
                        </div>
                        {previewPlan.skippedReasons.length > 0 && (
                          <div className="text-[11px] text-[#B52A70]">
                            {previewPlan.skippedReasons[0]}
                          </div>
                        )}
                        <label className="flex items-center space-x-2 pt-1 cursor-pointer select-none text-[11px] text-[#464451]">
                          <input
                            type="checkbox"
                            checked={trackInDeliveryPipeline}
                            onChange={(e) => setTrackInDeliveryPipeline(e.target.checked)}
                            className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                          />
                          <span>
                            {simEphemeralMode
                              ? 'Also send generic fallback alert (no content)'
                              : 'Track in Multi-Channel Fallback State Machine'}
                          </span>
                        </label>
                      </div>
                    );
                  })()}

                  {/* Ephemeral Mode (300s TTL & Crypto-Shredding) Controls */}
                  <div className="rounded-xl bg-[#FCECF4]/60 border border-[#F2C4DC] p-3.5 space-y-2.5">
                    <label className="flex items-center justify-between cursor-pointer select-none">
                      <span className="text-xs font-semibold text-[#16161D] flex items-center space-x-1.5">
                        <Flame className="w-3.5 h-3.5 text-[#D9468F]" />
                        <span>Ephemeral (self-destruct in 5 min)</span>
                      </span>
                      <input
                        type="checkbox"
                        checked={simEphemeralMode}
                        onChange={(e) => setSimEphemeralMode(e.target.checked)}
                        className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                      />
                    </label>

                    {simEphemeralMode && (
                      <div className="space-y-2.5 pt-1 border-t border-[#F2C4DC]">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-medium text-[#464451]">TTL Preset:</span>
                          <div className="flex items-center gap-1.5">
                            {ALLOWED_EPHEMERAL_TTL_PRESETS.map((preset) => (
                              <button
                                key={preset}
                                type="button"
                                onClick={() => setSimEphemeralTtl(preset)}
                                className={`px-2.5 py-1 rounded-lg text-[11px] font-mono-tech font-semibold border transition-all ${
                                  simEphemeralTtl === preset
                                    ? 'bg-[#16161D] text-[#FAF6F0] border-[#16161D]'
                                    : 'bg-[#FFFDF9] text-[#464451] border-[#D8CEC0] hover:border-[#D9468F]'
                                }`}
                              >
                                {preset}s
                              </button>
                            ))}
                          </div>
                        </div>

                        <label className="flex items-center space-x-2 cursor-pointer select-none text-[11px] text-[#464451]">
                          <input
                            type="checkbox"
                            checked={simEphemeralReadOnce}
                            onChange={(e) => setSimEphemeralReadOnce(e.target.checked)}
                            className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                          />
                          <span>Read once (burns 10s after 1st decryption)</span>
                        </label>

                        <div>
                          <label className="block text-[11px] font-medium text-[#464451] mb-1">
                            Recipient User ID (blank = self)
                          </label>
                          <input
                            type="text"
                            value={simEphemeralRecipientId}
                            onChange={(e) => setSimEphemeralRecipientId(e.target.value)}
                            placeholder={vaultUserId}
                            className="w-full px-3 py-1.5 text-xs font-mono-tech bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                          />
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Ed25519 Provenance Signing Key Status */}
                  <div
                    className={`rounded-xl px-3.5 py-2.5 border text-[11px] flex items-center justify-between gap-2 ${
                      unlockedSigningKey && !unlockedSigningKey.isWiped()
                        ? 'bg-emerald-50/80 border-emerald-200 text-emerald-900'
                        : 'bg-amber-50/80 border-amber-200 text-amber-900'
                    }`}
                  >
                    {unlockedSigningKey && !unlockedSigningKey.isWiped() ? (
                      <>
                        <span className="flex items-center gap-1.5 font-medium">
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-700 shrink-0" />
                          <span>
                            Ed25519 Signed Origin Active (
                            <code className="font-mono">{unlockedSigningKey.kid}</code>)
                          </span>
                        </span>
                        <button
                          type="button"
                          onClick={() => setActiveTab('rules')}
                          className="text-[11px] font-semibold underline shrink-0"
                        >
                          Manage
                        </button>
                      </>
                    ) : (
                      <>
                        <span className="flex items-center gap-1.5 font-medium">
                          <Lock className="w-3.5 h-3.5 text-amber-700 shrink-0" />
                          <span>
                            No Ed25519 signing key unlocked (CRITICAL/HIGH unsigned alerts blocked).
                          </span>
                        </span>
                        <button
                          type="button"
                          onClick={() => setActiveTab('rules')}
                          className="px-2 py-0.5 rounded bg-amber-900 text-white text-[10px] font-semibold shrink-0"
                        >
                          Unlock Key
                        </button>
                      </>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={isSubmittingSim}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-[#16161D] via-[#4A1C38] to-[#D9468F] hover:opacity-95 text-[#FAF6F0] transition-all flex items-center justify-center space-x-2 shadow-sm active:scale-[0.99]"
                  >
                    {simEphemeralMode ? <Flame className="w-3.5 h-3.5" /> : <Send className="w-3.5 h-3.5" />}
                    <span>
                      {isSubmittingSim
                        ? 'Dispatching...'
                        : simEphemeralMode
                        ? `Encrypt & Send (${simEphemeralTtl}s TTL)`
                        : 'Dispatch Alert'}
                    </span>
                  </button>
                </form>

                {simResult && (
                  <div className="p-3 rounded-xl text-xs bg-[#FAF6F0] border border-[#E5DDD0] text-[#16161D] space-y-1.5">
                    {simResult.ephemeral && simResult.success ? (
                      <div className="text-[#B52A70] flex items-center space-x-1.5 font-medium">
                        <Flame className="w-4 h-4 text-[#D9468F] shrink-0" />
                        <span>{simResult.message || 'Ephemeral encrypted item dispatched.'}</span>
                      </div>
                    ) : simResult.status === 'DEDUPLICATED' ? (
                      <div className="text-[#464451] flex items-center space-x-1.5">
                        <ShieldCheck className="w-4 h-4 text-[#D9468F] shrink-0" />
                        <span>Duplicate Shield: Suppressed identical repeat payload.</span>
                      </div>
                    ) : simResult.success ? (
                      <div className="text-[#14532D] flex items-center space-x-1.5">
                        <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0" />
                        <span>Dispatched: Ingested with priority {simUrgency}.</span>
                      </div>
                    ) : (
                      <div className="text-[#88134A] flex items-center space-x-1.5">
                        <AlertCircle className="w-4 h-4 text-[#D9468F] shrink-0" />
                        <span>Error: {simResult.message || simResult.error}</span>
                      </div>
                    )}
                    {simResult.pipelineJob && (
                      <div className="text-[11px] font-mono-tech text-[#464451] pt-1 border-t border-[#E5DDD0] flex items-center justify-between gap-2">
                        <span>
                          Job {simResult.pipelineJob.id.slice(0, 14)}: {simResult.pipelineJob.state} ({simResult.pipelineJob.channel})
                        </span>
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => setActiveTab('telemetry')}
                            className="text-[#B52A70] underline font-sans font-semibold shrink-0"
                          >
                            View Pipeline
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Quick Threat Test Trigger */}
              <div className="glass-panel rounded-2xl p-6 space-y-3 border border-[#E5DDD0]">
                <div className="flex items-center space-x-2.5">
                  <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                    <ShieldAlert className="w-3.5 h-3.5" />
                  </div>
                  <h4 className="text-[#16161D] text-xs font-semibold tracking-wide">Threat Interception</h4>
                </div>
                <p className="text-xs text-[#464451] leading-relaxed">
                  Trigger an unauthenticated counterfeit payload to verify zero-trust isolation in the Quarantine matrix.
                </p>
                <button
                  onClick={handleSimulateUnauthenticatedThreat}
                  disabled={isSimulatingThreat}
                  className="w-full py-2.5 rounded-xl text-xs font-semibold bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] transition-all flex items-center justify-center space-x-2"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>{isSimulatingThreat ? 'Intercepting...' : 'Simulate Threat'}</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 2: ALERT LOG FOR MISCELLANEOUS & UNAUTHENTICATED MESSAGES (QUARANTINE)
        ========================================================================== */}
        {activeTab === 'quarantine' && (
          <div className="space-y-6">
            {/* Header & Quick Action */}
            <div className="glass-panel border border-[#E5DDD0] rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2.5">
                  <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <h2 className="font-display text-base font-semibold text-[#16161D]">
                    Security Quarantine &amp; Anomaly Log
                  </h2>
                </div>
                <p className="text-xs text-[#464451]">
                  Isolated threats that failed cryptographic verification, lacked API credentials, or contained malformed payloads.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  onClick={handleSimulateUnauthenticatedThreat}
                  disabled={isSimulatingThreat}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] transition-all flex items-center space-x-1.5 shadow-xs whitespace-nowrap disabled:opacity-50"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Simulate Threat</span>
                </button>

                <button
                  onClick={() => handleRunSmsSimulation('SMS_BRUTE_FORCE')}
                  disabled={isSimulatingThreat}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center space-x-1.5 shadow-xs whitespace-nowrap disabled:opacity-50"
                  title="Simulates 6 wrong SMS attempts on an isolated mock number to verify lockout after 5 failures"
                >
                  <Lock className="w-3.5 h-3.5 text-[#F472B6]" />
                  <span>SMS Brute Force</span>
                </button>

                <button
                  onClick={() => handleRunSmsSimulation('SMS_SEND_FLOOD')}
                  disabled={isSimulatingThreat}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] transition-all flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                  title="Simulates rapid SMS send flood on an isolated mock number to verify 429 cooldown enforcement"
                >
                  <Smartphone className="w-3.5 h-3.5 text-[#D9468F]" />
                  <span>SMS Send Flood</span>
                </button>

                <button
                  onClick={() => handleRunSmsSimulation('INGEST_FORGED_SIGNATURE')}
                  disabled={isSimulatingThreat}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] transition-all flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                  title="Sends a forged X-Aegis-Signature to an isolated test connection to verify HTTP 401 + quarantine"
                >
                  <ShieldAlert className="w-3.5 h-3.5 text-[#D9468F]" />
                  <span>Forged Ingest Sig</span>
                </button>

                <button
                  onClick={() => handleRunSmsSimulation('INGEST_REPLAY_TIMESTAMP')}
                  disabled={isSimulatingThreat}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] transition-all flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                  title="Replays a 10-minute-old signed payload against an isolated test connection to verify 5-minute replay rejection"
                >
                  <Clock className="w-3.5 h-3.5 text-[#B52A70]" />
                  <span>Replay Timestamp</span>
                </button>

                <button
                  onClick={fetchQuarantine}
                  className="p-2 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#464451] hover:text-[#16161D] border border-[#D8CEC0] transition-colors"
                  title="Refresh Quarantine Data"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>

                <button
                  type="button"
                  onClick={handleExportQuarantineCsv}
                  disabled={quarantinedAlerts.length === 0}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] transition-all flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-40 disabled:cursor-not-allowed"
                  title={
                    quarantinedAlerts.length === 0
                      ? 'No quarantine history available to export'
                      : 'Download quarantine security history as CSV'
                  }
                >
                  <Download className="w-3.5 h-3.5 text-[#464451]" />
                  <span>Export CSV</span>
                </button>

                <button
                  type="button"
                  onClick={() => setShowBulkDeleteQuarantineModal(true)}
                  disabled={selectedQuarantineIds.length === 0 || isBulkDeletingQuarantine}
                  className="px-3.5 py-2 rounded-xl text-xs font-semibold bg-red-700 hover:bg-red-800 text-white transition-all flex items-center space-x-1.5 shadow-xs whitespace-nowrap disabled:opacity-40 disabled:cursor-not-allowed"
                  title={
                    selectedQuarantineIds.length === 0
                      ? 'Select one or more quarantined items below to bulk delete'
                      : `Delete ${selectedQuarantineIds.length} selected item(s)`
                  }
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>
                    {selectedQuarantineIds.length > 0
                      ? `Bulk Delete (${selectedQuarantineIds.length})`
                      : 'Bulk Delete'}
                  </span>
                </button>
              </div>
            </div>

            {/* Bulk Selection Toolbar */}
            {quarantinedAlerts.length > 0 && selectedQuarantineIds.length > 0 && (
              <div className="glass-panel border border-red-200 bg-red-50/75 rounded-2xl px-5 py-3 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs font-medium text-[#16161D] flex items-center gap-2">
                  <CheckSquare className="w-4 h-4 text-red-700" />
                  <span>
                    <strong>{selectedQuarantineIds.length}</strong> of{' '}
                    <strong>{quarantinedAlerts.length}</strong> quarantined item(s) selected
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setSelectedQuarantineIds([])}
                    className="px-3 py-1.5 rounded-xl text-xs font-medium bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#464451] border border-[#D8CEC0] transition-colors"
                  >
                    Clear Selection
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowBulkDeleteQuarantineModal(true)}
                    disabled={isBulkDeletingQuarantine}
                    className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-red-700 hover:bg-red-800 text-white flex items-center space-x-1.5 transition-colors disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete Selected ({selectedQuarantineIds.length})</span>
                  </button>
                </div>
              </div>
            )}

            {/* Quarantine Table */}
            <div className="glass-panel border border-[#E5DDD0] rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-sans">
                  <thead className="bg-[#F2ECE2] text-[#464451] text-[11px] font-semibold border-b border-[#E5DDD0]">
                    <tr>
                      <th className="py-3 pl-5 pr-2 w-10">
                        <input
                          type="checkbox"
                          aria-label="Select all quarantined items"
                          checked={
                            quarantinedAlerts.length > 0 &&
                            quarantinedAlerts.every((a) => selectedQuarantineIds.includes(a.id))
                          }
                          onChange={toggleSelectAllQuarantine}
                          disabled={quarantinedAlerts.length === 0}
                          className="h-4 w-4 rounded border-[#D8CEC0] accent-[#D9468F] cursor-pointer disabled:opacity-40"
                        />
                      </th>
                      <th className="py-3 px-4">Time</th>
                      <th className="py-3 px-5">Classification</th>
                      <th className="py-3 px-5">Source &amp; IP</th>
                      <th className="py-3 px-5">Anomaly Details</th>
                      <th className="py-3 px-5">Risk Level</th>
                      <th className="py-3 px-5">Status</th>
                      <th className="py-3 px-5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E5DDD0]">
                    {quarantinedAlerts.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="py-12 text-center text-[#6F6C7A]">
                          No anomalous or unauthenticated events logged. All traffic verified clean.
                        </td>
                      </tr>
                    ) : (
                      quarantinedAlerts.map((alert) => {
                        const isCritical = alert.riskLevel === 'CRITICAL';
                        const isHigh = alert.riskLevel === 'HIGH';
                        const isSelected = selectedQuarantineIds.includes(alert.id);

                        return (
                          <tr
                            key={alert.id}
                            className={`transition-colors ${
                              isSelected ? 'bg-[#FCECF4]/60' : 'hover:bg-[#FCECF4]/35'
                            }`}
                          >
                            <td className="py-4 pl-5 pr-2">
                              <input
                                type="checkbox"
                                aria-label={`Select quarantined alert ${alert.reasonLabel}`}
                                checked={isSelected}
                                onChange={() => toggleQuarantineSelection(alert.id)}
                                className="h-4 w-4 rounded border-[#D8CEC0] accent-[#D9468F] cursor-pointer"
                              />
                            </td>
                            <td className="py-4 px-4 text-[#464451] whitespace-nowrap font-mono-tech">
                              {new Date(alert.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="py-4 px-5 font-semibold text-[#16161D] whitespace-nowrap">
                              {alert.reasonLabel}
                            </td>
                            <td className="py-4 px-5 text-[#464451] whitespace-nowrap">
                              <div className="text-[#16161D] font-medium">{alert.sourceApp}</div>
                              <div className="text-[11px] text-[#6F6C7A] font-mono-tech">{alert.sourceIp}</div>
                            </td>
                            <td className="py-4 px-5 text-[#464451] max-w-xs truncate leading-relaxed">
                              {alert.description}
                            </td>
                            <td className="py-4 px-5 whitespace-nowrap">
                              <span
                                className={`text-xs font-semibold ${
                                  isCritical
                                    ? 'text-[#B52A70]'
                                    : isHigh
                                    ? 'text-[#16161D]'
                                    : 'text-[#464451]'
                                }`}
                              >
                                {alert.riskLevel}
                              </span>
                            </td>
                            <td className="py-4 px-5 whitespace-nowrap">
                              <span
                                className={`text-xs font-semibold ${
                                  alert.status === 'BLOCKED'
                                    ? 'text-[#B52A70]'
                                    : alert.status === 'DISMISSED'
                                    ? 'text-[#6F6C7A]'
                                    : 'text-[#16161D]'
                                }`}
                              >
                                {alert.status}
                              </span>
                            </td>
                            <td className="py-4 px-5 text-right whitespace-nowrap">
                              <div className="flex items-center justify-end space-x-2">
                                <button
                                  onClick={() => setSelectedQuarantineAlert(alert)}
                                  className="px-3 py-1 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-xs transition-colors"
                                  title="Inspect Payload"
                                >
                                  Inspect
                                </button>
                                {alert.status === 'FLAGGED' && (
                                  <>
                                    <button
                                      onClick={() => handleQuarantineAction(alert.id, 'BLOCKED')}
                                      className="px-3 py-1 rounded-xl bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] text-xs transition-colors font-medium"
                                    >
                                      Block
                                    </button>
                                    <button
                                      onClick={() => handleQuarantineAction(alert.id, 'DISMISSED')}
                                      className="px-3 py-1 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#6F6C7A] border border-[#E5DDD0] text-xs transition-colors"
                                    >
                                      Dismiss
                                    </button>
                                  </>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Bulk Delete Confirmation Modal */}
            {showBulkDeleteQuarantineModal && (() => {
              const selectedAlerts = quarantinedAlerts.filter((a) =>
                selectedQuarantineIds.includes(a.id)
              );
              return (
                <div className="fixed inset-0 bg-[#16161D]/45 backdrop-blur-md z-50 flex items-center justify-center p-4">
                  <div className="bg-[#FFFDF9] border border-[#E5DDD0] rounded-3xl max-w-md w-full p-6 sm:p-7 space-y-5 shadow-2xl font-sans">
                    <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="w-8 h-8 rounded-xl bg-red-50 text-red-700 border border-red-200 flex items-center justify-center">
                          <AlertTriangle className="w-4 h-4" />
                        </div>
                        <h3 className="text-[#16161D] text-sm font-semibold">
                          Confirm Bulk Delete
                        </h3>
                      </div>
                      <button
                        type="button"
                        disabled={isBulkDeletingQuarantine}
                        onClick={() => setShowBulkDeleteQuarantineModal(false)}
                        className="p-1 rounded-full text-[#6F6C7A] hover:text-[#16161D] transition-colors disabled:opacity-40"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>

                    <div className="space-y-3 text-xs text-[#464451]">
                      <p className="leading-relaxed">
                        You are about to permanently remove{' '}
                        <strong className="text-[#16161D]">{selectedAlerts.length}</strong>{' '}
                        quarantined item{selectedAlerts.length === 1 ? '' : 's'} from the Security
                        Quarantine &amp; Anomaly Log. This action cannot be undone and is recorded in
                        the security telemetry audit trail.
                      </p>

                      {selectedAlerts.length > 0 && (
                        <div className="bg-[#FAF6F0] border border-[#E5DDD0] rounded-2xl p-3 space-y-2 max-h-44 overflow-y-auto">
                          {selectedAlerts.slice(0, 4).map((item) => (
                            <div
                              key={item.id}
                              className="flex items-center justify-between gap-2 text-[11px] border-b border-[#E5DDD0]/60 last:border-b-0 pb-1.5 last:pb-0"
                            >
                              <div className="truncate">
                                <span className="font-semibold text-[#16161D]">
                                  {item.reasonLabel}
                                </span>
                                <span className="text-[#6F6C7A] font-mono-tech">
                                  {' '}
                                  · {item.sourceIp}
                                </span>
                              </div>
                              <span className="font-semibold text-[#B52A70] shrink-0">
                                {item.riskLevel}
                              </span>
                            </div>
                          ))}
                          {selectedAlerts.length > 4 && (
                            <div className="text-[11px] text-[#6F6C7A] font-medium pt-0.5">
                              + {selectedAlerts.length - 4} more item(s)
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[#E5DDD0]">
                      <button
                        type="button"
                        disabled={isBulkDeletingQuarantine}
                        onClick={() => setShowBulkDeleteQuarantineModal(false)}
                        className="px-4 py-2 rounded-xl text-xs font-medium bg-[#F2ECE2] hover:bg-[#E5DDD0] text-[#464451] transition-colors disabled:opacity-50"
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        disabled={isBulkDeletingQuarantine || selectedAlerts.length === 0}
                        onClick={() => void handleBulkDeleteQuarantine()}
                        className="px-4 py-2 rounded-xl text-xs font-semibold bg-red-700 hover:bg-red-800 text-white transition-colors flex items-center space-x-1.5 disabled:opacity-50"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>
                          {isBulkDeletingQuarantine
                            ? 'Deleting...'
                            : `Delete ${selectedAlerts.length} Item${selectedAlerts.length === 1 ? '' : 's'}`}
                        </span>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Quarantine Detail Modal */}
            {selectedQuarantineAlert && (
              <div className="fixed inset-0 bg-[#16161D]/45 backdrop-blur-md z-50 flex items-center justify-center p-4">
                <div className="bg-[#FFFDF9] border border-[#E5DDD0] rounded-3xl max-w-lg w-full p-6 sm:p-7 space-y-5 shadow-2xl font-sans">
                  <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
                    <div className="flex items-center space-x-2.5">
                      <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                        <ShieldAlert className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="text-[#16161D] text-sm font-semibold">
                        Payload Inspection: {selectedQuarantineAlert.reasonLabel}
                      </h3>
                    </div>
                    <button
                      onClick={() => setSelectedQuarantineAlert(null)}
                      className="p-1 rounded-full text-[#6F6C7A] hover:text-[#16161D] transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div className="bg-[#FAF6F0] p-4 rounded-2xl border border-[#E5DDD0] space-y-2">
                      <div>
                        <strong className="text-[#6F6C7A] text-xs block mb-0.5">Anomaly Description</strong>
                        <span className="text-[#16161D] text-xs leading-relaxed">{selectedQuarantineAlert.description}</span>
                      </div>
                      <div className="pt-2 border-t border-[#E5DDD0] flex items-center justify-between">
                        <div>
                          <strong className="text-[#6F6C7A] text-xs block mb-0.5">Origin IP</strong>
                          <span className="text-[#16161D] font-mono-tech">{selectedQuarantineAlert.sourceIp}</span>
                        </div>
                        <div>
                          <strong className="text-[#6F6C7A] text-xs block mb-0.5">Risk Assessment</strong>
                          <span className="text-[#B52A70] font-bold">{selectedQuarantineAlert.riskLevel}</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <label className="text-xs font-medium text-[#464451] block mb-1.5">
                        Intercepted Raw Payload
                      </label>
                      <pre className="p-4 bg-[#16161D] border border-[#2A2935] rounded-2xl text-xs text-[#FAF6F0] overflow-x-auto max-h-52 font-mono-tech">
                        {JSON.stringify(selectedQuarantineAlert.rawPayload, null, 2)}
                      </pre>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-3 border-t border-[#E5DDD0]">
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => {
                          handleQuarantineAction(selectedQuarantineAlert.id, 'BLOCKED');
                          setSelectedQuarantineAlert(null);
                        }}
                        className="px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] transition-colors"
                      >
                        Block Source
                      </button>
                      <button
                        onClick={() => {
                          handleQuarantineAction(selectedQuarantineAlert.id, 'DISMISSED');
                          setSelectedQuarantineAlert(null);
                        }}
                        className="px-3.5 py-1.5 rounded-xl text-xs font-medium bg-[#F2ECE2] hover:bg-[#E5DDD0] text-[#464451] transition-colors"
                      >
                        Dismiss
                      </button>
                    </div>

                    <button
                      onClick={() => setSelectedQuarantineAlert(null)}
                      className="px-4 py-1.5 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all"
                    >
                      Close
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 3: CONNECTED APPS & NOTIFICATION CONTROLS
        ========================================================================== */}
        {activeTab === 'integrations' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 glass-panel p-6 rounded-2xl border border-[#E5DDD0]">
              <div className="space-y-1">
                <div className="flex items-center space-x-2.5">
                  <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                    <Layers className="w-4 h-4" />
                  </div>
                  <h2 className="font-display text-base font-semibold text-[#16161D]">
                    Connected Applications &amp; Delivery Nodes
                  </h2>
                </div>
                <p className="text-xs text-[#464451]">
                  Configure priority thresholds, mute noisy ingress sources, and retrieve webhook endpoints.
                </p>
              </div>

              <button
                onClick={() => setShowAddAppModal(true)}
                className="px-4 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] font-semibold text-xs transition-all flex items-center space-x-2 shrink-0 shadow-xs active:scale-95 whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5 text-[#F472B6]" />
                <span>Connect App</span>
              </button>
            </div>

            {/* Apps Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {connectedApps.map((app) => (
                <div
                  key={app.id}
                  className={`rounded-2xl border p-5 transition-all flex flex-col justify-between space-y-4 ${
                    app.enabled
                      ? 'glass-panel glass-panel-hover border-[#E5DDD0]'
                      : 'bg-[#F2ECE2]/60 border-[#E5DDD0] opacity-70'
                  }`}
                >
                  <div className="space-y-3.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="w-11 h-11 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] flex items-center justify-center p-2">
                          {renderAppIcon(app.iconName, 'w-6 h-6')}
                        </div>
                        <div>
                          <h3 className="text-[#16161D] text-sm font-semibold">{app.name}</h3>
                          <span className="text-[11px] font-mono-tech text-[#B52A70] font-medium">{app.category}</span>
                        </div>
                      </div>

                      <button
                        onClick={() => handleToggleApp(app)}
                        className={`px-3 py-1 rounded-full text-xs font-semibold transition-all flex items-center space-x-1.5 ${
                          app.enabled
                            ? 'bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC]'
                            : 'bg-[#FAF6F0] text-[#6F6C7A] border border-[#D8CEC0]'
                        }`}
                      >
                        <Power className="w-3 h-3" />
                        <span>{app.enabled ? 'ACTIVE' : 'MUTED'}</span>
                      </button>
                    </div>

                    <p className="text-xs text-[#464451] leading-relaxed min-h-[36px]">
                      {app.description}
                    </p>

                    <div className="space-y-2 pt-3 border-t border-[#E5DDD0] text-xs font-mono-tech">
                      <div className="flex items-center justify-between">
                        <span className="text-[#6F6C7A] text-[11px]">Filter:</span>
                        <select
                          value={app.rules.urgencyOverride}
                          onChange={(e) =>
                            handleUpdateAppRules(app.id, { urgencyOverride: e.target.value as any })
                          }
                          disabled={!app.enabled}
                          className="bg-[#FAF6F0] border border-[#D8CEC0] text-[#16161D] rounded-lg px-2.5 py-1 text-[11px] focus:outline-none focus:border-[#D9468F] disabled:opacity-50"
                        >
                          <option value="AUTO">Default Priority</option>
                          <option value="HIGH_ONLY">High Priority Only</option>
                          <option value="ALL_CRITICAL">Force Critical</option>
                        </select>
                      </div>

                      <div className="flex items-center justify-between">
                        <span className="text-[#464451] text-xs font-medium font-sans">Duplicate Shield:</span>
                        <button
                          onClick={() =>
                            handleUpdateAppRules(app.id, { filterDuplicates: !app.rules.filterDuplicates })
                          }
                          disabled={!app.enabled}
                          className={`text-xs font-semibold px-2 py-0.5 rounded-lg transition-colors font-sans ${
                            app.rules.filterDuplicates
                              ? 'bg-[#F0F7F4] text-[#15803D] border border-[#16A34A]/25'
                              : 'bg-[#F2ECE2] text-[#6F6C7A]'
                          }`}
                        >
                          {app.rules.filterDuplicates ? 'Enabled' : 'Disabled'}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-[#E5DDD0] flex items-center justify-between gap-2">
                    <button
                      onClick={() => handleTestApp(app.id)}
                      disabled={testingAppId === app.id}
                      className="px-3.5 py-1.5 rounded-xl text-xs font-medium bg-[#FAF6F0] hover:bg-[#FCECF4] text-[#16161D] border border-[#D8CEC0] hover:border-[#D9468F]/50 flex items-center space-x-1.5 transition-colors"
                    >
                      <Zap className="w-3.5 h-3.5 text-[#D9468F]" />
                      <span>{testingAppId === app.id ? 'Sending...' : 'Test Alert'}</span>
                    </button>

                    <button
                      onClick={() => setSelectedApp(app)}
                      className="px-3.5 py-1.5 rounded-xl text-xs text-[#464451] hover:text-[#16161D] flex items-center space-x-1 transition-colors hover:bg-[#F2ECE2]"
                    >
                      <span>Webhook Info</span>
                      <ChevronRight className="w-3.5 h-3.5 text-[#6F6C7A]" />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Webhook Drawer */}
            {selectedApp && (
              <div className="glass-panel border border-[#D8CEC0] rounded-3xl p-6 sm:p-7 space-y-4 shadow-lg">
                <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] flex items-center justify-center">
                      {renderAppIcon(selectedApp.iconName, 'w-5 h-5')}
                    </div>
                    <div>
                      <h3 className="text-[#16161D] text-sm font-semibold">
                        Webhook Configuration · {selectedApp.name}
                      </h3>
                      <p className="text-xs text-[#464451]">
                        Paste this endpoint and API key into your {selectedApp.name} settings
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedApp(null)}
                    className="p-1.5 rounded-full text-[#6F6C7A] hover:text-[#16161D] transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-[#464451] block">Webhook Endpoint</label>
                    <div className="flex items-center space-x-2">
                      <input
                        readOnly
                        value={`${window.location.origin}${selectedApp.webhookUrl}`}
                        className="flex-1 px-3 py-2 text-xs font-mono-tech bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none"
                      />
                      <button
                        onClick={() =>
                          copyToClipboard(`${window.location.origin}${selectedApp.webhookUrl}`, 'hook')
                        }
                        className="p-2.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all shadow-xs"
                        title="Copy Webhook URL"
                      >
                        {copiedKey === 'hook' ? <Check className="w-4 h-4 text-[#F472B6]" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-[#464451] block">App API Key</label>
                    <div className="flex items-center space-x-2">
                      <input
                        readOnly
                        value={selectedApp.apiKey}
                        className="flex-1 px-3 py-2 text-xs font-mono-tech bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none"
                      />
                      <button
                        onClick={() => copyToClipboard(selectedApp.apiKey, 'key')}
                        className="p-2.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all shadow-xs"
                        title="Copy API Key"
                      >
                        {copiedKey === 'key' ? <Check className="w-4 h-4 text-[#F472B6]" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* =========================================================================
            TAB 4: DELIVERY & SECURITY RULES + FIRESTORE PREFERENCES
        ========================================================================== */}
        {activeTab === 'rules' && (
          <div className="max-w-3xl space-y-6">
            {/* Persistent User Notification Preferences */}
            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                      <Database className="w-4 h-4" />
                    </div>
                    <h2 className="font-display text-base font-semibold text-[#16161D]">
                      Notification Preferences &amp; Cloud Sync
                    </h2>
                  </div>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    {firebaseUser
                      ? `Synced to your verified Firebase profile (${firebaseUser.email || firebaseUser.phoneNumber || firebaseUser.uid}).`
                      : 'Saved locally in this browser. Sign in with Google or Firebase Phone Auth to sync across devices.'}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={handleSavePreferences}
                  disabled={isSavingPrefs}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] shadow-xs flex items-center space-x-1.5 disabled:opacity-60 shrink-0 whitespace-nowrap"
                >
                  <Save className="w-3.5 h-3.5" />
                  <span>{isSavingPrefs ? 'Saving...' : 'Save Preferences'}</span>
                </button>
              </div>

              {prefsFeedback && (
                <div
                  className={`p-3 rounded-xl border text-xs flex items-center space-x-2 ${
                    prefsFeedback.type === 'success'
                      ? 'bg-[#F0F7F4] border-[#16A34A]/30 text-[#14532D]'
                      : 'bg-[#FDF2F6] border-[#D9468F]/40 text-[#88134A]'
                  }`}
                >
                  {prefsFeedback.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-[#D9468F] shrink-0" />
                  )}
                  <span>{prefsFeedback.message}</span>
                </div>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="pref-dnd-toggle" className="text-xs font-semibold text-[#16161D]">
                      Do Not Disturb (Quiet Hours)
                    </label>
                    <input
                      id="pref-dnd-toggle"
                      type="checkbox"
                      checked={dndEnabled}
                      onChange={(e) => setDndEnabled(e.target.checked)}
                      className="h-4 w-4 rounded border-[#D8CEC0] bg-[#FFFDF9] text-[#D9468F] focus:ring-[#D9468F]"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <div>
                      <span className="text-[11px] text-[#6F6C7A] block mb-1">Start (HH:MM)</span>
                      <input
                        type="time"
                        value={quietHoursStart}
                        onChange={(e) => setQuietHoursStart(e.target.value)}
                        className="w-full px-2.5 py-1.5 text-xs bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D] font-mono tabular-nums"
                      />
                    </div>
                    <div>
                      <span className="text-[11px] text-[#6F6C7A] block mb-1">End (HH:MM)</span>
                      <input
                        type="time"
                        value={quietHoursEnd}
                        onChange={(e) => setQuietHoursEnd(e.target.value)}
                        className="w-full px-2.5 py-1.5 text-xs bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D] font-mono tabular-nums"
                      />
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-3">
                  <div>
                    <label htmlFor="pref-channel-select" className="text-xs font-semibold text-[#16161D] block mb-1">
                      Preferred Dispatch Channel
                    </label>
                    <select
                      id="pref-channel-select"
                      value={preferredChannel}
                      onChange={(e) => setPreferredChannel(e.target.value as any)}
                      className="w-full px-3 py-1.5 text-xs bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D]"
                    >
                      <option value="WEBSOCKET">WebSocket Live Stream</option>
                      <option value="WEBPUSH">Browser WebPush</option>
                      <option value="WHATSAPP">WhatsApp Business</option>
                      <option value="SMS">Mobile SMS</option>
                      <option value="EMAIL">Nodemailer Email</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="pref-threshold-select" className="text-xs font-semibold text-[#16161D] block mb-1">
                      Minimum Priority Threshold
                    </label>
                    <select
                      id="pref-threshold-select"
                      value={minPriorityThreshold}
                      onChange={(e) => setMinPriorityThreshold(e.target.value as any)}
                      className="w-full px-3 py-1.5 text-xs bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D]"
                    >
                      <option value="LOW">LOW (All alerts)</option>
                      <option value="MEDIUM">MEDIUM &amp; above</option>
                      <option value="HIGH">HIGH &amp; CRITICAL only</option>
                      <option value="CRITICAL">CRITICAL only</option>
                    </select>
                  </div>

                  <div>
                    <label htmlFor="pref-whatsapp-phone" className="text-xs font-semibold text-[#16161D] block mb-1">
                      WhatsApp Business Number (E.164)
                    </label>
                    <input
                      id="pref-whatsapp-phone"
                      type="tel"
                      value={whatsappPhone}
                      onChange={(e) => {
                        setWhatsappPhone(e.target.value);
                        if (whatsappPrefsError) setWhatsappPrefsError(null);
                      }}
                      placeholder="+919876543210"
                      className="w-full px-3 py-1.5 text-xs font-mono-tech bg-[#FFFDF9] border border-[#D8CEC0] rounded-xl text-[#16161D]"
                    />
                    {whatsappPrefsError && (
                      <p className="text-[11px] text-[#B52A70] mt-1 font-medium">{whatsappPrefsError}</p>
                    )}
                  </div>
                </div>
              </div>

              {/* Multi-Channel Fallback Opt-Outs & Critical Quiet-Hours Bypass */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor="pref-critical-bypass"
                      className="text-xs font-semibold text-[#16161D]"
                    >
                      Allow CRITICAL Alerts to Bypass Quiet Hours
                    </label>
                    <input
                      id="pref-critical-bypass"
                      type="checkbox"
                      checked={allowCriticalBypassQuietHours}
                      onChange={(e) => setAllowCriticalBypassQuietHours(e.target.checked)}
                      className="h-4 w-4 rounded border-[#D8CEC0] bg-[#FFFDF9] text-[#D9468F] focus:ring-[#D9468F]"
                    />
                  </div>
                  <p className="text-[11px] text-[#6F6C7A] leading-relaxed">
                    When disabled, even CRITICAL alerts defer to your In-App Inbox during Quiet Hours.
                  </p>
                </div>

                <div className="p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] space-y-2">
                  <div className="text-xs font-semibold text-[#16161D]">
                    Per-Channel Opt-Outs (Fallback State Machine)
                  </div>
                  <div className="flex flex-wrap items-center gap-4 pt-1 text-xs text-[#464451]">
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={optOutPush}
                        onChange={(e) => setOptOutPush(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F]"
                      />
                      <span>Mute Push</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={optOutWhatsapp}
                        onChange={(e) => setOptOutWhatsapp(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F]"
                      />
                      <span>Mute WhatsApp</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={optOutSms}
                        onChange={(e) => setOptOutSms(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F]"
                      />
                      <span>Mute SMS</span>
                    </label>
                    <label className="flex items-center space-x-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={optOutEmail}
                        onChange={(e) => setOptOutEmail(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-[#D8CEC0] text-[#D9468F]"
                      />
                      <span>Mute Email</span>
                    </label>
                  </div>
                </div>
              </div>
            </div>

            {/* Settings: Channel & Persistence Readiness + Firestore TTL Reminder */}
            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-7 h-7 rounded-lg bg-[#16161D] text-[#F472B6] flex items-center justify-center">
                      <Activity className="w-4 h-4" />
                    </div>
                    <h2 className="font-display text-base font-semibold text-[#16161D]">
                      Gateway &amp; Persistence Readiness
                    </h2>
                  </div>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Live backend configuration checks from OTP, WhatsApp, SMS, and system health endpoints.
                  </p>
                </div>
                <span className="text-[11px] font-mono-tech text-[#6F6C7A] whitespace-nowrap">
                  Store: {channelGatewayStatus.dbMode}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {[
                  {
                    label: 'Email SMTP',
                    isLive:
                      channelGatewayStatus.emailSmtpConfigured ||
                      (channelGatewayStatus.emailConfigured && channelGatewayStatus.emailVerified),
                    detail:
                      channelGatewayStatus.emailSmtpConfigured || channelGatewayStatus.emailConfigured
                        ? 'SMTP configured'
                        : 'Ethereal / preview fallback',
                  },
                  {
                    label: 'WhatsApp Cloud API',
                    isLive: channelGatewayStatus.whatsappConfigured,
                    detail: channelGatewayStatus.whatsappConfigured
                      ? 'Meta Graph v21.0 live'
                      : 'Dry-run / credentials unset',
                  },
                  {
                    label: 'SMS OTP',
                    isLive: channelGatewayStatus.twilioConfigured || (!channelGatewayStatus.smsDemoMode && smsStatus.smsConfigured),
                    detail: channelGatewayStatus.twilioConfigured ? 'Twilio Verify active' : 'Allowlist demo mode',
                  },
                  {
                    label: 'Fast2SMS',
                    isLive: channelGatewayStatus.fast2smsConfigured,
                    detail: channelGatewayStatus.fast2smsConfigured ? 'API key configured' : 'Mock dispatch fallback',
                  },
                  {
                    label: 'DB Persistence',
                    isLive: channelGatewayStatus.dbLive,
                    detail: channelGatewayStatus.dbLive ? 'External DB connected' : 'Local JSON fallback',
                  },
                ].map((item) => (
                  <div
                    key={item.label}
                    className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-3.5 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-[#16161D]">{item.label}</span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold border whitespace-nowrap ${
                          item.isLive
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : 'bg-amber-50 text-amber-800 border-amber-200'
                        }`}
                      >
                        {item.isLive ? 'LIVE' : 'DEMO / UNCONFIGURED'}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#6F6C7A]">{item.detail}</p>
                  </div>
                ))}
              </div>

              <div className="rounded-2xl bg-amber-50/85 border border-amber-200 px-4 py-3 flex items-start gap-2.5 text-xs text-amber-950">
                <Clock className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <div className="font-semibold">
                    Firestore Ephemeral TTL Policy Reminder
                  </div>
                  <p className="text-[11px] text-amber-900 leading-relaxed">
                    While the server sweeper crypto-shreds expired vault records every 5s, remember to enable a{' '}
                    <span className="font-mono-tech font-semibold">Firestore TTL policy on ephemeralMessages.expireAt</span>{' '}
                    in the Firebase Console so any synced ephemeral metadata documents auto-delete at the database layer.
                  </p>
                </div>
              </div>
            </div>

            {/* Settings: Verify & Link Your Phone (SMS OTP Login + 2FA) */}
            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                      <Smartphone className="w-4 h-4" />
                    </div>
                    <h2 className="font-display text-base font-semibold text-[#16161D]">
                      Verify your phone
                    </h2>
                    {smsStatus.demoMode && (
                      <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC]">
                        Demo Mode
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Link a verified mobile number to your profile so you can sign in with SMS OTP or use it as a second factor.
                  </p>
                </div>

                {verifiedPhoneInfo?.phoneVerified && verifiedPhoneInfo?.maskedPhone && (
                  <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-[#F0F7F4] border border-[#16A34A]/30 text-[#14532D] text-xs font-semibold shrink-0">
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#16A34A]" />
                    <span className="font-mono">{verifiedPhoneInfo.maskedPhone}</span>
                  </div>
                )}
              </div>

              {phoneLinkFeedback && (
                <div
                  className={`p-3 rounded-xl border text-xs flex items-center space-x-2 ${
                    phoneLinkFeedback.type === 'success'
                      ? 'bg-[#F0F7F4] border-[#16A34A]/30 text-[#14532D]'
                      : 'bg-[#FDF2F6] border-[#D9468F]/40 text-[#88134A]'
                  }`}
                >
                  {phoneLinkFeedback.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-[#D9468F] shrink-0" />
                  )}
                  <span>{phoneLinkFeedback.message}</span>
                </div>
              )}

              {phoneLinkStep === 'enter' ? (
                <form onSubmit={handleSendPhoneLinkSms} className="space-y-3">
                  <div className="flex flex-col sm:flex-row gap-2.5">
                    <select
                      value={phoneLinkCountry}
                      onChange={(e) => setPhoneLinkCountry(e.target.value)}
                      className="bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-3 py-2.5 text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
                      title="Country Code"
                    >
                      {smsStatus.allowedCountries.map((cc) => (
                        <option key={cc} value={cc} className="bg-[#FFFDF9] text-[#16161D]">
                          {cc}
                        </option>
                      ))}
                    </select>

                    <input
                      type="tel"
                      inputMode="numeric"
                      value={phoneLinkInput}
                      onChange={(e) => setPhoneLinkInput(e.target.value)}
                      placeholder="e.g. 9876543210"
                      required
                      className="flex-1 bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-2.5 text-xs text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono tabular-nums"
                    />

                    <button
                      type="submit"
                      disabled={isSendingLinkSms || !phoneLinkInput.trim()}
                      className="px-4 py-2.5 rounded-2xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center justify-center space-x-1.5 disabled:opacity-50 whitespace-nowrap shrink-0"
                    >
                      {isSendingLinkSms ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#F472B6]" />
                          <span>Sending...</span>
                        </>
                      ) : (
                        <>
                          <Smartphone className="w-3.5 h-3.5 text-[#F472B6]" />
                          <span>Send SMS Code</span>
                        </>
                      )}
                    </button>
                  </div>

                  {smsStatus.demoMode && (
                    <p className="text-[11px] text-[#6F6C7A] leading-relaxed">
                      Demo Mode active: use an allowlisted number (default <span className="font-mono font-semibold text-[#464451]">+919876543210</span>) and code <span className="font-mono font-semibold text-[#464451]">123456</span>.
                    </p>
                  )}
                </form>
              ) : (
                <form onSubmit={handleVerifyPhoneLinkSms} className="space-y-3">
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                    <input
                      type="text"
                      inputMode="numeric"
                      maxLength={6}
                      value={phoneLinkCode}
                      onChange={(e) => setPhoneLinkCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="Enter 6-digit code"
                      required
                      className="flex-1 bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-2.5 text-sm text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono tracking-widest"
                    />

                    <button
                      type="submit"
                      disabled={isVerifyingLinkSms || phoneLinkCode.length !== 6}
                      className="px-5 py-2.5 rounded-2xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] transition-all flex items-center justify-center space-x-1.5 disabled:opacity-50 whitespace-nowrap shrink-0"
                    >
                      {isVerifyingLinkSms ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Verifying...</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Verify</span>
                        </>
                      )}
                    </button>
                  </div>

                  <div className="flex items-center justify-between text-xs text-[#6F6C7A]">
                    <button
                      type="button"
                      onClick={() => {
                        setPhoneLinkStep('enter');
                        setPhoneLinkFeedback(null);
                      }}
                      className="text-[#464451] hover:text-[#16161D] underline"
                    >
                      Change phone number
                    </button>

                    {phoneLinkCooldown > 0 ? (
                      <span className="font-mono tabular-nums">
                        Resend in <strong className="text-[#B52A70]">{phoneLinkCooldown}s</strong>
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleSendPhoneLinkSms()}
                        disabled={isSendingLinkSms}
                        className="text-[#B52A70] hover:text-[#16161D] underline font-medium"
                      >
                        Resend SMS code
                      </button>
                    )}
                  </div>
                </form>
              )}
            </div>

            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-6">
              <div className="space-y-1.5">
                <div className="flex items-center space-x-2.5">
                  <div className="w-7 h-7 rounded-lg bg-[#16161D] text-[#F472B6] flex items-center justify-center">
                    <Sliders className="w-4 h-4" />
                  </div>
                  <h2 className="font-display text-base font-semibold text-[#16161D]">
                    Notification Architecture &amp; Safeguards
                  </h2>
                </div>
                <p className="text-xs text-[#464451] leading-relaxed">
                  Core algorithms managing priority classification, noise suppression, and zero-trust threat isolation.
                </p>
              </div>

              <div className="border-t border-[#E5DDD0] pt-5 flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <h4 className="font-semibold text-[#16161D] text-xs">Priority Classification &amp; Overrides</h4>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Users can re-tag or override priority scores dynamically. Messages satisfying priority thresholds dispatch instantly to connected screens.
                  </p>
                </div>
                <span className="text-xs font-medium text-[#B52A70] whitespace-nowrap shrink-0">
                  Dynamic Override
                </span>
              </div>

              <div className="border-t border-[#E5DDD0] pt-5 flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <h4 className="font-semibold text-[#16161D] text-xs">Unauthenticated Threat Isolation</h4>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Ingress traffic lacking valid API keys or signature tokens is quarantined instantly into the security isolation log.
                  </p>
                </div>
                <span className="text-xs font-medium text-[#16161D] whitespace-nowrap shrink-0">
                  Zero-Trust Gate
                </span>
              </div>

              <div className="border-t border-[#E5DDD0] pt-5 flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <h4 className="font-semibold text-[#16161D] text-xs">Automated Multi-Channel Fallback SLA</h4>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Critical alerts unacknowledged on screen after 3,000ms automatically escalate to secondary Nodemailer (Email), WebPush API (Instant device alerts), and Fast2SMS channels.
                  </p>
                </div>
                <span className="text-xs font-medium text-[#464451] font-mono tabular-nums whitespace-nowrap shrink-0">
                  3,000ms SLA
                </span>
              </div>
            </div>

            {/* Settings: Permissions & Privacy */}
            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-8 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2.5">
                    <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                      <ShieldCheck className="w-4 h-4" />
                    </div>
                    <h2 className="font-display text-base font-semibold text-[#16161D]">
                      Permissions &amp; Privacy
                    </h2>
                  </div>
                  <p className="text-xs text-[#464451] leading-relaxed">
                    Inspect browser notification access, grant or revoke catalog consent, disconnect webhooks, or delete stored connection data.
                  </p>
                </div>

                <span
                  className={`px-3 py-1 rounded-full text-[11px] font-semibold border whitespace-nowrap self-start sm:self-center ${
                    consentState?.consentGranted && !consentState?.revoked
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      : 'bg-amber-50 text-amber-800 border-amber-200'
                  }`}
                >
                  {consentState?.consentGranted && !consentState?.revoked
                    ? 'Consent Active'
                    : 'Consent Revoked / Off'}
                </span>
              </div>

              {privacyFeedback && (
                <div
                  className={`rounded-xl px-4 py-2.5 text-xs border ${
                    privacyFeedback.type === 'success'
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
                      : 'bg-red-50 border-red-200 text-red-700'
                  }`}
                >
                  {privacyFeedback.message}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-[#16161D]">
                      Browser Notifications:{' '}
                      <span className="font-mono-tech uppercase text-[#B52A70]">
                        {webPushPermission}
                      </span>
                    </p>
                    <p className="text-[11px] text-[#6F6C7A] mt-1">
                      Only triggered when you click the button below. If blocked, allow notifications in your browser&apos;s site settings.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleReRequestNotifications()}
                    className="px-3.5 py-2 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold self-start whitespace-nowrap"
                  >
                    Re-request Notification Permission
                  </button>
                </div>

                <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-[#16161D]">
                      Catalog &amp; Encrypted Storage Consent
                    </p>
                    <p className="text-[11px] text-[#6F6C7A] mt-1">
                      Policy {consentState?.policyVersion || '2026.11'} · Consent{' '}
                      {consentState?.consentVersion || 'v1'}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {consentState?.consentGranted && !consentState?.revoked ? (
                      <button
                        type="button"
                        onClick={() => void handleTogglePrivacyConsent(false)}
                        disabled={privacyActionBusy}
                        className="px-3.5 py-2 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#16161D] text-xs font-semibold whitespace-nowrap disabled:opacity-50"
                      >
                        Revoke Consent
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void handleTogglePrivacyConsent(true)}
                        disabled={privacyActionBusy}
                        className="px-3.5 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] text-xs font-semibold whitespace-nowrap disabled:opacity-50"
                      >
                        Grant Consent
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={() => setShowOnboardingModal(true)}
                      className="px-3.5 py-2 rounded-xl border border-[#D8CEC0] bg-[#FFFDF9] hover:bg-[#F2ECE2] text-[#464451] text-xs font-semibold whitespace-nowrap"
                    >
                      Re-open Onboarding
                    </button>
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-[#E5DDD0] flex flex-wrap items-center justify-between gap-3">
                <p className="text-[11px] text-[#6F6C7A]">
                  Destructive controls immediately purge server-side encrypted webhook secrets and/or your saved app marks.
                </p>
                <div className="flex flex-wrap items-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => void handleDisconnectAllConnections()}
                    disabled={privacyActionBusy}
                    className="px-3.5 py-2 rounded-xl border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-900 text-xs font-semibold whitespace-nowrap disabled:opacity-50"
                  >
                    Disconnect Everything
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDeleteAllConnectionData()}
                    disabled={privacyActionBusy}
                    className="px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap disabled:opacity-50"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete All Connection Data</span>
                  </button>
                </div>
              </div>

              <div className="pt-4 border-t border-[#E5DDD0] flex items-center justify-between gap-4">
                <div className="space-y-0.5">
                  <div className="text-xs font-semibold text-[#16161D] flex items-center space-x-1.5">
                    <EyeOff className="w-3.5 h-3.5 text-[#D9468F]" />
                    <span>Privacy Shield (Focus Blur for Ephemeral Messages)</span>
                  </div>
                  <p className="text-[11px] text-[#6F6C7A]">
                    Automatically blurs decrypted ephemeral plaintext whenever the browser tab loses focus or switches windows.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={privacyShieldEnabled}
                  onChange={(e) => setPrivacyShieldEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F] shrink-0"
                />
              </div>
            </div>

            {/* Settings: Dynamic Sigmoid Priority Engine Personalization */}
            <MyPrioritiesSettingsSection
              userId={vaultUserId}
              firebaseUid={firebaseUser?.uid || null}
              onModelUpdated={(updatedModel) => setUserPriorityModel(updatedModel)}
            />

            {/* Settings: On-Device Semantic Deduplication (ONNX NLP) */}
            <DedupSettingsSection
              userId={vaultUserId}
              firebaseUid={firebaseUser?.uid || null}
              onSettingsUpdated={(updatedDedup) => setUserDedupSettings(updatedDedup)}
            />

            {/* Settings: Zero-Trust Ed25519 Signing Keys & Transparency Log */}
            <SigningKeysSettingsSection
              userId={vaultUserId}
              unlockedKey={unlockedSigningKey}
              onUnlockedKeyChange={setUnlockedSigningKey}
            />

            {/* Settings: Sign-in Methods, Recent Sign-ins & Session Security */}
            <AccountSecuritySettingsSection
              userId={vaultUserId}
              userEmail={user?.email}
              token={typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null}
              firebaseUser={firebaseUser}
              onForceLogoutAll={handleSecureLogout}
            />
          </div>
        )}

        {/* =========================================================================
            TAB 4: DELIVERY CHANNELS & FALLBACK ESCALATION (NODEMAILER, WEBPUSH, FAST2SMS)
        ========================================================================== */}
        {activeTab === 'channels' && (
          <div className="space-y-6">
            {/* Header */}
            <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 sm:p-7 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-2.5">
                  <div className="w-8 h-8 rounded-xl bg-[#16161D] text-[#F472B6] flex items-center justify-center">
                    <Smartphone className="w-4 h-4" />
                  </div>
                  <div>
                    <h2 className="font-display text-base font-semibold text-[#16161D]">Delivery Gateways &amp; Secondary Fallback SLA</h2>
                    <p className="text-xs text-[#464451]">Zero-Trust WebSocket → WebPush API → WhatsApp Business → Fast2SMS → Nodemailer Email</p>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3">
                <button
                  onClick={() => handleTestFallbackChannel('ALL')}
                  disabled={testingChannel !== null}
                  className="px-4 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] transition-all shadow-xs flex items-center space-x-1.5 active:scale-95 whitespace-nowrap"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{testingChannel === 'ALL' ? 'Dispatched...' : 'Test All Fallbacks'}</span>
                </button>
              </div>
            </div>

            {/* Gateway & Persistence Readiness Badges */}
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              {[
                {
                  label: 'Email SMTP',
                  isLive:
                    channelGatewayStatus.emailSmtpConfigured ||
                    (channelGatewayStatus.emailConfigured && channelGatewayStatus.emailVerified),
                },
                {
                  label: 'WhatsApp Cloud API',
                  isLive: channelGatewayStatus.whatsappConfigured,
                },
                {
                  label: 'SMS OTP',
                  isLive: channelGatewayStatus.twilioConfigured || (!channelGatewayStatus.smsDemoMode && smsStatus.smsConfigured),
                },
                {
                  label: 'Fast2SMS',
                  isLive: channelGatewayStatus.fast2smsConfigured,
                },
                {
                  label: 'DB Persistence',
                  isLive: channelGatewayStatus.dbLive,
                },
              ].map((ch) => (
                <div
                  key={ch.label}
                  className="glass-panel border border-[#E5DDD0] rounded-2xl px-4 py-3 flex items-center justify-between gap-2"
                >
                  <span className="text-xs font-semibold text-[#16161D]">{ch.label}</span>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold border whitespace-nowrap ${
                      ch.isLive
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-amber-50 text-amber-800 border-amber-200'
                    }`}
                  >
                    {ch.isLive ? 'LIVE' : 'DEMO / UNCONFIGURED'}
                  </span>
                </div>
              ))}
            </div>

            {/* 4 Grid Gateway Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
              {/* Card 1: Nodemailer Email Service */}
              <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="w-9 h-9 rounded-2xl bg-[#FCECF4] border border-[#F2C4DC] text-[#B52A70] flex items-center justify-center">
                      <Mail className="w-4 h-4" />
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold border whitespace-nowrap ${
                        channelGatewayStatus.emailSmtpConfigured ||
                        (channelGatewayStatus.emailConfigured && channelGatewayStatus.emailVerified)
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}
                    >
                      {channelGatewayStatus.emailSmtpConfigured ||
                      (channelGatewayStatus.emailConfigured && channelGatewayStatus.emailVerified)
                        ? 'LIVE'
                        : 'DEMO / UNCONFIGURED'}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-[#16161D] text-sm font-bold">Email Dispatch</h3>
                    <p className="text-xs text-[#464451] leading-relaxed pt-1">
                      HTML formatted alerts with metadata and signed ACK link via SMTP or Ethereal sandbox preview.
                    </p>
                  </div>

                  <div className="space-y-1.5 pt-1">
                    <label className="text-[11px] font-medium text-[#464451] block">Recipient Email</label>
                    <input
                      type="email"
                      value={channelTestTargetEmail}
                      onChange={(e) => setChannelTestTargetEmail(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono-tech bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                      placeholder="user@example.com"
                    />
                  </div>
                </div>

                <div className="pt-4 border-t border-[#E5DDD0]">
                  <button
                    onClick={() => handleTestFallbackChannel('EMAIL')}
                    disabled={testingChannel !== null}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center justify-center space-x-1.5 shadow-xs active:scale-95"
                  >
                    <Mail className="w-3.5 h-3.5 text-[#F472B6]" />
                    <span>{testingChannel === 'EMAIL' ? 'Delivering...' : 'Send Test Email'}</span>
                  </button>
                </div>
              </div>

              {/* Card 2: WebPush API */}
              <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="w-9 h-9 rounded-2xl bg-[#16161D] text-[#FAF6F0] flex items-center justify-center">
                      <Bell className="w-4 h-4 text-[#F472B6]" />
                    </div>
                    <span className="text-[11px] font-semibold text-[#16161D]">
                      WebPush API
                    </span>
                  </div>

                  <div>
                    <h3 className="text-[#16161D] text-sm font-bold">Instant Device Alerts</h3>
                    <p className="text-xs text-[#464451] leading-relaxed pt-1">
                      Direct browser &amp; mobile notification popups paired via VAPID service worker subscription.
                    </p>
                  </div>

                  <div className="p-3 bg-[#FAF6F0] rounded-2xl border border-[#E5DDD0] space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-[#464451]">Push Permission:</span>
                      <span className={`font-semibold capitalize ${webPushPermission === 'granted' || isSubscribedPush ? 'text-[#15803D]' : 'text-[#B52A70]'}`}>
                        {isSubscribedPush ? 'Paired & Active' : (typeof Notification !== 'undefined' ? Notification.permission : 'Standard')}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#6F6C7A]">
                      Standardized WebPush payload with vibration &amp; zero-trust tags.
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-[#E5DDD0] space-y-2">
                  <button
                    onClick={handleSubscribeWebPush}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] transition-all flex items-center justify-center space-x-1.5 shadow-xs active:scale-95"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Pair Device Push</span>
                  </button>
                  <button
                    onClick={() => handleTestFallbackChannel('WEBPUSH')}
                    disabled={testingChannel !== null}
                    className="w-full py-2 rounded-xl text-xs font-semibold bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] transition-all flex items-center justify-center space-x-1.5"
                  >
                    <span>Trigger Push Dispatch</span>
                  </button>
                </div>
              </div>

              {/* Card 3: Meta WhatsApp Business Cloud API */}
              <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="w-9 h-9 rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center">
                      <MessageSquare className="w-4 h-4" />
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold border whitespace-nowrap ${
                        channelGatewayStatus.whatsappConfigured
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}
                    >
                      {channelGatewayStatus.whatsappConfigured ? 'LIVE' : 'DRY-RUN / UNSET'}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-[#16161D] text-sm font-bold">WhatsApp Cloud API</h3>
                    <p className="text-xs text-[#464451] leading-relaxed pt-1">
                      Meta Graph API v21.0 fallback immediately after Push with strict zero-plaintext ephemeral protection.
                    </p>
                  </div>

                  <div className="space-y-1.5 pt-1">
                    <label className="text-[11px] font-medium text-[#464451] block">
                      Recipient WhatsApp (E.164)
                    </label>
                    <input
                      type="tel"
                      value={channelTestTargetWhatsapp}
                      onChange={(e) => setChannelTestTargetWhatsapp(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono-tech bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                      placeholder="+919876543210"
                    />
                  </div>
                </div>

                <div className="pt-4 border-t border-[#E5DDD0]">
                  <button
                    onClick={() => handleTestFallbackChannel('WHATSAPP')}
                    disabled={testingChannel !== null}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center justify-center space-x-1.5 shadow-xs active:scale-95"
                  >
                    <MessageSquare className="w-3.5 h-3.5 text-emerald-400" />
                    <span>{testingChannel === 'WHATSAPP' ? 'Sending...' : 'Send Test WhatsApp Alert'}</span>
                  </button>
                </div>
              </div>

              {/* Card 4: Fast2SMS Gateway */}
              <div className="glass-panel border border-[#E5DDD0] rounded-3xl p-6 space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="w-9 h-9 rounded-2xl bg-[#F2ECE2] border border-[#E5DDD0] text-[#16161D] flex items-center justify-center">
                      <Smartphone className="w-4 h-4" />
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-mono-tech font-semibold border whitespace-nowrap ${
                        channelGatewayStatus.fast2smsConfigured
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}
                    >
                      {channelGatewayStatus.fast2smsConfigured ? 'LIVE' : 'DEMO / UNCONFIGURED'}
                    </span>
                  </div>

                  <div>
                    <h3 className="text-[#16161D] text-sm font-bold">Fast2SMS Gateway</h3>
                    <p className="text-xs text-[#464451] leading-relaxed pt-1">
                      Direct mobile SMS delivery powered by Fast2SMS Quick / OTP Bulk V2 routes with automated fallback.
                    </p>
                  </div>

                  <div className="space-y-2 pt-1">
                    <div className="flex items-center justify-between">
                      <label className="text-[11px] font-medium text-[#464451] block">
                        Target Mobile (FAST2SMS_TARGET_PHONE)
                      </label>
                      {user?.phoneNumber && (
                        <button
                          type="button"
                          onClick={() => handleSaveFast2SmsTargetPhone(user.phoneNumber)}
                          className="text-[10px] text-[#B52A70] hover:text-[#16161D] underline font-medium"
                        >
                          Use My Mobile
                        </button>
                      )}
                    </div>
                    <div className="flex space-x-2">
                      <input
                        type="tel"
                        value={channelTestTargetPhone}
                        onChange={(e) => setChannelTestTargetPhone(e.target.value)}
                        className="flex-1 px-3 py-2 text-xs font-mono-tech bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35"
                        placeholder="Enter mobile number e.g. 9876543210"
                      />
                      <button
                        type="button"
                        onClick={() => handleSaveFast2SmsTargetPhone()}
                        disabled={isSavingTargetPhone || !channelTestTargetPhone.trim()}
                        className="px-3 py-2 text-[11px] font-semibold bg-[#FCECF4] hover:bg-[#F8DCEB] text-[#B52A70] border border-[#F2C4DC] rounded-xl transition-all disabled:opacity-50 active:scale-95 whitespace-nowrap"
                      >
                        {isSavingTargetPhone ? 'Saving...' : 'Set Target'}
                      </button>
                    </div>
                    <div className="flex items-center justify-between pt-0.5 text-[10px]">
                      <span className="text-[#6F6C7A] font-mono-tech">
                        Active: {activeTargetPhoneDisplay || channelTestTargetPhone || 'Not set'}
                      </span>
                      {savePhoneFeedback && (
                        <span className="text-[#15803D] font-medium">
                          {savePhoneFeedback}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="pt-4 border-t border-[#E5DDD0]">
                  <button
                    onClick={() => handleTestFallbackChannel('FAST2SMS')}
                    disabled={testingChannel !== null}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] transition-all flex items-center justify-center space-x-1.5 shadow-xs active:scale-95"
                  >
                    <Smartphone className="w-3.5 h-3.5 text-[#F472B6]" />
                    <span>{testingChannel === 'FAST2SMS' ? 'Sending SMS...' : 'Send Fast2SMS Alert'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Test Results Output Banner */}
            {channelTestResult && (
              <div className="glass-panel border border-[#D8CEC0] rounded-2xl p-5 space-y-3 shadow-sm">
                <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-2">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-[#D9468F]" />
                    <h4 className="text-xs font-bold text-[#16161D] tracking-wide">
                      Dispatch Diagnostics Result ({channelTestResult.testedChannel || 'Response'})
                    </h4>
                  </div>
                  {channelTestResult.timestamp && (
                    <span className="text-[11px] text-[#6F6C7A] font-mono-tech">
                      {new Date(channelTestResult.timestamp).toLocaleTimeString()}
                    </span>
                  )}
                </div>

                {typeof channelTestResult?.results?.email?.previewUrl === 'string' &&
                  channelTestResult.results.email.previewUrl.startsWith('http') && (
                    <div className="rounded-xl bg-emerald-50 border border-emerald-200 px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="text-xs text-emerald-950">
                        <span className="font-semibold">Ethereal Test Inbox Preview Ready:</span>{' '}
                        Open the captured HTML email in Nodemailer&apos;s sandbox inbox.
                      </div>
                      <a
                        href={channelTestResult.results.email.previewUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-semibold whitespace-nowrap"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>View Email Preview</span>
                      </a>
                    </div>
                  )}

                <div className="text-xs font-mono-tech bg-[#16161D] p-3.5 rounded-xl text-[#FAF6F0] overflow-x-auto border border-[#2A2935]">
                  <pre>{JSON.stringify(channelTestResult.results || channelTestResult, null, 2)}</pre>
                </div>
              </div>
            )}
          </div>
        )}


        {/* =========================================================================
            TAB 5: AUDIT LOG
        ========================================================================== */}
        {activeTab === 'history' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between glass-panel p-5 rounded-2xl border border-[#E5DDD0]">
              <div className="flex items-center space-x-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                  <Clock className="w-4 h-4" />
                </div>
                <h3 className="font-display text-base font-semibold text-[#16161D]">
                  Verified Notification Audit Stream
                </h3>
              </div>
              <button
                onClick={fetchTelemetry}
                className="px-3.5 py-1.5 rounded-xl bg-[#FAF6F0] hover:bg-[#F2ECE2] text-[#16161D] border border-[#D8CEC0] text-xs transition-colors flex items-center space-x-1.5 font-medium"
              >
                <RefreshCw className="w-3.5 h-3.5 text-[#D9468F]" />
                <span>Refresh</span>
              </button>
            </div>

            <div className="glass-panel border border-[#E5DDD0] rounded-2xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-sans">
                  <thead className="bg-[#F2ECE2] text-[#464451] text-[11px] font-semibold border-b border-[#E5DDD0]">
                    <tr>
                      <th className="py-3 px-5">Time</th>
                      <th className="py-3 px-5">Event Type</th>
                      <th className="py-3 px-5">Summary</th>
                      <th className="py-3 px-5">Priority</th>
                      <th className="py-3 px-5">Channels</th>
                      <th className="py-3 px-5">Authenticity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E5DDD0]">
                    {notifications.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-[#6F6C7A]">
                          No audit history records found.
                        </td>
                      </tr>
                    ) : (
                      notifications.map((log) => (
                        <tr key={log.notificationId} className="hover:bg-[#FCECF4]/35 transition-colors">
                          <td className="py-4 px-5 text-[#464451] whitespace-nowrap font-mono-tech">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="py-4 px-5 font-semibold text-[#16161D] whitespace-nowrap">
                            {log.eventType}
                          </td>
                          <td className="py-4 px-5 text-[#464451] max-w-xs truncate leading-relaxed">
                            {log.rawText}
                          </td>
                          <td className="py-4 px-5 whitespace-nowrap">
                            <span
                              className={`text-xs font-semibold ${
                                log.priority === 'CRITICAL'
                                  ? 'text-[#B52A70]'
                                  : log.priority === 'HIGH'
                                  ? 'text-[#16161D]'
                                  : 'text-[#464451]'
                              }`}
                            >
                              {log.priority || 'MEDIUM'}
                            </span>
                          </td>
                          <td className="py-4 px-5 whitespace-nowrap text-xs text-[#6F6C7A]">
                            {(log.channelsUsed || ['WEBSOCKET']).join(', ')}
                          </td>
                          <td className="py-4 px-5 whitespace-nowrap">
                            <span className="text-[#15803D] font-medium flex items-center space-x-1.5">
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>Verified</span>
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            TAB 6: APP CATALOG & DIRECT CONNECTIONS
        ========================================================================== */}
        {activeTab === 'catalog' && (
          <ErrorBoundary fallbackTitle="App Catalog Error">
            <AppCatalogConnections
              userId={effectiveUserId}
              consentState={consentState}
              onConsentUpdated={(next) => setConsentState(next)}
              onSimulatedNotification={handleSendCatalogSimulatedNotification}
              onIngestSuccess={fetchTelemetry}
              externalConnectionsVersion={catalogConnectionsVersion}
            />
          </ErrorBoundary>
        )}

        {/* =========================================================================
            TAB 7: SECURITY TELEMETRY (ADMIN ONLY)
        ========================================================================== */}
        {activeTab === 'telemetry' && (
          <ErrorBoundary fallbackTitle="Security Telemetry Error">
            <SecurityTelemetryPage user={user} />
          </ErrorBoundary>
        )}

        {/* =========================================================================
            TAB 8: GEMINI AI ASSISTANT
        ========================================================================== */}
        {activeTab === 'chat' && (
          <ErrorBoundary fallbackTitle="Gemini AI Assistant Error">
            <GeminiChatbot
              recentAlertsSummary={[
                ...notifications.slice(0, 6).map(
                  (n) =>
                    `[Alert ${n.priority || 'MEDIUM'}] ${n.eventType}: ${n.rawText} (${n.status || 'ACTIVE'})`
                ),
                ...quarantinedAlerts.slice(0, 4).map(
                  (q) =>
                    `[Quarantined ${q.status} • ${q.riskLevel}] ${q.reasonLabel} from ${q.sourceIp}: ${q.description}`
                ),
              ].join('\n')}
            />
          </ErrorBoundary>
        )}
      </main>

      {showOnboardingModal && (
        <OnboardingModal
          userId={effectiveUserId}
          userEmail={user?.email || firebaseUser?.email || undefined}
          onComplete={(nextState) => {
            setConsentState(nextState);
            setShowOnboardingModal(false);
            if (typeof window !== 'undefined' && 'Notification' in window) {
              setWebPushPermission(Notification.permission);
            }
          }}
        />
      )}

      {/* Add App Modal */}
      {showAddAppModal && (
        <div className="fixed inset-0 bg-[#16161D]/45 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-[#FFFDF9] border border-[#E5DDD0] rounded-3xl max-w-md w-full p-6 sm:p-7 space-y-5 shadow-2xl font-sans">
            <div className="flex items-center justify-between border-b border-[#E5DDD0] pb-3">
              <h3 className="text-[#16161D] text-sm font-semibold flex items-center space-x-2">
                <div className="w-6 h-6 rounded-lg bg-[#FCECF4] text-[#B52A70] flex items-center justify-center">
                  <Plus className="w-4 h-4" />
                </div>
                <span>Connect External Application</span>
              </h3>
              <button
                onClick={() => setShowAddAppModal(false)}
                className="p-1 rounded-full text-[#6F6C7A] hover:text-[#16161D] transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleAddNewApp} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#464451] mb-1">Application Name</label>
                <input
                  type="text"
                  placeholder="e.g. Sentry, GitLab, Billing Engine"
                  value={newAppName}
                  onChange={(e) => setNewAppName(e.target.value)}
                  className="w-full px-3.5 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#464451] mb-1">Category</label>
                <select
                  value={newAppCategory}
                  onChange={(e) => setNewAppCategory(e.target.value as any)}
                  className="w-full px-3.5 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F]"
                >
                  <option value="Dev">Developer / CI / Cloud</option>
                  <option value="Chat">Team Chat &amp; Messaging</option>
                  <option value="Payments">Payments &amp; Billing</option>
                  <option value="Security">Security &amp; Audit</option>
                  <option value="Custom">Custom Service</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-[#464451] mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="App description..."
                  value={newAppDesc}
                  onChange={(e) => setNewAppDesc(e.target.value)}
                  className="w-full px-3.5 py-2 text-xs bg-[#FAF6F0] border border-[#D8CEC0] rounded-xl text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] resize-none"
                />
              </div>

              <div className="pt-3 border-t border-[#E5DDD0] flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setShowAddAppModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-[#6F6C7A] hover:text-[#16161D] transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl text-xs font-semibold bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] transition-all shadow-xs active:scale-95"
                >
                  Create Webhook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <ProvenanceDetailsDrawer
        report={inspectedProvenanceReport}
        onClose={() => setInspectedProvenanceReport(null)}
        onPinOverridden={() => {
          setInspectedProvenanceReport(null);
          invalidateClientProvenanceCaches();
          fetchTelemetry();
        }}
      />

      <PriorityWhyDrawer
        item={inspectedPriorityItem}
        onClose={() => setInspectedPriorityItem(null)}
        onFeedbackSubmitted={(_kind, result) => {
          if (result?.updatedState) {
            setUserPriorityModel(result.updatedState);
          }
        }}
      />

      <DedupWhyDrawer
        target={inspectedDedupTarget}
        onClose={() => setInspectedDedupTarget(null)}
        onUngroup={handleUngroupThread}
        onMarkNotDuplicate={handleMarkNotDuplicate}
      />
    </div>
  );
}
