import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import firebaseConfig from '../../../firebase-applet-config.json' with { type: 'json' };
import {
  formatMachineState,
  isTerminalState,
  transition,
  type DeliveryChannel,
  type DeliveryEventType,
  type DeliveryStateName,
} from './stateMachine.js';
import {
  normalizePriority,
  resolveEffectiveDeliveryPlan,
  type DeliveryPriority,
  type DeliveryUserPreferences,
} from './policies.js';
import { getAllBreakerStatuses, type BreakerChannel } from './circuitBreaker.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';
import type {
  DeliveryHistoryEntry,
  DeliveryJobRecord,
  DemoFaultConfig,
} from './channels/types.js';

const DELIVERY_JOBS_FILE = path.resolve(process.cwd(), '.aegis-delivery-jobs.json');
const MAX_PERSISTED_JOBS = 500;
const LEASE_TTL_MS = 10_000;

declare global {
  var __aegisDeliveryJobsMap: Map<string, DeliveryJobRecord> | undefined;
  var __aegisDeliveryIdempotencyMap: Map<string, string> | undefined;
  var __aegisDeliveryJobsHydrated: boolean | undefined;
  var __aegisDeliveryMutexPromise: Promise<void> | undefined;
}

/**
 * In-process async mutex ensuring transactional lease/update serialization
 * across concurrent worker ticks and API requests.
 */
export async function withDeliveryLock<T>(fn: () => Promise<T> | T): Promise<T> {
  const prev = global.__aegisDeliveryMutexPromise || Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  global.__aegisDeliveryMutexPromise = prev.then(() => next);
  await prev;
  try {
    return await fn();
  } finally {
    release();
  }
}

function hydrateDeliveryStore(): {
  jobs: Map<string, DeliveryJobRecord>;
  idempotency: Map<string, string>;
} {
  if (!global.__aegisDeliveryJobsMap) {
    global.__aegisDeliveryJobsMap = new Map();
  }
  if (!global.__aegisDeliveryIdempotencyMap) {
    global.__aegisDeliveryIdempotencyMap = new Map();
  }

  if (!global.__aegisDeliveryJobsHydrated) {
    global.__aegisDeliveryJobsHydrated = true;
    try {
      if (fs.existsSync(DELIVERY_JOBS_FILE)) {
        const raw = fs.readFileSync(DELIVERY_JOBS_FILE, 'utf8');
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          for (const item of list) {
            if (item && typeof item.id === 'string' && typeof item.state === 'string') {
              const job = item as DeliveryJobRecord;
              global.__aegisDeliveryJobsMap.set(job.id, job);
              if (job.idempotencyKey) {
                global.__aegisDeliveryIdempotencyMap.set(job.idempotencyKey, job.id);
              }
            }
          }
        }
      }
    } catch {
      // Non-fatal if persistence file does not exist yet or cannot be read
    }
  }

  return {
    jobs: global.__aegisDeliveryJobsMap,
    idempotency: global.__aegisDeliveryIdempotencyMap,
  };
}

function persistDeliveryStore(): void {
  try {
    const { jobs } = hydrateDeliveryStore();
    const sorted = Array.from(jobs.values())
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
      .slice(0, MAX_PERSISTED_JOBS);

    const tmpPath = `${DELIVERY_JOBS_FILE}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(sorted, null, 2), 'utf8');
    fs.renameSync(tmpPath, DELIVERY_JOBS_FILE);
  } catch {
    // Keep operational even on read-only disk environments
  }
}

/**
 * Best-effort authenticated Firestore REST sync when a Firebase ID Token is supplied by the caller.
 * Preserves Eight Pillars firestore.rules strictly because it runs with the user's verified token.
 */
export async function syncDeliveryJobToFirestoreRest(
  job: DeliveryJobRecord,
  firebaseIdToken?: string
): Promise<boolean> {
  if (!firebaseIdToken || !firebaseConfig?.projectId || !firebaseConfig?.firestoreDatabaseId) {
    return false;
  }

  const cleanUid = job.userId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
  const cleanJobId = job.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
  if (!cleanUid || !cleanJobId) return false;

  const docUrl = `https://firestore.googleapis.com/v1/projects/${firebaseConfig.projectId}/databases/${firebaseConfig.firestoreDatabaseId}/documents/users/${cleanUid}/deliveryJobs/${cleanJobId}`;

  const fields = {
    id: { stringValue: cleanJobId },
    uid: { stringValue: cleanUid },
    notificationId: { stringValue: job.notificationId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128) },
    priority: { stringValue: job.priority },
    state: { stringValue: job.state },
    channel: { stringValue: job.channel },
    attempt: { integerValue: String(job.attempt) },
    nextAttemptAt: { stringValue: job.nextAttemptAt },
    idempotencyKey: { stringValue: job.idempotencyKey.slice(0, 160) },
    history: {
      arrayValue: {
        values: job.history.slice(-20).map((h) => ({
          mapValue: {
            fields: {
              timestamp: { stringValue: h.timestamp },
              from: { stringValue: h.from },
              event: { stringValue: h.event },
              to: { stringValue: h.to },
              channel: { stringValue: h.channel },
              result: { stringValue: h.result.slice(0, 180) },
            },
          },
        })),
      },
    },
    createdAt: { timestampValue: job.createdAt },
    updatedAt: { timestampValue: job.updatedAt },
  };

  try {
    const res = await fetch(docUrl, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${firebaseIdToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ fields }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Simulates a server restart by wiping all in-memory maps and forcing
 * re-hydration directly from durable storage (.aegis-delivery-jobs.json).
 */
export function simulateServerRestartReload(): { reloadedCount: number } {
  global.__aegisDeliveryJobsMap = undefined;
  global.__aegisDeliveryIdempotencyMap = undefined;
  global.__aegisDeliveryJobsHydrated = false;
  const { jobs } = hydrateDeliveryStore();
  return { reloadedCount: jobs.size };
}

export interface CreateDeliveryJobInput {
  notificationId: string;
  userId: string;
  priority?: string;
  idempotencyKey?: string;
  recipientEmail?: string;
  recipientPhone?: string;
  userPreferences?: DeliveryUserPreferences | null;
  baseUrl?: string;
  isDemoJob?: boolean;
  demoFaults?: DemoFaultConfig;
  isEphemeral?: boolean;
  ephemeralTtlSeconds?: number;
  ephemeralExpiresAt?: string;
  firebaseIdToken?: string;
}

export async function createDeliveryJob(input: CreateDeliveryJobInput): Promise<{
  job: DeliveryJobRecord;
  created: boolean;
  idempotentReplay: boolean;
  skippedReasons: string[];
}> {
  return await withDeliveryLock(async () => {
    const { jobs, idempotency } = hydrateDeliveryStore();
    const idempotencyKey = (
      input.idempotencyKey?.trim() ||
      `notif:${input.userId}:${input.notificationId}`
    ).slice(0, 160);

    const existingId = idempotency.get(idempotencyKey);
    if (existingId) {
      const existingJob = jobs.get(existingId);
      if (existingJob) {
        return {
          job: structuredClone(existingJob),
          created: false,
          idempotentReplay: true,
          skippedReasons: [],
        };
      }
    }

    const now = Date.now();
    const nowIso = new Date(now).toISOString();
    const priority: DeliveryPriority = normalizePriority(input.priority);
    const plan = resolveEffectiveDeliveryPlan(priority, input.userPreferences, {
      now: new Date(now),
      demoShortTimeouts: Boolean(input.isDemoJob && input.demoFaults?.shortTimeouts),
    });

    const jobId = `dlv_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
    const firstChannel: DeliveryChannel = plan.channels[0] || 'in_app';
    let expiresAtMs = now + plan.policy.ttlMs;
    if (input.isEphemeral && input.ephemeralExpiresAt) {
      const ephExpMs = Date.parse(input.ephemeralExpiresAt);
      if (Number.isFinite(ephExpMs) && ephExpMs < expiresAtMs) {
        expiresAtMs = ephExpMs;
      }
    }
    const expiresAt = new Date(expiresAtMs).toISOString();

    const job: DeliveryJobRecord = {
      id: jobId,
      notificationId: input.notificationId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128),
      userId: input.userId.slice(0, 128),
      priority,
      state: 'QUEUED',
      channel: firstChannel,
      channelChain: plan.channels.length > 0 ? plan.channels : ['in_app'],
      channelIndex: 0,
      attempt: 0,
      requiresAck: plan.requiresAck,
      ackTimeoutMs: plan.ackTimeoutMs,
      maxRetriesPerChannel: plan.maxRetriesPerChannel,
      nextAttemptAt: nowIso,
      expiresAt,
      history: [
        {
          timestamp: nowIso,
          from: 'QUEUED',
          event: 'CREATE',
          to: 'QUEUED',
          channel: firstChannel,
          result:
            plan.skippedReasons.length > 0
              ? `Queued (${plan.skippedReasons.join('; ')})`
              : `Queued for ${plan.channels.join(' -> ')}`,
        },
      ],
      idempotencyKey,
      ...(input.recipientEmail ? { recipientEmail: input.recipientEmail } : {}),
      ...(input.recipientPhone ? { recipientPhone: input.recipientPhone } : {}),
      ...(input.baseUrl ? { baseUrl: input.baseUrl } : {}),
      ...(input.isDemoJob ? { isDemoJob: true } : {}),
      ...(input.demoFaults ? { demoFaults: input.demoFaults } : {}),
      ...(input.isEphemeral ? { isEphemeral: true } : {}),
      ...(typeof input.ephemeralTtlSeconds === 'number'
        ? { ephemeralTtlSeconds: input.ephemeralTtlSeconds }
        : {}),
      leaseOwner: null,
      leaseExpiresAt: null,
      acknowledgedAt: null,
      acknowledgedVia: null,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    jobs.set(job.id, job);
    idempotency.set(job.idempotencyKey, job.id);
    persistDeliveryStore();

    void syncDeliveryJobToFirestoreRest(job, input.firebaseIdToken);

    logSecurityEvent({
      eventType: 'DELIVERY_CREATED',
      severity: 'info',
      result: 'success',
      userId: job.userId,
      email: job.recipientEmail,
      details: `Delivery job ${job.id} created (${job.priority}, plan=${job.channelChain.join(' -> ')}${job.isDemoJob ? ', DEMO' : ''}).`,
    });

    return {
      job: structuredClone(job),
      created: true,
      idempotentReplay: false,
      skippedReasons: plan.skippedReasons,
    };
  });
}

export async function getDeliveryJobById(jobId: string): Promise<DeliveryJobRecord | null> {
  const { jobs } = hydrateDeliveryStore();
  const job = jobs.get(jobId);
  return job ? structuredClone(job) : null;
}

export async function listDeliveryJobs(filters: {
  userId?: string;
  isAdmin?: boolean;
  state?: string;
  priority?: string;
  limit?: number;
  includeDemo?: boolean;
} = {}): Promise<DeliveryJobRecord[]> {
  const { jobs } = hydrateDeliveryStore();
  const stateFilter = (filters.state || '').trim().toUpperCase();
  const priorityFilter = (filters.priority || '').trim().toUpperCase();
  const limit = Math.min(200, Math.max(1, Number(filters.limit) || 100));

  let list = Array.from(jobs.values());

  if (!filters.isAdmin && filters.userId) {
    list = list.filter((j) => j.userId === filters.userId);
  }

  if (filters.includeDemo === false) {
    list = list.filter((j) => !j.isDemoJob);
  }

  if (stateFilter) {
    list = list.filter((j) => j.state === stateFilter);
  }

  if (priorityFilter) {
    list = list.filter((j) => j.priority === priorityFilter);
  }

  list.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  return list.slice(0, limit).map((j) => structuredClone(j));
}

export async function listDueDeliveryJobIds(now: number = Date.now()): Promise<string[]> {
  const { jobs } = hydrateDeliveryStore();
  const due: string[] = [];
  for (const job of jobs.values()) {
    if (isTerminalState(job.state)) continue;
    const dueMs = Date.parse(job.nextAttemptAt);
    const expMs = Date.parse(job.expiresAt);
    if ((Number.isFinite(expMs) && now >= expMs) || (Number.isFinite(dueMs) && now >= dueMs)) {
      due.push(job.id);
    }
  }
  return due;
}

export async function acquireJobLease(
  jobId: string,
  workerId: string,
  now: number = Date.now()
): Promise<DeliveryJobRecord | null> {
  return await withDeliveryLock(() => {
    const { jobs } = hydrateDeliveryStore();
    const job = jobs.get(jobId);
    if (!job || isTerminalState(job.state)) return null;

    if (job.leaseOwner && job.leaseExpiresAt) {
      const leaseExp = Date.parse(job.leaseExpiresAt);
      if (Number.isFinite(leaseExp) && leaseExp > now && job.leaseOwner !== workerId) {
        return null;
      }
    }

    job.leaseOwner = workerId;
    job.leaseExpiresAt = new Date(now + LEASE_TTL_MS).toISOString();
    return structuredClone(job);
  });
}

export async function releaseJobLease(jobId: string, workerId: string): Promise<void> {
  await withDeliveryLock(() => {
    const { jobs } = hydrateDeliveryStore();
    const job = jobs.get(jobId);
    if (!job) return;
    if (job.leaseOwner === workerId) {
      job.leaseOwner = null;
      job.leaseExpiresAt = null;
      persistDeliveryStore();
    }
  });
}

export async function updateDeliveryJobRecord(
  jobId: string,
  mutator: (job: DeliveryJobRecord) => void,
  firebaseIdToken?: string
): Promise<DeliveryJobRecord | null> {
  return await withDeliveryLock(async () => {
    const { jobs } = hydrateDeliveryStore();
    const job = jobs.get(jobId);
    if (!job) return null;
    mutator(job);
    job.updatedAt = new Date().toISOString();
    persistDeliveryStore();
    void syncDeliveryJobToFirestoreRest(job, firebaseIdToken);
    return structuredClone(job);
  });
}

export async function applyStateTransitionToJob(params: {
  jobId: string;
  event: DeliveryEventType;
  targetChannel?: DeliveryChannel;
  nextChannel?: DeliveryChannel | null;
  canRetry?: boolean;
  requiresAck?: boolean;
  resultText: string;
  nextAttemptAt?: string;
  incrementAttempt?: boolean;
  resetAttempt?: boolean;
  advanceChannelIndex?: boolean;
  acknowledgedVia?: string;
  firebaseIdToken?: string;
}): Promise<DeliveryJobRecord> {
  return await withDeliveryLock(async () => {
    const { jobs } = hydrateDeliveryStore();
    const job = jobs.get(params.jobId);
    if (!job) {
      throw new Error(`Delivery job ${params.jobId} not found.`);
    }

    const res = transition(
      { state: job.state, channel: job.channel },
      {
        type: params.event,
        channel: params.targetChannel,
        nextChannel: params.nextChannel,
        canRetry: params.canRetry,
        requiresAck: params.requiresAck,
      }
    );

    const nowIso = new Date().toISOString();
    const entry: DeliveryHistoryEntry = {
      timestamp: nowIso,
      from: res.from.state,
      event: params.event,
      to: res.to.state,
      channel: res.to.channel === 'none' ? res.from.channel : res.to.channel,
      result: params.resultText.slice(0, 220),
    };

    job.state = res.to.state;
    job.channel = res.to.channel;

    if (params.resetAttempt) {
      job.attempt = 0;
    } else if (params.incrementAttempt) {
      job.attempt += 1;
    }

    if (params.advanceChannelIndex) {
      job.channelIndex = Math.min(job.channelChain.length, job.channelIndex + 1);
    }

    if (params.nextAttemptAt) {
      job.nextAttemptAt = params.nextAttemptAt;
    }

    if (res.to.state === 'DELIVERED_ACKED') {
      job.acknowledgedAt = nowIso;
      job.acknowledgedVia = params.acknowledgedVia || formatMachineState(res.to);
    }

    job.history.push(entry);
    if (job.history.length > 50) {
      job.history = job.history.slice(-50);
    }
    job.updatedAt = nowIso;

    persistDeliveryStore();
    void syncDeliveryJobToFirestoreRest(job, params.firebaseIdToken);
    return structuredClone(job);
  });
}

/**
 * Transitions all non-terminal delivery jobs matching an ephemeral notification ID
 * to EXPIRED so no fallback SMS or email is ever dispatched after burn/expiry.
 */
export async function expireDeliveryJobsByNotificationId(
  notificationId: string,
  reason: string = 'Associated ephemeral item expired or burned; delivery job expired.'
): Promise<number> {
  const safeId = notificationId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  return await withDeliveryLock(() => {
    const { jobs } = hydrateDeliveryStore();
    let expiredCount = 0;
    const nowIso = new Date().toISOString();

    for (const job of jobs.values()) {
      if ((job.notificationId === notificationId || job.notificationId === safeId) && !isTerminalState(job.state)) {
        const res = transition(
          { state: job.state, channel: job.channel },
          { type: 'EXPIRE' }
        );
        job.history.push({
          timestamp: nowIso,
          from: res.from.state,
          event: 'EXPIRE',
          to: res.to.state,
          channel: res.to.channel === 'none' ? res.from.channel : res.to.channel,
          result: reason.slice(0, 220),
        });
        if (job.history.length > 50) {
          job.history = job.history.slice(-50);
        }
        job.state = res.to.state;
        job.channel = res.to.channel;
        job.updatedAt = nowIso;
        expiredCount += 1;
      }
    }

    if (expiredCount > 0) {
      persistDeliveryStore();
    }
    return expiredCount;
  });
}

const DELIVERY_RANK: Record<DeliveryPriority, number> = {
  LOW: 0,
  NORMAL: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/**
 * Promotes an active unacked delivery job's priority at most once when the
 * Dynamic Sigmoid Priority engine escalates a notification across thresholds.
 * Respects user channel opt-outs, quiet hours, and circuit-breaker limits.
 */
export async function promoteDeliveryJobPriorityOnce(params: {
  notificationId: string;
  userId: string;
  newPriority: string;
  userPreferences?: DeliveryUserPreferences | null;
}): Promise<{ promoted: boolean; job?: DeliveryJobRecord; reason?: string }> {
  const safeId = params.notificationId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const nextPriority = normalizePriority(params.newPriority);

  return await withDeliveryLock(() => {
    const { jobs } = hydrateDeliveryStore();
    for (const job of jobs.values()) {
      if (job.userId !== params.userId) continue;
      if (job.notificationId !== params.notificationId && job.notificationId !== safeId) continue;
      if (isTerminalState(job.state)) {
        return { promoted: false, reason: 'Job already in terminal state.' };
      }
      if (job.priorityPromotedOnce) {
        return { promoted: false, reason: 'Delivery job already promoted once by priority escalation.' };
      }
      if (DELIVERY_RANK[nextPriority] <= DELIVERY_RANK[job.priority]) {
        return { promoted: false, reason: 'New priority is not higher than current delivery priority.' };
      }

      const plan = resolveEffectiveDeliveryPlan(nextPriority, params.userPreferences, {
        now: new Date(),
      });
      const prevPriority = job.priority;
      job.priority = nextPriority;
      job.priorityPromotedOnce = true;
      job.channelChain = plan.channels.length > 0 ? plan.channels : job.channelChain;
      job.requiresAck = plan.requiresAck;
      job.ackTimeoutMs = plan.ackTimeoutMs;
      job.maxRetriesPerChannel = plan.maxRetriesPerChannel;
      job.updatedAt = new Date().toISOString();
      job.history.push({
        timestamp: job.updatedAt,
        from: job.state,
        event: 'PRIORITY_ESCALATED',
        to: job.state,
        channel: job.channel,
        result: `Escalated ${prevPriority} -> ${nextPriority} (plan=${job.channelChain.join(' -> ')})`,
      });
      if (job.history.length > 50) {
        job.history = job.history.slice(-50);
      }

      persistDeliveryStore();
      return { promoted: true, job: structuredClone(job) };
    }
    return { promoted: false, reason: 'No matching active delivery job found.' };
  });
}

/**
 * Suppresses creating a duplicate SMS/email delivery job when a notification joins an
 * existing deduplicated thread, appending "duplicate suppressed" to the primary job's history.
 */
export async function suppressDuplicateDeliveryForThread(params: {
  userId: string;
  primaryNotificationId: string;
  duplicateNotificationId: string;
  threadId: string;
  similarity: number;
}): Promise<{ suppressed: boolean; job?: DeliveryJobRecord; reason?: string }> {
  const safePrimary = params.primaryNotificationId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const pct = Math.round(Math.max(0, Math.min(1, params.similarity)) * 100);

  return await withDeliveryLock(() => {
    const { jobs } = hydrateDeliveryStore();
    for (const job of jobs.values()) {
      if (job.userId !== params.userId) continue;
      if (job.notificationId !== params.primaryNotificationId && job.notificationId !== safePrimary) {
        continue;
      }

      const nowIso = new Date().toISOString();
      job.updatedAt = nowIso;
      job.history.push({
        timestamp: nowIso,
        from: job.state,
        event: 'DEDUP_SUPPRESSED',
        to: job.state,
        channel: job.channel,
        result: `duplicate suppressed (${params.duplicateNotificationId} merged into ${params.threadId}, ${pct}% sim)`,
      });
      if (job.history.length > 50) {
        job.history = job.history.slice(-50);
      }

      persistDeliveryStore();
      return { suppressed: true, job: structuredClone(job) };
    }
    return { suppressed: false, reason: 'No existing delivery job found for thread.' };
  });
}

export interface DeliveryStatsSummary {
  totalJobs: number;
  countsByState: Record<DeliveryStateName, number>;
  deliveredCount: number;
  inProgressCount: number;
  failedCount: number;
  averageTimeToAckMs: number;
  fallbackRatePercent: number;
  channelMetrics: Array<{
    channel: BreakerChannel;
    attempts: number;
    successes: number;
    failures: number;
    successRatePercent: number;
    circuitState: string;
    consecutiveFailures: number;
  }>;
  circuitBreakers: ReturnType<typeof getAllBreakerStatuses>;
  generatedAt: string;
}

export async function getDeliveryStats(options: {
  userId?: string;
  isAdmin?: boolean;
} = {}): Promise<DeliveryStatsSummary> {
  const { jobs } = hydrateDeliveryStore();
  let list = Array.from(jobs.values());
  if (!options.isAdmin && options.userId) {
    list = list.filter((j) => j.userId === options.userId);
  }

  const countsByState: Record<DeliveryStateName, number> = {
    QUEUED: 0,
    ATTEMPTING: 0,
    AWAITING_ACK: 0,
    RETRY_WAIT: 0,
    FALLBACK: 0,
    DELIVERED_ACKED: 0,
    FAILED_ALL_CHANNELS: 0,
    CANCELLED: 0,
    EXPIRED: 0,
  };

  let ackDurationSum = 0;
  let ackDurationCount = 0;
  let fallbackTriggeredJobs = 0;

  const perChannelStats: Record<BreakerChannel, { attempts: number; successes: number; failures: number }> = {
    push: { attempts: 0, successes: 0, failures: 0 },
    sms: { attempts: 0, successes: 0, failures: 0 },
    email: { attempts: 0, successes: 0, failures: 0 },
  };

  for (const job of list) {
    countsByState[job.state] = (countsByState[job.state] || 0) + 1;

    if (job.state === 'DELIVERED_ACKED' && job.acknowledgedAt) {
      const startMs = Date.parse(job.createdAt);
      const endMs = Date.parse(job.acknowledgedAt);
      if (Number.isFinite(startMs) && Number.isFinite(endMs) && endMs >= startMs) {
        ackDurationSum += endMs - startMs;
        ackDurationCount += 1;
      }
    }

    let jobHadFallback = false;
    for (const h of job.history) {
      if (h.to === 'FALLBACK') {
        jobHadFallback = true;
      }
      const ch = h.channel as BreakerChannel;
      if (ch === 'push' || ch === 'sms' || ch === 'email') {
        if (h.event === 'SEND_OK' || (h.event === 'ACK_RECEIVED' && h.from === 'AWAITING_ACK')) {
          if (h.event === 'SEND_OK') {
            perChannelStats[ch].attempts += 1;
            perChannelStats[ch].successes += 1;
          }
        } else if (h.event === 'SEND_FAILED' || h.event === 'ACK_TIMEOUT') {
          perChannelStats[ch].attempts += 1;
          perChannelStats[ch].failures += 1;
        }
      }
    }

    if (jobHadFallback) {
      fallbackTriggeredJobs += 1;
    }
  }

  const breakers = getAllBreakerStatuses('live');
  const breakerMap = new Map(breakers.map((b) => [b.channel, b]));

  const channelMetrics = (['push', 'sms', 'email'] as BreakerChannel[]).map((ch) => {
    const raw = perChannelStats[ch];
    const br = breakerMap.get(ch);
    const successRatePercent =
      raw.attempts > 0 ? Math.round((raw.successes / raw.attempts) * 100) : 100;
    return {
      channel: ch,
      attempts: raw.attempts,
      successes: raw.successes,
      failures: raw.failures,
      successRatePercent,
      circuitState: br?.state || 'CLOSED',
      consecutiveFailures: br?.consecutiveFailures || 0,
    };
  });

  const deliveredCount = countsByState.DELIVERED_ACKED;
  const failedCount = countsByState.FAILED_ALL_CHANNELS + countsByState.EXPIRED;
  const inProgressCount =
    countsByState.QUEUED +
    countsByState.ATTEMPTING +
    countsByState.AWAITING_ACK +
    countsByState.RETRY_WAIT +
    countsByState.FALLBACK;

  return {
    totalJobs: list.length,
    countsByState,
    deliveredCount,
    inProgressCount,
    failedCount,
    averageTimeToAckMs:
      ackDurationCount > 0 ? Math.round(ackDurationSum / ackDurationCount) : 0,
    fallbackRatePercent:
      list.length > 0 ? Math.round((fallbackTriggeredJobs / list.length) * 100) : 0,
    channelMetrics,
    circuitBreakers: breakers,
    generatedAt: new Date().toISOString(),
  };
}
