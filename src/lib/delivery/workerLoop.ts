import crypto from 'crypto';
import {
  acquireJobLease,
  applyStateTransitionToJob,
  getDeliveryJobById,
  listDueDeliveryJobIds,
  releaseJobLease,
} from './deliveryStore.js';
import { calculateBackoffMs } from './policies.js';
import {
  canAttemptChannel,
  recordChannelFailure,
  recordChannelSuccess,
  type BreakerChannel,
} from './circuitBreaker.js';
import { buildSignedAckUrl } from './ackTokens.js';
import { checkAndRecordUserChannelLimit, getChannelAdapter } from './channels/index.js';
import type { DeliveryJobRecord } from './channels/types.js';
import { isTerminalState, type DeliveryChannel } from './stateMachine.js';
import { logSecurityEvent } from '../telemetry/securityLogger.js';

const WORKER_INSTANCE_ID = `worker_${process.pid}_${crypto.randomBytes(3).toString('hex')}`;
const DEFAULT_WORKER_INTERVAL_MS = 2_000;

declare global {
  var __aegisDeliveryWorkerTimer: ReturnType<typeof setInterval> | undefined;
  var __aegisDeliveryTickBusy: boolean | undefined;
}

function getNextChannelForJob(job: DeliveryJobRecord): DeliveryChannel | null {
  const nextIdx = job.channelIndex + 1;
  if (nextIdx >= job.channelChain.length) return null;
  return job.channelChain[nextIdx] || null;
}

function formatTimeoutDuration(ms: number): string {
  if (ms >= 60_000) {
    const mins = Math.round(ms / 60_000);
    return `${mins}m`;
  }
  const secs = Math.max(1, Math.round(ms / 1000));
  return `${secs}s`;
}

export async function processSingleDeliveryJob(
  jobId: string,
  options: { now?: number; shortDemoBackoffMs?: number } = {}
): Promise<DeliveryJobRecord | null> {
  const now = options.now ?? Date.now();
  const leased = await acquireJobLease(jobId, WORKER_INSTANCE_ID, now);
  if (!leased) {
    return await getDeliveryJobById(jobId);
  }

  let current = leased;
  const namespace: 'live' | 'sim' = current.isDemoJob ? 'sim' : 'live';

  try {
    // 1. Expiration check on non-terminal job
    const expiresMs = Date.parse(current.expiresAt);
    if (!isTerminalState(current.state) && Number.isFinite(expiresMs) && now >= expiresMs) {
      current = await applyStateTransitionToJob({
        jobId: current.id,
        event: 'EXPIRE',
        resultText: 'Delivery job TTL expired before acknowledgement.',
      });
      logSecurityEvent({
        eventType: 'DELIVERY_FAILED',
        severity: 'warning',
        result: 'failed',
        userId: current.userId,
        details: `Delivery job ${current.id} expired in state ${leased.state}.`,
      });
      return current;
    }

    // 2. If in QUEUED, transition START -> ATTEMPTING(firstChannel)
    if (current.state === 'QUEUED') {
      const targetChannel = current.channelChain[0] || current.channel;
      current = await applyStateTransitionToJob({
        jobId: current.id,
        event: 'START',
        targetChannel,
        incrementAttempt: true,
        resultText: `Starting primary delivery on ${targetChannel}.`,
      });
    }

    // 3. If in FALLBACK, transition START -> ATTEMPTING(fallbackChannel)
    if (current.state === 'FALLBACK') {
      current = await applyStateTransitionToJob({
        jobId: current.id,
        event: 'START',
        targetChannel: current.channel,
        incrementAttempt: true,
        resultText: `Starting fallback attempt on ${current.channel}.`,
      });
    }

    // 4. If in RETRY_WAIT and due, transition RETRY_TIMER -> ATTEMPTING(channel)
    if (current.state === 'RETRY_WAIT') {
      const dueMs = Date.parse(current.nextAttemptAt);
      if (Number.isFinite(dueMs) && now < dueMs) {
        return current;
      }
      current = await applyStateTransitionToJob({
        jobId: current.id,
        event: 'RETRY_TIMER',
        incrementAttempt: true,
        resultText: `Retry timer fired for ${current.channel} (attempt #${current.attempt + 1}).`,
      });
    }

    // 5. If in AWAITING_ACK and due, evaluate ACK_TIMEOUT
    if (current.state === 'AWAITING_ACK') {
      const dueMs = Date.parse(current.nextAttemptAt);
      if (Number.isFinite(dueMs) && now < dueMs) {
        return current;
      }

      const nextChannel = getNextChannelForJob(current);
      const timeoutLabel = formatTimeoutDuration(current.ackTimeoutMs);

      if (nextChannel) {
        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'ACK_TIMEOUT',
          canRetry: false,
          nextChannel,
          resetAttempt: true,
          advanceChannelIndex: true,
          nextAttemptAt: new Date(now).toISOString(),
          resultText: `${current.channel} timed out after ${timeoutLabel} -> falling back to ${nextChannel}`,
        });

        logSecurityEvent({
          eventType: 'DELIVERY_FALLBACK',
          severity: 'warning',
          result: 'failed',
          userId: current.userId,
          details: `Job ${current.id}: ${leased.channel} timed out after ${timeoutLabel} -> falling back to ${nextChannel}.`,
        });

        // Immediately advance FALLBACK -> ATTEMPTING(nextChannel) cleanly on same pass
        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'START',
          targetChannel: nextChannel,
          incrementAttempt: true,
          resultText: `Fallback attempt #1 initiated on ${nextChannel}.`,
        });
      } else {
        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'ACK_TIMEOUT',
          canRetry: false,
          nextChannel: null,
          resultText: `${current.channel} timed out after ${timeoutLabel} with no remaining fallback channels.`,
        });

        logSecurityEvent({
          eventType: 'DELIVERY_FAILED',
          severity: 'critical',
          result: 'failed',
          userId: current.userId,
          details: `ADMIN ALERT: Delivery job ${current.id} (${current.priority}) exhausted all channels after ${leased.channel} ACK timeout.`,
        });
        return current;
      }
    }

    // 6. Execute ATTEMPTING(channel)
    if (current.state === 'ATTEMPTING') {
      const activeChannel = current.channel;
      const isBreakerChannel =
        activeChannel === 'push' || activeChannel === 'sms' || activeChannel === 'email';

      // Circuit breaker guard
      if (isBreakerChannel) {
        const breakerCheck = canAttemptChannel(activeChannel as BreakerChannel, namespace, now);
        if (!breakerCheck.allowed) {
          const nextChannel = getNextChannelForJob(current);
          const secsLeft = Math.max(1, Math.ceil(breakerCheck.remainingMs / 1000));
          current = await applyStateTransitionToJob({
            jobId: current.id,
            event: 'SEND_FAILED',
            canRetry: false,
            nextChannel,
            resetAttempt: Boolean(nextChannel),
            advanceChannelIndex: Boolean(nextChannel),
            nextAttemptAt: new Date(now).toISOString(),
            resultText: `${activeChannel} circuit OPEN (${secsLeft}s remaining) -> ${
              nextChannel ? `skipping straight to ${nextChannel}` : 'all channels failed'
            }`,
          });

          if (nextChannel) {
            logSecurityEvent({
              eventType: 'DELIVERY_FALLBACK',
              severity: 'warning',
              result: 'blocked',
              userId: current.userId,
              details: `Job ${current.id}: skipped ${activeChannel} (circuit OPEN) -> ${nextChannel}.`,
            });
          } else {
            logSecurityEvent({
              eventType: 'DELIVERY_FAILED',
              severity: 'critical',
              result: 'failed',
              userId: current.userId,
              details: `ADMIN ALERT: Delivery job ${current.id} failed because all channels are unavailable/OPEN.`,
            });
          }
          return current;
        }
      }

      // Per-user hourly rate-limit check (never spam user via fallback chain)
      if (!current.isDemoJob && activeChannel !== 'none') {
        const rl = checkAndRecordUserChannelLimit(current.userId, activeChannel, now);
        if (!rl.allowed) {
          const nextChannel = getNextChannelForJob(current);
          const backoffMs = calculateBackoffMs(Math.max(0, current.attempt - 1), 2_000, 0.25);
          const canRetryWait = !nextChannel && current.attempt <= current.maxRetriesPerChannel;
          current = await applyStateTransitionToJob({
            jobId: current.id,
            event: 'SEND_FAILED',
            canRetry: canRetryWait,
            nextChannel: canRetryWait ? undefined : nextChannel,
            resetAttempt: Boolean(!canRetryWait && nextChannel),
            advanceChannelIndex: Boolean(!canRetryWait && nextChannel),
            nextAttemptAt: new Date(now + (canRetryWait ? backoffMs : 0)).toISOString(),
            resultText: `throttled (${activeChannel} hourly cap ${rl.limit}/hr reached)${canRetryWait ? ` -> retry backoff ${backoffMs}ms` : ''}.`,
          });
          if (!canRetryWait && !nextChannel) {
            logSecurityEvent({
              eventType: 'DELIVERY_FAILED',
              severity: 'critical',
              result: 'blocked',
              userId: current.userId,
              details: `Job ${current.id} throttled by per-user channel rate limits across all channels.`,
            });
          }
          return current;
        }
      }

      const adapter = getChannelAdapter(activeChannel);
      if (!adapter) {
        const nextChannel = getNextChannelForJob(current);
        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'SEND_FAILED',
          canRetry: false,
          nextChannel,
          resetAttempt: Boolean(nextChannel),
          advanceChannelIndex: Boolean(nextChannel),
          resultText: `No channel adapter found for ${activeChannel}.`,
        });
        return current;
      }

      const currentExpMs = Date.parse(current.expiresAt);
      const effectiveClock = options.now ?? Date.now();
      if (Number.isFinite(currentExpMs) && effectiveClock >= currentExpMs) {
        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'EXPIRE',
          resultText: current.isEphemeral
            ? 'Ephemeral item expired before channel dispatch; halted fallback.'
            : 'Delivery job expired right before dispatch.',
        });
        return current;
      }

      const ackLink = buildSignedAckUrl({
        baseUrl: current.baseUrl,
        jobId: current.id,
        userId: current.userId,
      });

      logSecurityEvent({
        eventType: 'DELIVERY_ATTEMPT',
        severity: 'info',
        result: 'success',
        userId: current.userId,
        email: current.recipientEmail,
        details: `Attempting delivery job ${current.id} via ${activeChannel} (attempt #${current.attempt}).`,
      });

      const sendResult = await adapter.send(current, ackLink.url);

      if (sendResult.ok) {
        if (isBreakerChannel) {
          recordChannelSuccess(activeChannel as BreakerChannel, namespace, now);
        }

        const shouldAwaitAck = current.requiresAck && activeChannel !== 'in_app';
        const waitMs = shouldAwaitAck ? Math.max(50, current.ackTimeoutMs) : 0;

        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'SEND_OK',
          requiresAck: shouldAwaitAck,
          nextAttemptAt: new Date(now + waitMs).toISOString(),
          resultText:
            sendResult.detail ||
            `Sent via ${activeChannel} (${sendResult.providerId || 'ok'}).`,
        });

        if (current.state === 'DELIVERED_ACKED') {
          logSecurityEvent({
            eventType: 'DELIVERY_ACKED',
            severity: 'info',
            result: 'success',
            userId: current.userId,
            email: current.recipientEmail,
            details: `Delivery job ${current.id} completed via ${activeChannel} (no ACK wait required).`,
          });
        }
        return current;
      }

      // Send failed -> update circuit breaker and determine retry vs fallback vs failed
      if (isBreakerChannel) {
        recordChannelFailure(
          activeChannel as BreakerChannel,
          sendResult.error || 'Channel delivery failure',
          namespace,
          now
        );
      }

      // Attempt 1 is initial send; attempts 2..(1+maxRetriesPerChannel) are retries
      const retriesUsedSoFar = Math.max(0, current.attempt - 1);
      const canRetry = sendResult.retryable && retriesUsedSoFar < current.maxRetriesPerChannel;

      if (canRetry) {
        const backoffMs =
          current.isDemoJob && current.demoFaults?.shortTimeouts
            ? options.shortDemoBackoffMs ?? 120
            : calculateBackoffMs(retriesUsedSoFar, 2_000, 0.25);

        current = await applyStateTransitionToJob({
          jobId: current.id,
          event: 'SEND_FAILED',
          canRetry: true,
          nextAttemptAt: new Date(now + backoffMs).toISOString(),
          resultText: `${activeChannel} failed (${sendResult.error || 'error'}) -> retry #${retriesUsedSoFar + 1} scheduled in ${backoffMs}ms`,
        });
        return current;
      }

      const nextChannel = getNextChannelForJob(current);
      current = await applyStateTransitionToJob({
        jobId: current.id,
        event: 'SEND_FAILED',
        canRetry: false,
        nextChannel,
        resetAttempt: Boolean(nextChannel),
        advanceChannelIndex: Boolean(nextChannel),
        nextAttemptAt: new Date(now).toISOString(),
        resultText: nextChannel
          ? `${activeChannel} failed (${sendResult.error || 'exhausted retries'}) -> falling back to ${nextChannel}`
          : `${activeChannel} failed (${sendResult.error || 'exhausted retries'}) -> all channels exhausted`,
      });

      if (nextChannel) {
        logSecurityEvent({
          eventType: 'DELIVERY_FALLBACK',
          severity: 'warning',
          result: 'failed',
          userId: current.userId,
          details: `Job ${current.id}: ${activeChannel} failed -> falling back to ${nextChannel}.`,
        });
      } else {
        logSecurityEvent({
          eventType: 'DELIVERY_FAILED',
          severity: 'critical',
          result: 'failed',
          userId: current.userId,
          details: `ADMIN ALERT: Delivery job ${current.id} (${current.priority}) failed on ALL channels.`,
        });
      }

      return current;
    }

    return current;
  } finally {
    await releaseJobLease(jobId, WORKER_INSTANCE_ID);
  }
}

export async function acknowledgeDeliveryJob(params: {
  jobId: string;
  via: string;
  firebaseIdToken?: string;
}): Promise<DeliveryJobRecord> {
  const existing = await getDeliveryJobById(params.jobId);
  if (!existing) {
    throw new Error(`Delivery job ${params.jobId} not found.`);
  }
  if (isTerminalState(existing.state)) {
    return existing;
  }

  const updated = await applyStateTransitionToJob({
    jobId: existing.id,
    event: 'ACK_RECEIVED',
    resultText: `Acknowledged via ${params.via}. Remaining timers and fallback steps cancelled.`,
    acknowledgedVia: params.via,
    firebaseIdToken: params.firebaseIdToken,
  });

  logSecurityEvent({
    eventType: 'DELIVERY_ACKED',
    severity: 'info',
    result: 'success',
    userId: updated.userId,
    email: updated.recipientEmail,
    details: `Delivery job ${updated.id} acknowledged via ${params.via} on channel ${updated.channel}.`,
  });

  return updated;
}

export async function cancelDeliveryJob(params: {
  jobId: string;
  reason?: string;
  firebaseIdToken?: string;
}): Promise<DeliveryJobRecord> {
  const existing = await getDeliveryJobById(params.jobId);
  if (!existing) {
    throw new Error(`Delivery job ${params.jobId} not found.`);
  }

  const updated = await applyStateTransitionToJob({
    jobId: existing.id,
    event: 'CANCEL',
    resultText: params.reason || 'Delivery job cancelled by operator/owner.',
    firebaseIdToken: params.firebaseIdToken,
  });

  return updated;
}

export async function runDeliveryWorkerTick(): Promise<{
  processedCount: number;
  jobIds: string[];
}> {
  if (global.__aegisDeliveryTickBusy) {
    return { processedCount: 0, jobIds: [] };
  }

  global.__aegisDeliveryTickBusy = true;
  try {
    const dueIds = await listDueDeliveryJobIds(Date.now());
    for (const id of dueIds) {
      await processSingleDeliveryJob(id).catch((err) => {
        console.warn(`[Delivery Worker] Error processing job ${id}:`, err?.message || err);
      });
    }
    return { processedCount: dueIds.length, jobIds: dueIds };
  } finally {
    global.__aegisDeliveryTickBusy = false;
  }
}

export function startDeliveryWorkerLoop(intervalMs: number = DEFAULT_WORKER_INTERVAL_MS): void {
  if (global.__aegisDeliveryWorkerTimer) {
    return;
  }
  console.log(`[Delivery Worker] Starting durable state-machine loop (interval=${intervalMs}ms)`);
  global.__aegisDeliveryWorkerTimer = setInterval(() => {
    void runDeliveryWorkerTick();
  }, intervalMs);
}
