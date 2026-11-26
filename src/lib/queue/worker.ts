import { Worker, Job } from 'bullmq';
import Redis from 'ioredis';
import { z } from 'zod';
import { redis, RATE_LIMIT_LUA_SCRIPT } from '../db/redis.js';
import { connectToDatabase } from '../db/mongoose.js';
import { NotificationLog, inMemoryNotificationLogs } from '../../models/NotificationLog.js';
import { User, inMemoryUsers } from '../../models/User.js';
import {
  NOTIFICATION_QUEUE_NAME,
  FALLBACK_QUEUE_NAME,
  NotificationJobData,
  FallbackJobData,
  getFallbackQueue,
  registerJobHandler,
} from './bullmq.js';
import {
  sendEmailNotification,
  buildFallbackAlertEmailHtml,
  isEmailConfigured,
} from '../integrations/emailService.js';
import {
  broadcastWebPushAlert,
  isWebPushConfigured,
} from '../integrations/webPushService.js';
import {
  sendFast2Sms,
  isFast2SmsConfigured,
  getFast2SmsTargetPhone,
  setFast2SmsTargetPhone,
} from '../integrations/fast2smsService.js';

// Ingress Validation Schema
export const IngestNotificationSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  eventType: z.string().min(1, 'Event type is required'),
  rawText: z.string().min(1, 'Notification content is required'),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
  riskScore: z.number().min(0).max(1).optional().default(0.5),
  otp: z.string().optional(),
  otpCode: z.string().optional(),
  recipientEmail: z.string().email().optional(),
  recipientPhone: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type IngestNotificationInput = z.infer<typeof IngestNotificationSchema>;

// Connected WebSocket Clients Registry for primary dispatch & presence
type SocketListener = (data: string) => void;
export const activeSocketConnections: Map<string, Set<{ id: string; send: SocketListener }>> = new Map();

export function registerClientSocket(userId: string, socketId: string, send: SocketListener) {
  let userSockets = activeSocketConnections.get(userId);
  if (!userSockets) {
    userSockets = new Set();
    activeSocketConnections.set(userId, userSockets);
  }
  userSockets.add({ id: socketId, send });
  console.log(`[WebSocket] Client connected: user=${userId}, socket=${socketId} (Active sockets: ${userSockets.size})`);
}

export function unregisterClientSocket(userId: string, socketId: string) {
  const userSockets = activeSocketConnections.get(userId);
  if (userSockets) {
    for (const socket of Array.from(userSockets)) {
      if (socket.id === socketId) {
        userSockets.delete(socket);
      }
    }
    if (userSockets.size === 0) {
      activeSocketConnections.delete(userId);
    }
  }
  console.log(`[WebSocket] Client disconnected: user=${userId}, socket=${socketId}`);
}

export function hasActiveSocketPresence(userId: string): boolean {
  const sockets = activeSocketConnections.get(userId);
  return !!sockets && sockets.size > 0;
}

/**
 * Atomic Redis Lua Rate Limiter for HTTP Ingress
 * 100 requests per 60-second window per API Key
 */
export async function enforceRateLimit(
  apiKey: string,
  limit = 100,
  windowSec = 60
): Promise<{ allowed: boolean; currentCount: number; remaining: number }> {
  const key = `rate:lim:${apiKey}`;
  try {
    const result = (await (redis as any).eval(
      RATE_LIMIT_LUA_SCRIPT,
      1,
      key,
      String(limit),
      String(windowSec)
    )) as [number, number];

    const allowed = result[0] === 1;
    const currentCount = result[1];
    return {
      allowed,
      currentCount,
      remaining: Math.max(0, limit - currentCount),
    };
  } catch {
    // Fallback in-memory rate-limit handling if Redis eval is unsupported
    const count = await redis.incr(key);
    if (count === 1) {
      await redis.expire(key, windowSec);
    }
    const allowed = count <= limit;
    return {
      allowed,
      currentCount: count,
      remaining: Math.max(0, limit - count),
    };
  }
}

/**
 * Primary WebSocket Dispatch
 */
export async function dispatchPrimaryWebSocket(jobData: NotificationJobData): Promise<boolean> {
  const userSockets = activeSocketConnections.get(jobData.userId);
  const payloadString = JSON.stringify({
    type: 'NOTIFICATION_DISPATCH',
    notificationId: jobData.notificationId,
    userId: jobData.userId,
    eventType: jobData.eventType,
    rawText: jobData.rawText,
    dispatchScore: jobData.dispatchScore,
    priority: jobData.priority,
    signature: jobData.signature,
    sanitizedPayload: jobData.sanitizedPayload,
    metadata: jobData.metadata,
    provenanceEnvelope: jobData.provenanceEnvelope || null,
    provenanceReport: jobData.provenanceReport || null,
    priorityEngine: jobData.priorityEngine || jobData.metadata?.priorityEngine || null,
    timestamp: new Date().toISOString(),
  });

  let delivered = false;
  if (userSockets && userSockets.size > 0) {
    for (const socket of Array.from(userSockets)) {
      try {
        socket.send(payloadString);
        delivered = true;
      } catch (err) {
        console.warn('[WebSocket] Send failed for socket', socket.id, err);
      }
    }
  }

  // Also broadcast to all dashboard observers if user is admin or watching
  const broadcastSockets = activeSocketConnections.get('*');
  if (broadcastSockets) {
    for (const socket of Array.from(broadcastSockets)) {
      try {
        socket.send(payloadString);
      } catch {}
    }
  }

  return delivered;
}

/**
 * BullMQ Worker Handler: Primary Dispatch & Delayed Fallback Setup
 */
export async function processNotificationJob(data: NotificationJobData) {
  console.log(`[Queue Worker] Processing notification ${data.notificationId} for user ${data.userId}`);

  // 1. Primary dispatch via WebSockets
  const delivered = await dispatchPrimaryWebSocket(data);
  const channelsUsed = ['WEBSOCKET'];

  // 2. Write Redis key ack:pending:<notificationId> with 3,000ms TTL
  const ackKey = `ack:pending:${data.notificationId}`;
  await redis.set(ackKey, 'PENDING', 'PX', 3000);

  // 3. Update status in memory / database
  try {
    const db = await connectToDatabase();
    if (db) {
      await NotificationLog.findByIdAndUpdate(data.notificationId, {
        status: 'DISPATCHED_PRIMARY',
        channelsUsed,
      }).exec();
    } else {
      const log = inMemoryNotificationLogs.find(
        (l) => String(l._id) === String(data.notificationId)
      );
      if (log) {
        log.status = 'DISPATCHED_PRIMARY';
        log.channelsUsed = channelsUsed;
      }
    }
  } catch {
    const log = inMemoryNotificationLogs.find(
      (l) => String(l._id) === String(data.notificationId)
    );
    if (log) {
      log.status = 'DISPATCHED_PRIMARY';
      log.channelsUsed = channelsUsed;
    }
  }

  // 4. Enqueue delayed BullMQ fallback job (3,000ms delay)
  const fallbackQueue = getFallbackQueue();
  await fallbackQueue.add(
    'process-fallback',
    {
      notificationId: data.notificationId,
      userId: data.userId,
      dispatchScore: data.dispatchScore,
      rawText: data.rawText,
      eventType: data.eventType,
      recipientPhone: data.recipientPhone,
      recipientEmail: data.recipientEmail,
    },
    { delay: 3000, jobId: `fallback-${data.notificationId}` }
  );

  console.log(`[Queue Worker] Fallback job scheduled for ${data.notificationId} in 3000ms (Weight W=${data.dispatchScore})`);
}

/**
 * BullMQ Worker Handler: Fallback State Machine
 * If ack:pending:<notificationId> is unacknowledged and W >= 0.75, trigger multi-channel fallback:
 * 1. Nodemailer Email Delivery: Generates HTML notification and delivers to user/admin email
 * 2. WebPush API: Triggers instant device-level notification via Service Worker
 * 3. Fast2SMS Service: Sends urgent SMS alert to recipient's phone number
 */
export async function processFallbackJob(data: FallbackJobData) {
  const ackKey = `ack:pending:${data.notificationId}`;
  const isPending = await redis.get(ackKey);

  console.log(`[Fallback Check] ID=${data.notificationId}, AckPending=${!!isPending}, Score W=${data.dispatchScore}`);

  if (isPending && data.dispatchScore >= 0.75) {
    console.log(`[Fallback Triggered] Notification ${data.notificationId} unacknowledged after 3000ms with W=${data.dispatchScore} >= 0.75! Escalating to Nodemailer Email, WebPush API, and Fast2SMS.`);

    const channelsAdded = ['EMAIL', 'WEBPUSH', 'FAST2SMS'];
    const nowIso = new Date().toISOString();

    // 1. Nodemailer Email Fallback Delivery
    try {
      const targetEmail =
        process.env.ADMIN_FALLBACK_EMAIL?.trim() ||
        process.env.NOTIFICATION_TARGET_EMAIL?.trim() ||
        '';

      if (!targetEmail) {
        console.log('[Fallback Nodemailer] Skipped email fallback: no ADMIN_FALLBACK_EMAIL or NOTIFICATION_TARGET_EMAIL configured.');
      } else {
        const emailHtml = buildFallbackAlertEmailHtml({
          eventType: data.eventType,
          rawText: data.rawText,
          dispatchScore: data.dispatchScore,
          notificationId: data.notificationId,
          timestamp: nowIso,
        });

        const emailResult = await sendEmailNotification({
          to: targetEmail,
          subject: `[Aegis Fallback Alert] ${data.eventType}: Critical Escalation (W=${data.dispatchScore})`,
          text: `[Aegis Fallback Alert] Event: ${data.eventType}\nSeverity Weight: ${data.dispatchScore}\nMessage: ${data.rawText}\nNotification ID: ${data.notificationId}`,
          html: emailHtml,
        });

        console.log(`[Fallback Nodemailer] Email dispatched to ${targetEmail}. Success=${emailResult.success}`);
      }
    } catch (emailErr: any) {
      console.log(`[Fallback Email Handled] Error sending fallback email: ${emailErr.message}`);
    }

    // 2. WebPush API Device-Level Push Alert
    try {
      const pushTitle = `🚨 Aegis Alert: ${data.eventType}`;
      const pushBody = `${data.rawText} (Weight: ${data.dispatchScore})`;

      await broadcastWebPushAlert({
        title: pushTitle,
        body: pushBody,
        icon: '/assets/logo.png',
        badge: '/assets/logo.png',
        tag: `fallback-${data.notificationId}`,
        data: {
          notificationId: data.notificationId,
          eventType: data.eventType,
          dispatchScore: data.dispatchScore,
          url: '/',
        },
      });

      // Record WebPush trigger in Redis
      await redis.set(
        `webpush:triggered:${data.notificationId}`,
        JSON.stringify({
          notificationId: data.notificationId,
          userId: data.userId,
          rawText: data.rawText,
          dispatchedAt: nowIso,
        }),
        'EX',
        86400
      );
    } catch (pushErr: any) {
      console.log(`[Fallback WebPush Handled] ${pushErr.message}`);
    }

    // 3. Fast2SMS SMS Delivery Fallback
    try {
      let targetPhone = data.recipientPhone?.trim();
      if (!targetPhone && data.userId) {
        const memUser = inMemoryUsers.get(data.userId) as any;
        if (memUser?.phoneNumber) {
          targetPhone = memUser.phoneNumber;
        }
      }
      if (!targetPhone) {
        targetPhone = getFast2SmsTargetPhone();
      }
      if (!targetPhone) {
        targetPhone = '9876543210';
      }

      const smsText = `[Aegis Security] ${data.eventType}: ${data.rawText.slice(0, 80)} (W=${data.dispatchScore})`;
      const smsResult = await sendFast2Sms(targetPhone, smsText);

      console.log(`[Fallback Fast2SMS] SMS dispatched to ${smsResult.phoneNumber}. Simulated=${smsResult.simulated}`);
    } catch (smsErr: any) {
      console.log(`[Fallback Fast2SMS Handled] ${smsErr.message}`);
    }

    // Update log status to ESCALATED_FALLBACK
    try {
      const db = await connectToDatabase();
      if (db) {
        await NotificationLog.findByIdAndUpdate(data.notificationId, {
          status: 'ESCALATED_FALLBACK',
          $addToSet: { channelsUsed: { $each: channelsAdded } },
        }).exec();
      } else {
        const log = inMemoryNotificationLogs.find(
          (l) => String(l._id) === String(data.notificationId)
        );
        if (log) {
          log.status = 'ESCALATED_FALLBACK';
          log.channelsUsed = Array.from(new Set([...log.channelsUsed, ...channelsAdded]));
        }
      }
    } catch {
      const log = inMemoryNotificationLogs.find(
        (l) => String(l._id) === String(data.notificationId)
      );
      if (log) {
        log.status = 'ESCALATED_FALLBACK';
        log.channelsUsed = Array.from(new Set([...log.channelsUsed, ...channelsAdded]));
      }
    }

    // Secondary dispatch notification broadcast via WebSocket
    const broadcastSockets = activeSocketConnections.get('*');
    const fallbackNotice = JSON.stringify({
      type: 'FALLBACK_ESCALATION_TRIGGERED',
      notificationId: data.notificationId,
      userId: data.userId,
      eventType: data.eventType,
      dispatchScore: data.dispatchScore,
      escalatedChannels: channelsAdded,
      fallbackType: 'NODEMAILER_WEBPUSH_AND_FAST2SMS',
      reason: 'ACK_TIMEOUT_EXCEEDED_HIGH_DISPATCH_WEIGHT (3000ms SLA breach)',
      timestamp: nowIso,
    });

    if (broadcastSockets) {
      for (const socket of Array.from(broadcastSockets)) {
        try {
          socket.send(fallbackNotice);
        } catch {}
      }
    }

    // Clean pending key
    await redis.del(ackKey);
  } else {
    // Acknowledged or below threshold
    if (!isPending) {
      console.log(`[Fallback Resolved] Notification ${data.notificationId} was acknowledged in time.`);
    } else {
      console.log(`[Fallback Bypassed] Notification ${data.notificationId} unacknowledged but W=${data.dispatchScore} < 0.75.`);
    }
  }
}

// Register memory loop handlers
registerJobHandler(NOTIFICATION_QUEUE_NAME, (data: NotificationJobData) => processNotificationJob(data));
registerJobHandler(FALLBACK_QUEUE_NAME, (data: FallbackJobData) => processFallbackJob(data));

// Initialize BullMQ Workers when Redis server is active
export function initBullMQWorkers() {
  if (process.env.USE_REDIS_QUEUE !== 'true') {
    console.log('[Queue] Running with resilient in-memory BullMQ event loop.');
    return;
  }

  try {
    const redisOptions = {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: parseInt(process.env.REDIS_PORT || '6379', 10),
      maxRetriesPerRequest: null,
    };

    const notificationWorker = new Worker<NotificationJobData>(
      NOTIFICATION_QUEUE_NAME,
      async (job: Job<NotificationJobData>) => {
        await processNotificationJob(job.data);
      },
      { connection: redisOptions as any }
    );

    const fallbackWorker = new Worker<FallbackJobData>(
      FALLBACK_QUEUE_NAME,
      async (job: Job<FallbackJobData>) => {
        await processFallbackJob(job.data);
      },
      { connection: redisOptions as any }
    );

    notificationWorker.on('completed', (job) => {
      console.log(`[BullMQ Worker] Notification job ${job.id} dispatched successfully`);
    });

    fallbackWorker.on('completed', (job) => {
      console.log(`[BullMQ Worker] Fallback job ${job.id} completed successfully`);
    });

    console.log('[BullMQ Worker] Active workers initialized for BullMQ queues');
  } catch (err: any) {
    console.warn('[BullMQ Worker] Redis worker init skipped:', err.message);
  }
}
