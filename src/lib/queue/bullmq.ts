import { Queue, QueueEvents } from 'bullmq';
import Redis from 'ioredis';

const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = parseInt(process.env.REDIS_PORT || '6379', 10);

export interface NotificationJobData {
  notificationId: string;
  userId: string;
  eventType: string;
  rawText: string;
  dispatchScore: number;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  signature: string;
  sanitizedPayload: Record<string, any>;
  metadata?: Record<string, any>;
  provenanceEnvelope?: any;
  provenanceReport?: any;
  priorityEngine?: any;
  channelsUsed: string[];
  recipientPhone?: string;
  recipientEmail?: string;
}

export interface FallbackJobData {
  notificationId: string;
  userId: string;
  dispatchScore: number;
  rawText: string;
  eventType: string;
  recipientPhone?: string;
  recipientEmail?: string;
}

export const NOTIFICATION_QUEUE_NAME = 'aegis-notification-queue';
export const FALLBACK_QUEUE_NAME = 'aegis-fallback-queue';

let notificationQueue: Queue<NotificationJobData> | null = null;
let fallbackQueue: Queue<FallbackJobData> | null = null;

const redisConnectionOptions = {
  host: REDIS_HOST,
  port: REDIS_PORT,
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
};

type JobHandler<T = any> = (data: T) => Promise<void> | void;
const jobHandlers: Map<string, JobHandler> = new Map();

export function registerJobHandler(queueName: string, handler: JobHandler) {
  jobHandlers.set(queueName, handler);
}

// Internal memory queue runner when external Redis daemon is not available
class InMemoryFallbackQueue<T> {
  private jobs: Map<string, { data: T; delay: number; enqueuedAt: number }> = new Map();
  name: string;

  constructor(name: string) {
    this.name = name;
  }

  async add(jobName: string, data: T, opts?: { delay?: number; jobId?: string }) {
    const jobId = opts?.jobId || `${jobName}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const delay = opts?.delay || 0;
    this.jobs.set(jobId, { data, delay, enqueuedAt: Date.now() });

    if (delay > 0) {
      setTimeout(() => {
        this.triggerJobExecution(jobId);
      }, delay);
    } else {
      setImmediate(() => {
        this.triggerJobExecution(jobId);
      });
    }

    return { id: jobId, data };
  }

  private triggerJobExecution(jobId: string) {
    const job = this.jobs.get(jobId);
    if (!job) return;
    this.jobs.delete(jobId);

    const handler = jobHandlers.get(this.name);
    if (handler) {
      try {
        Promise.resolve(handler(job.data)).catch((err) => {
          console.warn(`[Queue Handler Error in ${this.name}]`, err);
        });
      } catch (err) {
        console.warn(`[Queue Execution Error in ${this.name}]`, err);
      }
    }
  }
}

export const inMemoryNotificationQueue = new InMemoryFallbackQueue<NotificationJobData>(NOTIFICATION_QUEUE_NAME);
export const inMemoryFallbackQueue = new InMemoryFallbackQueue<FallbackJobData>(FALLBACK_QUEUE_NAME);

export function getNotificationQueue(): Queue<NotificationJobData> | InMemoryFallbackQueue<NotificationJobData> {
  if (process.env.USE_REDIS_QUEUE === 'true') {
    if (!notificationQueue) {
      try {
        notificationQueue = new Queue<NotificationJobData>(NOTIFICATION_QUEUE_NAME, {
          connection: new Redis(redisConnectionOptions),
        });
      } catch {
        return inMemoryNotificationQueue;
      }
    }
    return notificationQueue;
  }
  return inMemoryNotificationQueue;
}

export function getFallbackQueue(): Queue<FallbackJobData> | InMemoryFallbackQueue<FallbackJobData> {
  if (process.env.USE_REDIS_QUEUE === 'true') {
    if (!fallbackQueue) {
      try {
        fallbackQueue = new Queue<FallbackJobData>(FALLBACK_QUEUE_NAME, {
          connection: new Redis(redisConnectionOptions),
        });
      } catch {
        return inMemoryFallbackQueue;
      }
    }
    return fallbackQueue;
  }
  return inMemoryFallbackQueue;
}
