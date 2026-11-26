import type { DeliveryChannel, DeliveryStateName } from '../stateMachine.js';
import type { DeliveryPriority } from '../policies.js';

export interface DeliveryHistoryEntry {
  timestamp: string;
  from: DeliveryStateName;
  event: string;
  to: DeliveryStateName;
  channel: DeliveryChannel;
  result: string;
}

export interface DemoFaultConfig {
  forcePushFail?: boolean;
  forceWhatsappFail?: boolean;
  forceSmsFail?: boolean;
  forceEmailFail?: boolean;
  forceNoAck?: boolean;
  forceSlowAck?: boolean;
  forceAllDown?: boolean;
  shortTimeouts?: boolean;
}

export interface DeliveryJobRecord {
  id: string;
  notificationId: string;
  userId: string;
  priority: DeliveryPriority;
  state: DeliveryStateName;
  channel: DeliveryChannel;
  channelChain: DeliveryChannel[];
  channelIndex: number;
  attempt: number;
  requiresAck: boolean;
  ackTimeoutMs: number;
  maxRetriesPerChannel: number;
  nextAttemptAt: string;
  expiresAt: string;
  history: DeliveryHistoryEntry[];
  idempotencyKey: string;
  title?: string;
  sourceApp?: string;
  recipientEmail?: string;
  recipientPhone?: string;
  recipientWhatsappPhone?: string;
  baseUrl?: string;
  isDemoJob?: boolean;
  demoFaults?: DemoFaultConfig;
  isEphemeral?: boolean;
  ephemeralTtlSeconds?: number;
  leaseOwner?: string | null;
  leaseExpiresAt?: string | null;
  acknowledgedAt?: string | null;
  acknowledgedVia?: string | null;
  priorityPromotedOnce?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ChannelSendResult {
  ok: boolean;
  providerId?: string;
  error?: string;
  retryable: boolean;
  mockDelivered?: boolean;
  detail?: string;
}

export interface ChannelAdapter {
  readonly channel: DeliveryChannel;
  send(job: DeliveryJobRecord, ackUrl: string): Promise<ChannelSendResult>;
}
