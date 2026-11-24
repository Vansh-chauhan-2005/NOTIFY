import mongoose, { Schema, Document, Model, Types } from 'mongoose';

export type NotificationStatus =
  | 'QUEUED'
  | 'PROCESSING'
  | 'DEDUPLICATED'
  | 'DISPATCHED_PRIMARY'
  | 'ESCALATED_FALLBACK'
  | 'FAILED';

export interface INotificationLog extends Document {
  userId: Types.ObjectId | string;
  eventType: string;
  rawText: string;
  dispatchScore: number;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: NotificationStatus;
  signature: string;
  encryptedPayload?: string;
  channelsUsed: string[];
  createdAt: Date;
  metadata?: Record<string, unknown>;
  provenanceEnvelope?: any;
  provenanceReport?: any;
}

export const NotificationLogSchema = new Schema<INotificationLog>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    eventType: {
      type: String,
      required: true,
      index: true,
    },
    rawText: {
      type: String,
      required: true,
    },
    dispatchScore: {
      type: Number,
      required: true,
      min: 0,
      max: 1,
    },
    priority: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      default: 'MEDIUM',
    },
    status: {
      type: String,
      enum: [
        'QUEUED',
        'PROCESSING',
        'DEDUPLICATED',
        'DISPATCHED_PRIMARY',
        'ESCALATED_FALLBACK',
        'FAILED',
      ],
      default: 'QUEUED',
      required: true,
      index: true,
    },
    signature: {
      type: String,
      required: true,
    },
    encryptedPayload: {
      type: String,
      required: false,
    },
    channelsUsed: {
      type: [String],
      default: [],
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
    provenanceEnvelope: {
      type: Schema.Types.Mixed,
      default: null,
    },
    provenanceReport: {
      type: Schema.Types.Mixed,
      default: null,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: false }
);

// 30-Day TTL Index: 30 * 24 * 60 * 60 = 2592000 seconds
NotificationLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 });

// Resilient memory cache for logs in sandbox environments without live Mongo instances
export const inMemoryNotificationLogs: INotificationLog[] = [];

export const NotificationLog: Model<INotificationLog> =
  mongoose.models.NotificationLog ||
  mongoose.model<INotificationLog>('NotificationLog', NotificationLogSchema);

export default NotificationLog;
