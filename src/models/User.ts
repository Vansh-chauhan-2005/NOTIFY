import mongoose, { Schema, Document, Model } from 'mongoose';

export type UserRole = 'ADMIN' | 'SERVICE' | 'USER';
export type PreferredChannel = 'WEBSOCKET' | 'WEBPUSH' | 'EMAIL';

export interface IUserPreferences {
  dndEnabled: boolean;
  quietHoursStart: string; // "HH:mm"
  quietHoursEnd: string;   // "HH:mm"
  preferredChannel: PreferredChannel;
}

export interface IUser extends Document {
  email: string;
  phoneNumber?: string;
  passwordHash: string;
  role: UserRole;
  preferences: IUserPreferences;
  pushSubscription?: Record<string, unknown>;
  createdAt: Date;
}

export const UserPreferencesSchema = new Schema<IUserPreferences>(
  {
    dndEnabled: { type: Boolean, default: false },
    quietHoursStart: { type: String, default: '22:00' },
    quietHoursEnd: { type: String, default: '07:00' },
    preferredChannel: {
      type: String,
      enum: ['WEBSOCKET', 'WEBPUSH', 'EMAIL'],
      default: 'WEBSOCKET',
    },
  },
  { _id: false }
);

export const UserSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    phoneNumber: {
      type: String,
      trim: true,
      default: undefined,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ['ADMIN', 'SERVICE', 'USER'],
      default: 'USER',
      required: true,
    },
    preferences: {
      type: UserPreferencesSchema,
      default: () => ({
        dndEnabled: false,
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
        preferredChannel: 'WEBSOCKET',
      }),
    },
    pushSubscription: {
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

// Fallback in-memory user registry for sandbox environment
export const inMemoryUsers: Map<string, IUser> = new Map();

export const User: Model<IUser> =
  mongoose.models.User || mongoose.model<IUser>('User', UserSchema);

export default User;
