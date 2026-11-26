import { z } from 'zod';
import { User, inMemoryUsers } from '../../../../../models/User.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { setFast2SmsTargetPhone } from '../../../../../lib/integrations/fast2smsService.js';
import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';

const PreferencesUpdateSchema = z.object({
  userId: z.string().min(1).optional(),
  phoneNumber: z.string().max(24).optional(),
  dndEnabled: z.boolean().optional(),
  quietHoursStart: z
    .string()
    .regex(/^([01]\d|2[0-3]):([0-5]\d)$/, 'Format must be HH:mm')
    .optional(),
  quietHoursEnd: z
    .string()
    .regex(/^([01]\d|2[0-3]):([0-5]\d)$/, 'Format must be HH:mm')
    .optional(),
  preferredChannel: z.enum(['WEBSOCKET', 'WEBPUSH', 'EMAIL', 'SMS', 'WHATSAPP']).optional(),
  whatsappPhone: z
    .union([
      z.literal(''),
      z.string().regex(/^\+[1-9]\d{6,14}$/, 'WhatsApp number must use E.164 format (e.g. +919876543210)'),
    ])
    .optional(),
  optOutWhatsapp: z.boolean().optional(),
});

export async function GET(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const url = new URL(request.url);
    const requestedUserId = url.searchParams.get('userId') || auth.user.userId;
    const isAdmin = auth.user.role === 'ADMIN';

    if (!isAdmin && requestedUserId !== auth.user.userId) {
      return Response.json(
        { error: 'Forbidden', message: 'You can only read your own notification preferences.' },
        { status: 403 }
      );
    }

    const userId = requestedUserId;
    const mongooseConn = await connectToDatabase();
    let preferences = null;

    if (mongooseConn) {
      const user = await User.findById(userId);
      if (user) preferences = user.preferences;
    } else {
      const user = Array.from(inMemoryUsers.values()).find(
        (u) => String(u._id) === userId || u.email === userId
      );
      if (user) preferences = user.preferences;
    }

    if (!preferences) {
      preferences = {
        dndEnabled: false,
        quietHoursStart: '22:00',
        quietHoursEnd: '07:00',
        preferredChannel: 'WEBSOCKET',
        whatsappPhone: '',
        optOutWhatsapp: false,
      };
    }

    return Response.json({ success: true, userId, preferences });
  } catch {
    return Response.json(
      { error: 'Internal Server Error', message: 'Failed to load preferences.' },
      { status: 500 }
    );
  }
}

export async function PUT(request: Request) {
  try {
    const auth = authenticateUserRequest(request);
    if (!auth.ok || !auth.user) {
      return auth.response!;
    }

    const body = await request.json().catch(() => null);
    const parsed = PreferencesUpdateSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        { error: 'Validation Error', details: parsed.error.format() },
        { status: 400 }
      );
    }

    const isAdmin = auth.user.role === 'ADMIN';
    const requestedUserId = parsed.data.userId || auth.user.userId;
    if (!isAdmin && requestedUserId !== auth.user.userId) {
      return Response.json(
        { error: 'Forbidden', message: 'You can only update your own notification preferences.' },
        { status: 403 }
      );
    }

    const userId = requestedUserId;
    const { userId: _ignored, phoneNumber, ...prefUpdates } = parsed.data;
    if (isAdmin && phoneNumber && phoneNumber.trim()) {
      setFast2SmsTargetPhone(phoneNumber);
    }

    const mongooseConn = await connectToDatabase();

    if (mongooseConn) {
      const setFields: Record<string, any> = {};
      if (prefUpdates.dndEnabled !== undefined) {
        setFields['preferences.dndEnabled'] = prefUpdates.dndEnabled;
      }
      if (prefUpdates.quietHoursStart !== undefined) {
        setFields['preferences.quietHoursStart'] = prefUpdates.quietHoursStart;
      }
      if (prefUpdates.quietHoursEnd !== undefined) {
        setFields['preferences.quietHoursEnd'] = prefUpdates.quietHoursEnd;
      }
      if (prefUpdates.preferredChannel !== undefined) {
        setFields['preferences.preferredChannel'] = prefUpdates.preferredChannel;
      }
      if (prefUpdates.whatsappPhone !== undefined) {
        setFields['preferences.whatsappPhone'] = prefUpdates.whatsappPhone;
      }
      if (prefUpdates.optOutWhatsapp !== undefined) {
        setFields['preferences.optOutWhatsapp'] = prefUpdates.optOutWhatsapp;
      }
      if (phoneNumber && phoneNumber.trim()) {
        setFields.phoneNumber = phoneNumber.trim();
      }

      const user = await User.findByIdAndUpdate(
        userId,
        { $set: setFields },
        { new: true }
      );

      return Response.json({
        success: true,
        message: 'Preferences updated successfully',
        preferences: user?.preferences,
      });
    } else {
      let user = Array.from(inMemoryUsers.values()).find(
        (u) => String(u._id) === userId || u.email === userId
      );

      if (!user) {
        user = {
          _id: userId,
          email: auth.user.email || `${userId}@aegis.local`,
          passwordHash: '',
          role: 'USER',
          preferences: {
            dndEnabled: prefUpdates.dndEnabled ?? false,
            quietHoursStart: prefUpdates.quietHoursStart ?? '22:00',
            quietHoursEnd: prefUpdates.quietHoursEnd ?? '07:00',
            preferredChannel: prefUpdates.preferredChannel ?? 'WEBSOCKET',
            whatsappPhone: prefUpdates.whatsappPhone ?? '',
            optOutWhatsapp: prefUpdates.optOutWhatsapp ?? false,
          },
          createdAt: new Date(),
        } as any;
        inMemoryUsers.set(userId, user!);
      } else {
        user.preferences = {
          ...user.preferences,
          ...prefUpdates,
        };
        if (phoneNumber && phoneNumber.trim()) {
          user.phoneNumber = phoneNumber.trim();
        }
      }

      return Response.json({
        success: true,
        message: 'Preferences updated successfully',
        preferences: user.preferences,
      });
    }
  } catch {
    return Response.json(
      { error: 'Internal Server Error', message: 'Failed to update preferences.' },
      { status: 500 }
    );
  }
}
