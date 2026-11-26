import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { User, inMemoryUsers, IUser } from '../../../../../models/User.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';

const RegisterSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  preferences: z
    .object({
      dndEnabled: z.boolean().optional(),
      quietHoursStart: z.string().optional(),
      quietHoursEnd: z.string().optional(),
      preferredChannel: z.enum(['WEBSOCKET', 'WEBPUSH', 'EMAIL', 'SMS', 'WHATSAPP']).optional(),
    })
    .optional(),
});

export async function POST(request: Request) {
  try {
    const body = await request.json().catch(() => null);
    const parsed = RegisterSchema.safeParse(body);

    if (!parsed.success) {
      return Response.json(
        {
          success: false,
          error: 'Validation Error',
          message: 'Please provide a valid email and password.',
          details: parsed.error.format(),
        },
        { status: 400 }
      );
    }

    const { email, password, preferences } = parsed.data;
    const role = 'USER' as const;
    const passwordHash = await bcrypt.hash(password, 10);
    const reqCtx = extractRequestContext(request);

    const mongooseConn = await connectToDatabase().catch(() => null);
    if (mongooseConn) {
      const existing = await User.findOne({ email: email.toLowerCase() });
      if (existing) {
        return Response.json(
          { success: false, error: 'Registration Failed', message: 'Unable to complete registration with those details.' },
          { status: 409 }
        );
      }

      const newUser = await User.create({
        email: email.toLowerCase(),
        passwordHash,
        role,
        preferences: preferences || {
          dndEnabled: false,
          quietHoursStart: '22:00',
          quietHoursEnd: '07:00',
          preferredChannel: 'WEBSOCKET',
        },
        createdAt: new Date(),
      });

      const userPayload = {
        id: newUser._id,
        email: newUser.email,
        role: newUser.role,
        preferences: newUser.preferences,
        createdAt: newUser.createdAt,
      };

      logSecurityEvent({
        eventType: 'SIGNUP_COMPLETED',
        severity: 'info',
        result: 'success',
        userId: String(newUser._id),
        email: newUser.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Account registered via auth/register.',
      });

      return Response.json(
        {
          success: true,
          message: 'Account created.',
          user: userPayload,
          data: { user: userPayload },
        },
        { status: 201 }
      );
    } else {
      // Memory Store Fallback
      if (inMemoryUsers.has(email.toLowerCase())) {
        return Response.json(
          { success: false, error: 'Registration Failed', message: 'Unable to complete registration with those details.' },
          { status: 409 }
        );
      }

      const mockUser = {
        _id: `usr_${Date.now()}`,
        email: email.toLowerCase(),
        passwordHash,
        role,
        preferences: {
          dndEnabled: preferences?.dndEnabled ?? false,
          quietHoursStart: preferences?.quietHoursStart ?? '22:00',
          quietHoursEnd: preferences?.quietHoursEnd ?? '07:00',
          preferredChannel: preferences?.preferredChannel ?? 'WEBSOCKET',
        },
        createdAt: new Date(),
      } as unknown as IUser;

      inMemoryUsers.set(email.toLowerCase(), mockUser);

      const userPayload = {
        id: mockUser._id,
        email: mockUser.email,
        role: mockUser.role,
        preferences: mockUser.preferences,
        createdAt: mockUser.createdAt,
      };

      logSecurityEvent({
        eventType: 'SIGNUP_COMPLETED',
        severity: 'info',
        result: 'success',
        userId: String(mockUser._id),
        email: mockUser.email,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Account registered via auth/register.',
      });

      return Response.json(
        {
          success: true,
          message: 'Account created.',
          user: userPayload,
          data: { user: userPayload },
        },
        { status: 201 }
      );
    }
  } catch (err: any) {
    return Response.json(
      { success: false, error: 'Internal Server Error', message: err.message || 'Registration failed.' },
      { status: 500 }
    );
  }
}
