import jwt from 'jsonwebtoken';
import { User, inMemoryUsers } from '../../../../../models/User.js';
import { getServerKeyPair } from '../../../../../lib/crypto/ed25519.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { getJwtSecret } from '../../../../../lib/auth/jwtSecret.js';

export async function GET(request: Request) {
  try {
    const authHeader = request.headers.get('authorization');
    const { publicKey } = getServerKeyPair();

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // Return public server identity and anonymous context
      return Response.json({
        authenticated: false,
        serverPublicKey: publicKey,
        serverTime: new Date().toISOString(),
      });
    }

    const token = authHeader.split(' ')[1];
    let decoded: any;
    try {
      decoded = jwt.verify(token, getJwtSecret());
    } catch {
      return Response.json({ error: 'Invalid or expired token' }, { status: 401 });
    }

    let user: any = null;
    const mongooseConn = await connectToDatabase();
    if (mongooseConn) {
      user = await User.findById(decoded.userId).select('-passwordHash');
    } else {
      user = inMemoryUsers.get(decoded.email?.toLowerCase()) || Array.from(inMemoryUsers.values()).find(u => String(u._id) === String(decoded.userId));
    }

    return Response.json({
      authenticated: true,
      user: user || {
        id: decoded.userId,
        email: decoded.email,
        role: decoded.role,
      },
      serverPublicKey: publicKey,
      serverTime: new Date().toISOString(),
    });
  } catch (err: any) {
    return Response.json(
      { error: 'Internal Server Error', message: err.message },
      { status: 500 }
    );
  }
}
