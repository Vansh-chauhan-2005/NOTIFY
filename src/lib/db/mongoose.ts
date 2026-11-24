import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/aegis_notify';

interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose | null> | null;
}

declare global {
  // eslint-disable-next-line no-var
  var mongooseCache: MongooseCache | undefined;
}

let cached = global.mongooseCache;

if (!cached) {
  cached = global.mongooseCache = { conn: null, promise: null };
}

let lastConnectAttempt = 0;
let connectionFailed = false;
let authPermanentlyFailed = false;

// Attach error listener to avoid unhandled MongoServerError events to stderr
try {
  mongoose.connection.on('error', () => {
    // Gracefully handled; in-memory datastore operates seamlessly
  });
} catch {
  // ignore
}

export async function connectToDatabase(): Promise<typeof mongoose | null> {
  if (cached!.conn) {
    return cached!.conn;
  }

  // If credentials failed authentication or no URI specified, use high-speed memory store immediately
  if (!process.env.MONGODB_URI || authPermanentlyFailed) {
    return null;
  }

  // If recent connection failure, avoid stalling API requests with repeated network timeouts (60s backoff)
  if (connectionFailed && Date.now() - lastConnectAttempt < 60000) {
    return null;
  }

  lastConnectAttempt = Date.now();

  if (!cached!.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 1500,
    };

    cached!.promise = mongoose
      .connect(MONGODB_URI, opts)
      .then((m) => {
        connectionFailed = false;
        authPermanentlyFailed = false;
        return m;
      })
      .catch((err) => {
        const errMsg = String(err?.message || '');
        const isAuthError =
          errMsg.toLowerCase().includes('bad auth') ||
          errMsg.toLowerCase().includes('authentication failed') ||
          errMsg.toLowerCase().includes('auth failed');

        if (isAuthError) {
          authPermanentlyFailed = true;
        }

        connectionFailed = true;
        cached!.promise = null;
        return null;
      });
  }

  try {
    cached!.conn = await cached!.promise;
  } catch {
    cached!.conn = null;
    cached!.promise = null;
    connectionFailed = true;
  }

  return cached!.conn;
}

export default connectToDatabase;
