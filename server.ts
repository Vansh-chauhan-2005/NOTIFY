import dotenv from 'dotenv';
dotenv.config({ override: true });
import http from 'http';
import path from 'path';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import {
  registerClientSocket,
  unregisterClientSocket,
  initBullMQWorkers,
} from './src/lib/queue/worker.js';
import { startDeliveryWorkerLoop } from './src/lib/delivery/workerLoop.js';
import { startEphemeralSweeperLoop } from './src/lib/ephemeral/ephemeralStore.js';
import { getTrustProxyHops } from './src/lib/gateway/identity.js';
import {
  createIngressGatewayMiddleware,
  createPostJsonHardeningMiddleware,
  gatewayRawBodyVerifier,
} from './src/lib/gateway/middleware.js';
import { verifySessionToken, type AuthenticatedRequestUser } from './src/lib/auth/requestAuth.js';

// Route handlers
import * as RegisterRoute from './src/app/api/v1/auth/register/route.js';
import * as LoginRoute from './src/app/api/v1/auth/login/route.js';
import * as OtpSendRoute from './src/app/api/v1/auth/otp/send/route.js';
import * as OtpVerifyRoute from './src/app/api/v1/auth/otp/verify/route.js';
import * as OtpAuditRoute from './src/app/api/v1/auth/otp/audit/route.js';
import * as SmsSendRoute from './src/app/api/v1/auth/sms/send/route.js';
import * as SmsVerifyRoute from './src/app/api/v1/auth/sms/verify/route.js';
import * as SmsStatusRoute from './src/app/api/v1/auth/sms/status/route.js';
import * as FirebaseGoogleRoute from './src/app/api/v1/auth/firebase/google/route.js';
import * as FirebaseSessionRoute from './src/app/api/v1/auth/firebase/session/route.js';
import * as KeysBackupRoute from './src/app/api/v1/auth/keys-backup/route.js';
import * as SessionsRoute from './src/app/api/v1/auth/sessions/route.js';
import * as AuthTelemetryRoute from './src/app/api/v1/auth/telemetry/route.js';
import * as ChatRoute from './src/app/api/v1/chat/route.js';
import * as ApiKeysRoute from './src/app/api/v1/auth/api-keys/route.js';
import * as MeRoute from './src/app/api/v1/auth/me/route.js';
import * as IngestRoute from './src/app/api/v1/notifications/ingest/route.js';
import * as HistoryRoute from './src/app/api/v1/notifications/history/route.js';
import * as AckRoute from './src/app/api/v1/notifications/ack/[notificationId]/route.js';
import * as StreamRoute from './src/app/api/v1/notifications/stream/route.js';
import * as PreferencesRoute from './src/app/api/v1/users/preferences/route.js';
import * as PushSubRoute from './src/app/api/v1/users/push-subscription/route.js';
import * as MetricsRoute from './src/app/api/v1/analytics/metrics/route.js';
import * as HealthRoute from './src/app/api/v1/analytics/health/route.js';
import * as IntegrationsRoute from './src/app/api/v1/integrations/route.js';
import * as IntegrationsAppRoute from './src/app/api/v1/integrations/[appId]/route.js';
import * as WebhookRoute from './src/app/api/v1/integrations/webhook/route.js';
import * as IntegrationsTestRoute from './src/app/api/v1/integrations/test/route.js';
import * as QuarantineRoute from './src/app/api/v1/notifications/quarantine/route.js';
import * as PriorityRoute from './src/app/api/v1/notifications/priority/route.js';
import * as FallbackTestRoute from './src/app/api/v1/notifications/fallback/test/route.js';
import * as FallbackTargetPhoneRoute from './src/app/api/v1/notifications/fallback/target-phone/route.js';
import * as TelemetryEventsRoute from './src/app/api/v1/telemetry/events/route.js';
import * as TelemetryStatsRoute from './src/app/api/v1/telemetry/stats/route.js';
import * as TelemetryClientEventRoute from './src/app/api/v1/telemetry/client-event/route.js';
import * as ConnectionsRoute from './src/app/api/v1/connections/route.js';
import * as ConnectionIngestRoute from './src/app/api/v1/ingest/[connectionId]/route.js';
import * as DeliveryJobsRoute from './src/app/api/v1/delivery/jobs/route.js';
import * as DeliveryJobByIdRoute from './src/app/api/v1/delivery/jobs/[id]/route.js';
import * as DeliveryJobCancelRoute from './src/app/api/v1/delivery/jobs/[id]/cancel/route.js';
import * as DeliveryAckRoute from './src/app/api/v1/delivery/[jobId]/ack/route.js';
import * as DeliveryStatsRoute from './src/app/api/v1/delivery/stats/route.js';
import * as DeliverySimulateRoute from './src/app/api/v1/delivery/simulate/route.js';
import * as EphemeralRoute from './src/app/api/v1/ephemeral/route.js';
import * as EphemeralStatsRoute from './src/app/api/v1/ephemeral/stats/route.js';
import * as EphemeralSimulateRoute from './src/app/api/v1/ephemeral/simulate/route.js';
import * as EphemeralPubKeyRoute from './src/app/api/v1/ephemeral/public-key/route.js';
import * as EphemeralPubKeyUserRoute from './src/app/api/v1/ephemeral/public-key/[userId]/route.js';
import * as EphemeralByIdRoute from './src/app/api/v1/ephemeral/[id]/route.js';
import * as EphemeralBurnRoute from './src/app/api/v1/ephemeral/[id]/burn/route.js';
import * as ProvenanceKeysRoute from './src/app/api/v1/provenance/keys/route.js';
import * as ProvenanceRotateRoute from './src/app/api/v1/provenance/keys/rotate/route.js';
import * as ProvenanceRevokeRoute from './src/app/api/v1/provenance/keys/revoke/route.js';
import * as ProvenanceUserKeysRoute from './src/app/api/v1/provenance/keys/[userId]/route.js';
import * as ProvenanceServerKeyRoute from './src/app/api/v1/provenance/server-key/route.js';
import * as ProvenanceKeyLogRoute from './src/app/api/v1/provenance/keylog/route.js';
import * as ProvenanceVerifyRoute from './src/app/api/v1/provenance/verify/route.js';
import * as ProvenanceQuarantineRoute from './src/app/api/v1/provenance/quarantine/route.js';
import * as ProvenanceSimulateRoute from './src/app/api/v1/provenance/simulate/route.js';
import * as PriorityScoreRoute from './src/app/api/v1/priority/score/route.js';
import * as PriorityModelRoute from './src/app/api/v1/priority/model/route.js';
import * as PriorityFeedbackRoute from './src/app/api/v1/priority/feedback/route.js';
import * as PriorityResetRoute from './src/app/api/v1/priority/reset/route.js';
import * as PriorityStatsRoute from './src/app/api/v1/priority/stats/route.js';
import * as PrioritySimulateRoute from './src/app/api/v1/priority/simulate/route.js';
import * as DedupConfigRoute from './src/app/api/v1/dedup/config/route.js';
import * as DedupFeedbackRoute from './src/app/api/v1/dedup/feedback/route.js';
import * as DedupThreadsRoute from './src/app/api/v1/dedup/threads/route.js';
import * as DedupThreadUngroupRoute from './src/app/api/v1/dedup/threads/[id]/ungroup/route.js';
import * as DedupStatsRoute from './src/app/api/v1/dedup/stats/route.js';
import * as DedupSimulateRoute from './src/app/api/v1/dedup/simulate/route.js';
import * as GatewayStatsRoute from './src/app/api/v1/gateway/stats/route.js';
import * as GatewayBlocksRoute from './src/app/api/v1/gateway/blocks/route.js';
import * as GatewayBlockByIdRoute from './src/app/api/v1/gateway/blocks/[id]/route.js';
import * as GatewayAllowlistRoute from './src/app/api/v1/gateway/allowlist/route.js';
import * as GatewayPoliciesRoute from './src/app/api/v1/gateway/policies/route.js';
import * as GatewayHealthRoute from './src/app/api/v1/gateway/health/route.js';
import * as GatewaySimulateRoute from './src/app/api/v1/gateway/simulate/route.js';

const PORT = 3000;
const HOST = '0.0.0.0';

function isAllowedOrigin(origin: string | undefined, requestHost: string | undefined): boolean {
  if (!origin) return false;
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }

  if (requestHost && parsed.host === requestHost) {
    return true;
  }

  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) {
    try {
      if (new URL(appUrl).origin === parsed.origin) return true;
    } catch {}
  }

  const extra = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (extra.includes(parsed.origin)) {
    return true;
  }

  if (
    process.env.NODE_ENV !== 'production' &&
    (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
  ) {
    return true;
  }

  return false;
}

// Helper to bridge Next.js App Router Request/Response to Express req/res
function adaptNextRoute(handler: (req: Request, context?: any) => Promise<Response>) {
  return async (req: express.Request, res: express.Response) => {
    try {
      const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (value) {
          headers.set(key, Array.isArray(value) ? value.join(', ') : value);
        }
      }

      let bodyContent: string | undefined;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const rawBody = (req as any).rawBody;
        if (typeof rawBody === 'string' && rawBody.length > 0) {
          bodyContent = rawBody;
        } else if (req.body) {
          bodyContent = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        }
      }

      const nextRequest = new Request(url, {
        method: req.method,
        headers,
        body: bodyContent,
      });

      const context = { params: req.params };
      const nextResponse = await handler(nextRequest, context);

      res.status(nextResponse.status);
      nextResponse.headers.forEach((val, key) => {
        res.setHeader(key, val);
      });

      const responseText = await nextResponse.text();
      res.send(responseText);
    } catch (err: any) {
      console.error('[Route Adapter Error]', err);
      res.status(500).json({
        success: false,
        error: 'Internal Route Execution Error',
        message: 'An unexpected server error occurred.',
      });
    }
  };
}

async function startAegisPlatform() {
  const app = express();
  app.set('trust proxy', getTrustProxyHops());

  // 1. Ingress Gateway & DoS Rate Limiter FIRST in chain (before body parsing & all routes)
  app.use(createIngressGatewayMiddleware());

  // 2. Bounded JSON body parser with pre-route raw prototype-pollution & size checks
  app.use(
    express.json({
      limit: '512kb',
      verify: gatewayRawBodyVerifier,
    })
  );

  // 3. Post-parse JSON structural depth / key-count / array-length / prototype-pollution hardening
  app.use(createPostJsonHardeningMiddleware());

  // 4. Security headers & Zero-Trust CORS (strict origin allowlist, no wildcard)
  app.use((req, res, next) => {
    res.setHeader('X-Aegis-Zero-Trust', 'Ed25519-Verified');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Vary', 'Origin');

    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
    if (origin && isAllowedOrigin(origin, req.get('host'))) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-API-Key, X-Firebase-Id-Token, X-Aegis-Signature, X-Aegis-Timestamp, X-Aegis-Priority, X-Hub-Signature-256, X-Telegram-Bot-Api-Secret-Token'
      );
    }

    if (req.method === 'OPTIONS') {
      if (origin && !isAllowedOrigin(origin, req.get('host'))) {
        return res.status(403).end();
      }
      return res.status(204).end();
    }
    next();
  });

  // API Ingestion & Authentication Routes (Supporting both /auth/* and /api/v1/auth/*)
  app.post('/auth/register', adaptNextRoute(RegisterRoute.POST));
  app.post('/api/v1/auth/register', adaptNextRoute(RegisterRoute.POST));
  app.post('/auth/login', adaptNextRoute(LoginRoute.POST));
  app.post('/api/v1/auth/login', adaptNextRoute(LoginRoute.POST));
  app.post('/auth/otp/send', adaptNextRoute(OtpSendRoute.POST));
  app.post('/api/v1/auth/otp/send', adaptNextRoute(OtpSendRoute.POST));
  app.get('/auth/otp/send', adaptNextRoute(OtpSendRoute.GET));
  app.get('/api/v1/auth/otp/send', adaptNextRoute(OtpSendRoute.GET));
  app.post('/auth/otp/verify', adaptNextRoute(OtpVerifyRoute.POST));
  app.post('/api/v1/auth/otp/verify', adaptNextRoute(OtpVerifyRoute.POST));
  app.get('/auth/otp/audit', adaptNextRoute(OtpAuditRoute.GET));
  app.get('/api/v1/auth/otp/audit', adaptNextRoute(OtpAuditRoute.GET));
  app.post('/auth/sms/send', adaptNextRoute(SmsSendRoute.POST));
  app.post('/api/v1/auth/sms/send', adaptNextRoute(SmsSendRoute.POST));
  app.post('/auth/sms/verify', adaptNextRoute(SmsVerifyRoute.POST));
  app.post('/api/v1/auth/sms/verify', adaptNextRoute(SmsVerifyRoute.POST));
  app.get('/auth/sms/status', adaptNextRoute(SmsStatusRoute.GET));
  app.get('/api/v1/auth/sms/status', adaptNextRoute(SmsStatusRoute.GET));
  app.post('/auth/firebase/google', adaptNextRoute(FirebaseGoogleRoute.POST));
  app.post('/api/v1/auth/firebase/google', adaptNextRoute(FirebaseGoogleRoute.POST));
  app.post('/auth/firebase/session', adaptNextRoute(FirebaseSessionRoute.POST));
  app.post('/api/v1/auth/firebase/session', adaptNextRoute(FirebaseSessionRoute.POST));
  app.get('/api/v1/auth/keys-backup', adaptNextRoute(KeysBackupRoute.GET));
  app.post('/api/v1/auth/keys-backup', adaptNextRoute(KeysBackupRoute.POST));
  app.get('/api/v1/auth/sessions', adaptNextRoute(SessionsRoute.GET));
  app.post('/api/v1/auth/sessions', adaptNextRoute(SessionsRoute.POST));
  app.post('/api/v1/auth/telemetry', adaptNextRoute(AuthTelemetryRoute.POST));
  app.post('/api/v1/chat', adaptNextRoute(ChatRoute.POST));
  app.get('/auth/api-keys', adaptNextRoute(ApiKeysRoute.GET));
  app.get('/api/v1/auth/api-keys', adaptNextRoute(ApiKeysRoute.GET));
  app.post('/auth/api-keys', adaptNextRoute(ApiKeysRoute.POST));
  app.post('/api/v1/auth/api-keys', adaptNextRoute(ApiKeysRoute.POST));
  app.get('/auth/me', adaptNextRoute(MeRoute.GET));
  app.get('/api/v1/auth/me', adaptNextRoute(MeRoute.GET));

  app.post('/api/v1/notifications/ingest', adaptNextRoute(IngestRoute.POST));
  app.get('/api/v1/notifications/history', adaptNextRoute(HistoryRoute.GET));
  app.post('/api/v1/notifications/ack/:notificationId', adaptNextRoute(AckRoute.POST));
  app.get('/api/v1/notifications/stream', adaptNextRoute(StreamRoute.GET));

  app.get('/api/v1/users/preferences', adaptNextRoute(PreferencesRoute.GET));
  app.put('/api/v1/users/preferences', adaptNextRoute(PreferencesRoute.PUT));
  app.get('/api/v1/users/push-subscription', adaptNextRoute(PushSubRoute.GET));
  app.post('/api/v1/users/push-subscription', adaptNextRoute(PushSubRoute.POST));

  app.get('/api/v1/analytics/metrics', adaptNextRoute(MetricsRoute.GET));
  app.get('/api/v1/analytics/health', adaptNextRoute(HealthRoute.GET));

  app.get('/api/v1/integrations', adaptNextRoute(IntegrationsRoute.GET));
  app.post('/api/v1/integrations', adaptNextRoute(IntegrationsRoute.POST));
  app.get('/api/v1/integrations/:appId', adaptNextRoute(IntegrationsAppRoute.GET));
  app.put('/api/v1/integrations/:appId', adaptNextRoute(IntegrationsAppRoute.PUT));
  app.post('/api/v1/integrations/webhook', adaptNextRoute(WebhookRoute.POST));
  app.post('/api/v1/integrations/test', adaptNextRoute(IntegrationsTestRoute.POST));

  app.get('/api/v1/notifications/quarantine', adaptNextRoute(QuarantineRoute.GET));
  app.post('/api/v1/notifications/quarantine', adaptNextRoute(QuarantineRoute.POST));
  app.delete('/api/v1/notifications/quarantine', adaptNextRoute(QuarantineRoute.DELETE));
  app.patch('/api/v1/notifications/priority', adaptNextRoute(PriorityRoute.PATCH));
  app.post('/api/v1/notifications/priority', adaptNextRoute(PriorityRoute.POST));
  app.get('/api/v1/notifications/fallback/test', adaptNextRoute(FallbackTestRoute.GET));
  app.post('/api/v1/notifications/fallback/test', adaptNextRoute(FallbackTestRoute.POST));
  app.get('/api/v1/notifications/fallback/target-phone', adaptNextRoute(FallbackTargetPhoneRoute.GET));
  app.post('/api/v1/notifications/fallback/target-phone', adaptNextRoute(FallbackTargetPhoneRoute.POST));

  app.get('/api/v1/telemetry/events', adaptNextRoute(TelemetryEventsRoute.GET));
  app.get('/api/v1/telemetry/stats', adaptNextRoute(TelemetryStatsRoute.GET));
  app.post('/api/v1/telemetry/client-event', adaptNextRoute(TelemetryClientEventRoute.POST));

  app.get('/api/v1/connections', adaptNextRoute(ConnectionsRoute.GET));
  app.post('/api/v1/connections', adaptNextRoute(ConnectionsRoute.POST));
  app.delete('/api/v1/connections', adaptNextRoute(ConnectionsRoute.DELETE));
  app.get('/api/v1/ingest/:connectionId', adaptNextRoute(ConnectionIngestRoute.GET));
  app.post('/api/v1/ingest/:connectionId', adaptNextRoute(ConnectionIngestRoute.POST));

  // Multi-Channel Fallback State Machine Delivery Routes
  app.get('/api/v1/delivery/jobs', adaptNextRoute(DeliveryJobsRoute.GET));
  app.post('/api/v1/delivery/jobs', adaptNextRoute(DeliveryJobsRoute.POST));
  app.get('/api/v1/delivery/jobs/:id', adaptNextRoute(DeliveryJobByIdRoute.GET));
  app.post('/api/v1/delivery/jobs/:id/cancel', adaptNextRoute(DeliveryJobCancelRoute.POST));
  app.get('/api/v1/delivery/ack', adaptNextRoute(DeliveryAckRoute.GET));
  app.post('/api/v1/delivery/ack', adaptNextRoute(DeliveryAckRoute.POST));
  app.get('/api/v1/delivery/:jobId/ack', adaptNextRoute(DeliveryAckRoute.GET));
  app.post('/api/v1/delivery/:jobId/ack', adaptNextRoute(DeliveryAckRoute.POST));
  app.get('/api/v1/delivery/stats', adaptNextRoute(DeliveryStatsRoute.GET));
  app.post('/api/v1/delivery/simulate', adaptNextRoute(DeliverySimulateRoute.POST));

  // Ephemeral Data Isolation (300s TTL & Crypto-Shredding) Routes
  // Note: static routes (/stats, /simulate, /public-key) must be registered before /:id
  app.get('/api/v1/ephemeral', adaptNextRoute(EphemeralRoute.GET));
  app.post('/api/v1/ephemeral', adaptNextRoute(EphemeralRoute.POST));
  app.get('/api/v1/ephemeral/stats', adaptNextRoute(EphemeralStatsRoute.GET));
  app.post('/api/v1/ephemeral/simulate', adaptNextRoute(EphemeralSimulateRoute.POST));
  app.post('/api/v1/ephemeral/public-key', adaptNextRoute(EphemeralPubKeyRoute.POST));
  app.get('/api/v1/ephemeral/public-key/:userId', adaptNextRoute(EphemeralPubKeyUserRoute.GET));
  app.get('/api/v1/ephemeral/:id', adaptNextRoute(EphemeralByIdRoute.GET));
  app.post('/api/v1/ephemeral/:id/burn', adaptNextRoute(EphemeralBurnRoute.POST));

  // Zero-Trust Ed25519 Provenance & Key Transparency Log Routes
  // Static paths (/rotate, /revoke) must precede :userId parameter route
  app.post('/api/v1/provenance/keys', adaptNextRoute(ProvenanceKeysRoute.POST));
  app.post('/api/v1/provenance/keys/rotate', adaptNextRoute(ProvenanceRotateRoute.POST));
  app.post('/api/v1/provenance/keys/revoke', adaptNextRoute(ProvenanceRevokeRoute.POST));
  app.get('/api/v1/provenance/keys/:userId', adaptNextRoute(ProvenanceUserKeysRoute.GET));
  app.get('/api/v1/provenance/server-key', adaptNextRoute(ProvenanceServerKeyRoute.GET));
  app.get('/api/v1/provenance/keylog', adaptNextRoute(ProvenanceKeyLogRoute.GET));
  app.post('/api/v1/provenance/verify', adaptNextRoute(ProvenanceVerifyRoute.POST));
  app.get('/api/v1/provenance/quarantine', adaptNextRoute(ProvenanceQuarantineRoute.GET));
  app.post('/api/v1/provenance/simulate', adaptNextRoute(ProvenanceSimulateRoute.POST));

  // Dynamic Sigmoid Priority Engine Routes
  app.post('/api/v1/priority/score', adaptNextRoute(PriorityScoreRoute.POST));
  app.get('/api/v1/priority/model', adaptNextRoute(PriorityModelRoute.GET));
  app.put('/api/v1/priority/model', adaptNextRoute(PriorityModelRoute.PUT));
  app.post('/api/v1/priority/feedback', adaptNextRoute(PriorityFeedbackRoute.POST));
  app.post('/api/v1/priority/reset', adaptNextRoute(PriorityResetRoute.POST));
  app.get('/api/v1/priority/stats', adaptNextRoute(PriorityStatsRoute.GET));
  app.post('/api/v1/priority/simulate', adaptNextRoute(PrioritySimulateRoute.POST));

  // Semantic Deduplication (ONNX NLP) Metadata-Only Routes
  app.get('/api/v1/dedup/config', adaptNextRoute(DedupConfigRoute.GET));
  app.put('/api/v1/dedup/config', adaptNextRoute(DedupConfigRoute.PUT));
  app.post('/api/v1/dedup/feedback', adaptNextRoute(DedupFeedbackRoute.POST));
  app.get('/api/v1/dedup/threads', adaptNextRoute(DedupThreadsRoute.GET));
  app.post('/api/v1/dedup/threads', adaptNextRoute(DedupThreadsRoute.POST));
  app.post('/api/v1/dedup/threads/:id/ungroup', adaptNextRoute(DedupThreadUngroupRoute.POST));
  app.get('/api/v1/dedup/stats', adaptNextRoute(DedupStatsRoute.GET));
  app.post('/api/v1/dedup/simulate', adaptNextRoute(DedupSimulateRoute.POST));

  // Ingress Gateway & DoS Rate Limiter Routes
  app.get('/api/v1/gateway/health', adaptNextRoute(GatewayHealthRoute.GET));
  app.get('/api/v1/gateway/stats', adaptNextRoute(GatewayStatsRoute.GET));
  app.get('/api/v1/gateway/blocks', adaptNextRoute(GatewayBlocksRoute.GET));
  app.post('/api/v1/gateway/blocks', adaptNextRoute(GatewayBlocksRoute.POST));
  app.delete('/api/v1/gateway/blocks/:id', adaptNextRoute(GatewayBlockByIdRoute.DELETE));
  app.get('/api/v1/gateway/allowlist', adaptNextRoute(GatewayAllowlistRoute.GET));
  app.post('/api/v1/gateway/allowlist', adaptNextRoute(GatewayAllowlistRoute.POST));
  app.delete('/api/v1/gateway/allowlist', adaptNextRoute(GatewayAllowlistRoute.DELETE));
  app.get('/api/v1/gateway/policies', adaptNextRoute(GatewayPoliciesRoute.GET));
  app.put('/api/v1/gateway/policies', adaptNextRoute(GatewayPoliciesRoute.PUT));
  app.post('/api/v1/gateway/simulate', adaptNextRoute(GatewaySimulateRoute.POST));

  // Initialize BullMQ Workers, Durable Delivery Worker (2s), and Ephemeral TTL Sweeper (5s)
  initBullMQWorkers();
  startDeliveryWorkerLoop(2000);
  startEphemeralSweeperLoop(5000);

  // Create HTTP Server with Slowloris / slow-request timeouts
  const server = http.createServer(app);
  server.headersTimeout = 10_000;
  server.requestTimeout = 20_000;
  server.keepAliveTimeout = 5_000;

  // Attach WebSocket Server with JWT upgrade verification
  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
    if (url.pathname !== '/ws' && url.pathname !== '/api/v1/notifications/stream') {
      socket.destroy();
      return;
    }

    const origin = typeof request.headers.origin === 'string' ? request.headers.origin : undefined;
    if (origin && !isAllowedOrigin(origin, request.headers.host)) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    const authHeader =
      typeof request.headers.authorization === 'string' ? request.headers.authorization : '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const queryToken = url.searchParams.get('token') || '';
    const wsToken = bearerToken || queryToken;
    const caller = verifySessionToken(wsToken);

    if (!caller) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request, caller, wsToken);
    });
  });

  wss.on(
    'connection',
    (
      ws: WebSocket,
      request: http.IncomingMessage,
      caller: AuthenticatedRequestUser,
      wsToken: string
    ) => {
      const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
      const requestedUserId = url.searchParams.get('userId');
      const userId =
        caller.role === 'ADMIN' && requestedUserId ? requestedUserId : caller.userId;
      const socketId = `ws_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

      const sendFn = (data: string) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(data);
        }
      };

      registerClientSocket(userId, socketId, sendFn);

      // Initial greeting and presence affirmation
      ws.send(
        JSON.stringify({
          type: 'CONNECTION_READY',
          socketId,
          userId,
          serverTime: new Date().toISOString(),
          message: 'Aegis Zero-Trust Real-time Secure Channel Open',
        })
      );

      ws.on('message', async (raw) => {
        try {
          const msg = JSON.parse(raw.toString());
          if (msg.type === 'ACK' && msg.notificationId) {
            const mockReq = new Request(
              `http://localhost:3000/api/v1/notifications/ack/${encodeURIComponent(
                String(msg.notificationId)
              )}`,
              {
                method: 'POST',
                headers: {
                  Authorization: `Bearer ${wsToken}`,
                },
              }
            );
            await AckRoute.POST(mockReq, {
              params: { notificationId: String(msg.notificationId) },
            });
          }
        } catch {}
      });

      ws.on('close', () => {
        unregisterClientSocket(userId, socketId);
      });

      ws.on('error', (err) => {
        console.warn('[WebSocket Client Error]', err);
        unregisterClientSocket(userId, socketId);
      });
    }
  );

  // Ensure unmatched /api/* and /auth/* routes always return JSON (never fall through to HTML index.html)
  app.use(['/api', '/auth'], (req, res) => {
    res.status(404).json({
      success: false,
      error: 'Not Found',
      message: `API route not found: ${req.method} ${req.originalUrl}`,
    });
  });

  // Express JSON error handler (catches malformed JSON body errors, oversize 413, etc. as JSON only)
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status =
      err?.type === 'entity.too.large'
        ? 413
        : typeof err?.status === 'number'
        ? err.status
        : typeof err?.statusCode === 'number'
        ? err.statusCode
        : 500;
    if (status >= 500) {
      console.error('[Express Server Error]', err);
    }
    res.status(status).json({
      success: false,
      error: status === 413 ? 'Payload Too Large' : status >= 500 ? 'Server Error' : err?.name || 'Request Error',
      message:
        status >= 500
          ? 'An unexpected server error occurred.'
          : err?.message || 'Request could not be processed.',
    });
  });

  // Vite Middleware in Dev vs Static in Production
  let servedViaVite = false;
  if (process.env.NODE_ENV !== 'production') {
    try {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
      servedViaVite = true;
    } catch {
      servedViaVite = false;
    }
  }
  if (!servedViaVite) {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, HOST, () => {
    console.log(`[AegisNotify Engine] Operational at http://${HOST}:${PORT}`);
    console.log(`[AegisNotify Engine] Real-time WebSocket listening at ws://${HOST}:${PORT}/ws`);
  });
}

startAegisPlatform().catch((err) => {
  console.error('[Fatal Error Starting Platform]', err);
});
