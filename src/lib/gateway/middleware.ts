import type express from 'express';
import jwt from 'jsonwebtoken';
import { evaluateGatewayRequest } from './engine.js';
import { inspectRawJsonTextForPollution, validateParsedJsonSafety } from './hardening.js';
import { getGatewayMetrics } from './metrics.js';
import { classifyRequestRoute, getPolicyForGroup } from './policies.js';
import type { RoutePolicy } from './types.js';
import { getJwtSecret } from '../auth/jwtSecret.js';

function tryExtractUserFromRequest(req: express.Request): {
  userId?: string;
  isAuthenticated: boolean;
} {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) {
      try {
        const decoded = jwt.verify(token, getJwtSecret()) as any;
        if (decoded?.userId) {
          return { userId: String(decoded.userId), isAuthenticated: true };
        }
      } catch {
        // Ignore invalid JWT at ingress identity step; protected routes still verify auth
      }
    }
  }

  return { isAuthenticated: false };
}

/**
 * FIRST middleware in the Express chain, installed BEFORE body parsing and BEFORE any route.
 * Runs cheap rejections, client identification, load shedding, concurrency, rate limiting,
 * and installs a per-request slow-request deadline.
 */
export function createIngressGatewayMiddleware() {
  const metrics = getGatewayMetrics();

  return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const startHr = process.hrtime.bigint();
    metrics.incrementInFlight();

    let metricsFinalized = false;
    let releaseConcurrencyFn: () => void = () => {};
    let deadlineTimer: ReturnType<typeof setTimeout> | null = null;
    let timedOut = false;

    const finalize = () => {
      if (metricsFinalized) return;
      metricsFinalized = true;
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
        deadlineTimer = null;
      }
      releaseConcurrencyFn();
      metrics.decrementInFlight();
      const elapsedMs = Number(process.hrtime.bigint() - startHr) / 1e6;
      metrics.recordLatency(elapsedMs);
    };

    res.on('finish', finalize);
    res.on('close', finalize);

    try {
      const authCtx = tryExtractUserFromRequest(req);
      const priorityHeader = String(req.headers['x-aegis-priority'] || '').toUpperCase();
      const isCriticalPriority = priorityHeader === 'CRITICAL';

      const evalResult = await evaluateGatewayRequest({
        method: req.method,
        url: req.originalUrl || req.url,
        headers: req.headers as Record<string, string | string[] | undefined>,
        socketRemoteAddress: req.socket?.remoteAddress || req.ip,
        userId: authCtx.userId,
        isAuthenticated: authCtx.isAuthenticated,
        isCriticalPriority,
      });

      releaseConcurrencyFn = evalResult.releaseConcurrency;
      (req as any).__aegisGatewayPolicy = evalResult.policy;
      (req as any).__aegisGatewayShortIp = evalResult.shortIpHash;

      // Always attach standard RateLimit-* / Retry-After headers
      for (const [k, v] of Object.entries(evalResult.decision.headers)) {
        res.setHeader(k, v);
      }

      if (!evalResult.decision.allowed) {
        return res.status(evalResult.decision.statusCode).json({
          success: false,
          message: evalResult.decision.message,
          ...(evalResult.decision.retryAfterSeconds !== undefined
            ? { retryAfterSeconds: evalResult.decision.retryAfterSeconds }
            : {}),
          ...(evalResult.decision.challengeRequired
            ? { challengeRequired: true }
            : {}),
        });
      }

      // Progressive penalty box slowdown delay (bounded) if client is in SLOWDOWN stage
      if (evalResult.decision.artificialDelayMs && evalResult.decision.artificialDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, evalResult.decision.artificialDelayMs));
      }

      // Slow-request / Slowloris per-request deadline guard (skip SSE stream routes)
      const isStreamRoute = (req.originalUrl || '').includes('/notifications/stream');
      if (!isStreamRoute && evalResult.policy.requestTimeoutMs > 0) {
        deadlineTimer = setTimeout(() => {
          timedOut = true;
          if (!res.headersSent) {
            metrics.recordOutcome({
              routeGroup: evalResult.policy.group,
              outcome: 'shed',
              shortIpHash: evalResult.shortIpHash,
              detail: `Request deadline exceeded (${evalResult.policy.requestTimeoutMs}ms) on ${evalResult.policy.group}.`,
            });
            res.status(408).json({
              success: false,
              message: 'Request deadline exceeded. Slow request aborted by ingress gateway.',
            });
          }
        }, evalResult.policy.requestTimeoutMs);
        deadlineTimer.unref?.();
      }

      if (timedOut) return;
      next();
    } catch (err: any) {
      finalize();
      if (!res.headersSent) {
        res.status(500).json({
          success: false,
          message: 'Ingress gateway evaluation error.',
        });
      }
    }
  };
}

/**
 * Raw-body verification hook passed into express.json({ verify }) to block prototype-pollution
 * keys before parsed objects propagate, plus enforce exact streaming byte limit.
 */
export function gatewayRawBodyVerifier(
  req: express.Request,
  _res: express.Response,
  buf: Buffer
): void {
  const raw = buf.toString('utf8');
  (req as any).rawBody = raw;

  const routeMatch = classifyRequestRoute(req.method, req.originalUrl || req.url);
  const policy: RoutePolicy =
    (req as any).__aegisGatewayPolicy || getPolicyForGroup(routeMatch.group);

  if (buf.byteLength > policy.maxBodyBytes) {
    const err: any = new Error(
      `Payload byte length (${buf.byteLength}) exceeds ${Math.round(
        policy.maxBodyBytes / 1024
      )} KB route cap.`
    );
    err.status = 413;
    err.gatewayOutcome = 'oversize';
    throw err;
  }

  const pollutionCheck = inspectRawJsonTextForPollution(raw);
  if (!pollutionCheck.ok) {
    const err: any = new Error(pollutionCheck.message);
    err.status = 400;
    err.gatewayOutcome = 'malformed';
    throw err;
  }
}

/**
 * Runs immediately AFTER express.json() to enforce JSON depth, key count, array length,
 * and prototype-pollution object key checks before any route handler sees req.body.
 */
export function createPostJsonHardeningMiddleware() {
  const metrics = getGatewayMetrics();

  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.body === undefined || req.body === null || typeof req.body !== 'object') {
      return next();
    }

    const routeMatch = classifyRequestRoute(req.method, req.originalUrl || req.url);
    const policy: RoutePolicy =
      (req as any).__aegisGatewayPolicy || getPolicyForGroup(routeMatch.group);
    const shortIpHash: string = (req as any).__aegisGatewayShortIp || 'unknown';

    const check = validateParsedJsonSafety(req.body, {
      maxDepth: policy.maxJsonDepth,
      maxKeys: policy.maxJsonKeys,
      maxArrayLength: policy.maxJsonArrayLength,
    });

    if (!check.ok) {
      metrics.recordOutcome({
        routeGroup: policy.group,
        outcome: 'malformed',
        shortIpHash,
        detail: check.message || 'JSON structural guard rejected payload.',
      });
      return res.status(check.statusCode || 400).json({
        success: false,
        message: check.message || 'JSON payload violates security structure limits.',
      });
    }

    next();
  };
}
