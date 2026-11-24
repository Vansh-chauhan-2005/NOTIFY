import { enforceRateLimit, hasActiveSocketPresence } from '../../../../../lib/queue/worker.js';
import { calculateDispatchWeight } from '../../../../../lib/math/riskScoring.js';
import {
  signPayload,
  getServerKeyPair,
  processEphemeralSecurityData,
} from '../../../../../lib/crypto/ed25519.js';
import { NotificationLog, inMemoryNotificationLogs } from '../../../../../models/NotificationLog.js';
import { getNotificationQueue } from '../../../../../lib/queue/bullmq.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { addQuarantinedAlert } from '../../../../../lib/quarantine/store.js';
import {
  logSecurityEvent,
  extractRequestContext,
} from '../../../../../lib/telemetry/securityLogger.js';
import {
  getConnectionById,
  decryptSecret,
  encryptSecret,
  verifyIngestSignature,
  isTimestampWithinReplayWindow,
  sanitizeNotificationText,
  classifyIngestedPriority,
  incrementConnectionReceived,
  MAX_INGEST_PAYLOAD_BYTES,
} from '../../../../../lib/integrations/connectionsStore.js';
import {
  computeTextImportanceScore,
  extractFeaturesFromContent,
} from '../../../../../lib/priority/features.js';
import { toLegacyNotificationPriority } from '../../../../../lib/priority/math.js';
import {
  getUserPriorityModelState,
  scoreForUser,
} from '../../../../../lib/priority/store.js';
import { createServerAttestedEnvelope } from '../../../../../lib/provenance/serverCrypto.js';

function extractNormalizedContent(
  parsedBody: Record<string, any>,
  appName: string
): { title: string; rawText: string; eventType: string; priorityHint?: string } {
  // Telegram Bot API Update shape
  if (parsedBody.message && typeof parsedBody.message === 'object') {
    const msg = parsedBody.message;
    const sender = sanitizeNotificationText(
      msg.from?.username || msg.from?.first_name || 'Telegram Contact',
      60
    );
    const bodyText = sanitizeNotificationText(msg.text || msg.caption || 'Telegram bot message', 420);
    return {
      title: `${appName} · ${sender}`,
      rawText: bodyText,
      eventType: 'TELEGRAM_BOT_MESSAGE',
      priorityHint: parsedBody.priority,
    };
  }

  // GitHub Webhook shape
  if (parsedBody.repository && typeof parsedBody.repository === 'object') {
    const repo = sanitizeNotificationText(parsedBody.repository.full_name || 'repository', 80);
    const actor = sanitizeNotificationText(parsedBody.sender?.login || 'github', 40);
    const action = sanitizeNotificationText(
      parsedBody.action || parsedBody.head_commit?.message || 'webhook event',
      240
    );
    return {
      title: `${appName} · ${repo}`,
      rawText: `${actor}: ${action}`,
      eventType: String(parsedBody.eventType || 'GITHUB_WEBHOOK').toUpperCase().slice(0, 64),
      priorityHint: parsedBody.priority,
    };
  }

  // Standard Aegis Ingest shape
  const title = sanitizeNotificationText(
    parsedBody.title || parsedBody.subject || `${appName} Alert`,
    120
  );
  const textCandidate =
    parsedBody.rawText ||
    parsedBody.message ||
    parsedBody.text ||
    parsedBody.content ||
    parsedBody.body ||
    '';
  const rawText = sanitizeNotificationText(textCandidate, 480);
  const eventType = sanitizeNotificationText(
    parsedBody.eventType || `${appName.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_INGEST`,
    64
  ).replace(/\s+/g, '_');

  return {
    title: title || `${appName} Alert`,
    rawText,
    eventType: eventType || 'APP_INGEST_EVENT',
    priorityHint: parsedBody.priority ? String(parsedBody.priority) : undefined,
  };
}

export async function POST(
  request: Request,
  context?: { params?: Promise<{ connectionId?: string }> | { connectionId?: string } }
) {
  const reqCtx = extractRequestContext(request);

  try {
    const resolvedParams =
      context?.params && 'then' in (context.params as any)
        ? await (context.params as Promise<{ connectionId?: string }>)
        : ((context?.params || {}) as { connectionId?: string });

    let connectionId = resolvedParams?.connectionId?.trim();
    if (!connectionId) {
      const pathParts = new URL(request.url).pathname.split('/').filter(Boolean);
      connectionId = pathParts[pathParts.length - 1];
    }

    if (!connectionId) {
      return Response.json(
        { success: false, message: 'Missing connectionId parameter.' },
        { status: 400 }
      );
    }

    // 1. Check declared Content-Length before reading body
    const contentLengthHeader = Number(request.headers.get('content-length') || '0');
    if (contentLengthHeader > MAX_INGEST_PAYLOAD_BYTES) {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'blocked',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Ingest payload rejected: Content-Length ${contentLengthHeader} exceeds 64KB limit.`,
      });
      return Response.json(
        { success: false, message: 'Payload exceeds 64KB ingest limit.' },
        { status: 413 }
      );
    }

    // 2. Rate limiting per connection (60 req / 60s)
    const rateResult = await enforceRateLimit(`ingest:${connectionId}`, 60, 60);
    if (!rateResult.allowed) {
      logSecurityEvent({
        eventType: 'RATE_LIMIT_HIT',
        severity: 'warning',
        result: 'blocked',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Connection ingest rate limit exceeded for ${connectionId}.`,
      });
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'blocked',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Ingest throttled (HTTP 429) on connection ${connectionId}.`,
      });
      return Response.json(
        {
          success: false,
          message: 'Rate limit exceeded for this connection. Please slow down and retry shortly.',
        },
        {
          status: 429,
          headers: { 'Retry-After': '60' },
        }
      );
    }

    // 3. Look up connection
    const connection = getConnectionById(connectionId);
    if (!connection || !connection.enabled) {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'blocked',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Ingest targeted unknown or disabled connection ${connectionId}.`,
      });
      return Response.json(
        { success: false, message: 'Unknown or disabled connection.' },
        { status: 404 }
      );
    }

    // 4. Read exact raw body & enforce 64KB byte cap
    const rawBody = await request.text();
    const byteLength = Buffer.byteLength(rawBody, 'utf8');
    if (byteLength > MAX_INGEST_PAYLOAD_BYTES) {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'blocked',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Ingest payload (${byteLength} bytes) exceeded 64KB cap on ${connection.appName}.`,
      });
      return Response.json(
        { success: false, message: 'Payload exceeds 64KB maximum size.' },
        { status: 413 }
      );
    }

    if (!rawBody || !rawBody.trim()) {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'failed',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Empty ingest body rejected for ${connection.appName}.`,
      });
      return Response.json(
        { success: false, message: 'Request body cannot be empty.' },
        { status: 400 }
      );
    }

    // 5. Replay window check (5 minutes)
    const timestampHeader = request.headers.get('x-aegis-timestamp');
    const githubSigHeader = request.headers.get('x-hub-signature-256');
    const telegramSecretHeader = request.headers.get('x-telegram-bot-api-secret-token');
    const aegisSigHeader = request.headers.get('x-aegis-signature');

    const requiresAegisTimestamp = !githubSigHeader && !telegramSecretHeader;
    if (requiresAegisTimestamp || timestampHeader !== null) {
      const replayCheck = isTimestampWithinReplayWindow(timestampHeader);
      if (!replayCheck.valid) {
        addQuarantinedAlert({
          reason: 'INVALID_SIGNATURE',
          reasonLabel: 'Replayed or Stale Webhook Timestamp',
          description: `${connection.appName} ingest rejected: ${replayCheck.reason}`,
          sourceIp: reqCtx.ipAddress,
          sourceApp: connection.appName,
          riskLevel: 'HIGH',
          rawPayload: {
            connectionId: connection.id,
            reason: replayCheck.reason,
          },
        });

        logSecurityEvent({
          eventType: 'INGEST_REJECTED',
          severity: 'warning',
          result: 'blocked',
          userId: connection.userId,
          ipAddress: reqCtx.ipAddress,
          userAgent: reqCtx.userAgent,
          details: `Ingest replay window check failed for ${connection.appName}: ${replayCheck.reason}`,
        });

        return Response.json(
          {
            success: false,
            message: replayCheck.reason || 'Timestamp is missing or outside 5-minute replay window.',
          },
          { status: 401 }
        );
      }
    }

    // 6. Decrypt server-stored connection secret & verify HMAC with timingSafeEqual
    let signingSecret: string;
    try {
      signingSecret = decryptSecret(connection.encryptedSecret);
    } catch {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'critical',
        result: 'failed',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Failed to decrypt signing secret for connection ${connection.id}.`,
      });
      return Response.json(
        { success: false, message: 'Connection key verification unavailable.' },
        { status: 500 }
      );
    }

    const sigCheck = verifyIngestSignature({
      secret: signingSecret,
      rawBody,
      timestampRaw: timestampHeader,
      aegisSignature: aegisSigHeader,
      githubSignature: githubSigHeader,
      telegramSecretHeader,
      connectionType: connection.connectionType,
    });

    if (!sigCheck.valid) {
      addQuarantinedAlert({
        reason: 'INVALID_SIGNATURE',
        reasonLabel: 'Forged Webhook HMAC Signature',
        description: `Rejected signed ingest for ${connection.appName} (${sigCheck.mode}): ${sigCheck.reason}`,
        sourceIp: reqCtx.ipAddress,
        sourceApp: connection.appName,
        riskLevel: 'CRITICAL',
        rawPayload: {
          connectionId: connection.id,
          verificationMode: sigCheck.mode,
          reason: sigCheck.reason,
        },
      });

      logSecurityEvent({
        eventType: 'SIGNATURE_INVALID',
        severity: 'critical',
        result: 'blocked',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Invalid HMAC signature rejected on ${connection.appName} ingest (${sigCheck.mode}).`,
      });

      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'blocked',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Ingest blocked due to signature verification failure on ${connection.appName}.`,
      });

      return Response.json(
        {
          success: false,
          message: sigCheck.reason || 'HMAC signature verification failed.',
        },
        { status: 401 }
      );
    }

    // 7. Parse JSON payload safely & sanitize fields
    let parsedBody: any;
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'failed',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Malformed JSON rejected on ${connection.appName} ingest.`,
      });
      return Response.json(
        { success: false, message: 'Payload must be valid JSON.' },
        { status: 400 }
      );
    }

    if (!parsedBody || typeof parsedBody !== 'object') {
      return Response.json(
        { success: false, message: 'JSON body must be an object.' },
        { status: 400 }
      );
    }

    const normalized = extractNormalizedContent(parsedBody, connection.appName);
    if (!normalized.rawText) {
      logSecurityEvent({
        eventType: 'INGEST_REJECTED',
        severity: 'warning',
        result: 'failed',
        userId: connection.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Missing notification message text on ${connection.appName} ingest.`,
      });
      return Response.json(
        {
          success: false,
          message: 'Payload must contain a non-empty message, text, or rawText field.',
        },
        { status: 400 }
      );
    }

    // 8. Priority classification (Dynamic Sigmoid Priority Engine) & Zero-Trust Ed25519 + AES-256-GCM encryption
    const classification = classifyIngestedPriority(normalized.rawText, normalized.priorityHint);
    const hasSocket = hasActiveSocketPresence(connection.userId);
    const userModelState = getUserPriorityModelState(connection.userId);
    const textAnalysis = computeTextImportanceScore(
      normalized.rawText,
      userModelState.urgentKeywords
    );
    const sourceKey = connection.appId || 'webhook';
    const priorityFeatures = extractFeaturesFromContent({
      plaintextInMemory: normalized.rawText,
      precomputedTextScore: textAnalysis.textScore,
      category: textAnalysis.detectedCategory,
      source: sourceKey,
      provenanceTrustScore: 0.7, // HMAC-verified gateway connection
      sourceReliability: userModelState.sourceReliability[sourceKey] ?? 0.78,
      elapsedSeconds: 0,
      isAcked: false,
      repeatCount: 1,
      userAffinity: 0.65,
      senderClaimedPriority: normalized.priorityHint || classification.priority,
      urgentKeywords: userModelState.urgentKeywords,
      quietHours: userModelState.quietHours,
    });

    const priorityBreakdown = scoreForUser({
      userId: connection.userId,
      features: priorityFeatures,
      source: sourceKey,
      ruleContext: {
        isSecurityAlert: textAnalysis.detectedCategory === 'security',
        isProvenanceVerified: true,
        isPromo: textAnalysis.detectedCategory === 'promo',
        senderTrust: 0.7,
        source: sourceKey,
      },
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
    });

    const effectivePriority = toLegacyNotificationPriority(priorityBreakdown.label);

    const riskResult = await calculateDispatchWeight({
      userId: connection.userId,
      priority: effectivePriority,
      riskScore: Math.max(classification.riskScore, priorityBreakdown.p),
      hasActiveSocket: hasSocket,
    });

    const finalDispatchScore = Number(
      Math.max(riskResult.dispatchWeight, priorityBreakdown.p).toFixed(4)
    );

    const notificationId = `notif_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const gatewayEnvelope = await createServerAttestedEnvelope({
      messageId: notificationId,
      senderId: connection.appId || 'connection-gateway',
      recipientId: connection.userId,
      source: sourceKey,
      priority: effectivePriority,
      ciphertextOrDigestInput: normalized.rawText,
      role: 'GATEWAY',
      textScore: textAnalysis.textScore,
      signedPriorityLabel: priorityBreakdown.label,
    });

    const enrichedMetadata = {
      appId: connection.appId,
      appName: connection.appName,
      connectionId: connection.id,
      connectionLabel: connection.label,
      title: normalized.title,
      simulated: Boolean(parsedBody.simulated),
      priorityEngine: priorityBreakdown,
    };

    const { sanitizedPayload } = await processEphemeralSecurityData(notificationId, {
      notificationId,
      userId: connection.userId,
      eventType: normalized.eventType,
      rawText: normalized.rawText,
      dispatchScore: finalDispatchScore,
      priority: effectivePriority,
      metadata: enrichedMetadata,
    });

    const { privateKey } = getServerKeyPair();
    const signature = signPayload(
      {
        notificationId,
        userId: connection.userId,
        eventType: normalized.eventType,
        rawText: normalized.rawText,
        dispatchScore: finalDispatchScore,
        createdAt: new Date().toISOString(),
      },
      privateKey
    );

    const encryptedPayload = encryptSecret(
      JSON.stringify({
        appId: connection.appId,
        appName: connection.appName,
        title: normalized.title,
        rawText: normalized.rawText,
      })
    );

    const newLogData = {
      _id: notificationId,
      userId: connection.userId,
      eventType: normalized.eventType,
      rawText: normalized.rawText,
      dispatchScore: finalDispatchScore,
      priority: effectivePriority,
      status: 'QUEUED' as const,
      signature,
      encryptedPayload,
      channelsUsed: [],
      metadata: enrichedMetadata,
      provenanceEnvelope: gatewayEnvelope,
      createdAt: new Date(),
    };

    if (!connection.isTestConnection) {
      try {
        const mongooseConn = await connectToDatabase();
        if (mongooseConn) {
          await NotificationLog.create(newLogData);
        } else {
          inMemoryNotificationLogs.unshift(newLogData as any);
        }
      } catch {
        inMemoryNotificationLogs.unshift(newLogData as any);
      }

      const queue = getNotificationQueue();
      await queue.add('dispatch-primary', {
        notificationId,
        userId: connection.userId,
        eventType: normalized.eventType,
        rawText: normalized.rawText,
        dispatchScore: finalDispatchScore,
        priority: effectivePriority,
        signature,
        sanitizedPayload,
        metadata: enrichedMetadata,
        provenanceEnvelope: gatewayEnvelope,
        priorityEngine: priorityBreakdown,
        channelsUsed: [],
      });
    }

    incrementConnectionReceived(connection.id);

    logSecurityEvent({
      eventType: 'INGEST_ACCEPTED',
      severity: 'info',
      result: 'success',
      userId: connection.userId,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Accepted signed ${connection.appName} notification (${notificationId}, priority=${priorityBreakdown.label}, p=${priorityBreakdown.p}).`,
    });

    return Response.json(
      {
        success: true,
        message: 'Notification verified, encrypted, and queued for delivery.',
        data: {
          notificationId,
          appId: connection.appId,
          appName: connection.appName,
          priority: priorityBreakdown.label,
          dispatchScore: finalDispatchScore,
          priorityEngine: priorityBreakdown,
          status: 'QUEUED',
        },
      },
      { status: 202 }
    );
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failed to process ingest payload.',
      },
      { status: 500 }
    );
  }
}
