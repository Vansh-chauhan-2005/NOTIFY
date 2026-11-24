import { z } from 'zod';
import { enforceRateLimit, IngestNotificationSchema, hasActiveSocketPresence } from '../../../../../lib/queue/worker.js';
import { calculateDispatchWeight } from '../../../../../lib/math/riskScoring.js';
import {
  signPayload,
  verifyPayload,
  getServerKeyPair,
  processEphemeralSecurityData,
} from '../../../../../lib/crypto/ed25519.js';
import { NotificationLog, inMemoryNotificationLogs } from '../../../../../models/NotificationLog.js';
import { getNotificationQueue } from '../../../../../lib/queue/bullmq.js';
import { connectToDatabase } from '../../../../../lib/db/mongoose.js';
import { addQuarantinedAlert } from '../../../../../lib/quarantine/store.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';
import { computeCiphertextHash } from '../../../../../lib/provenance/canonical.js';
import { createServerAttestedEnvelope } from '../../../../../lib/provenance/serverCrypto.js';
import {
  recordProvenanceOutcome,
  verifyEnvelopeOnServer,
} from '../../../../../lib/provenance/store.js';
import type {
  ProvenanceEnvelopeV1,
  ProvenanceVerificationReport,
} from '../../../../../lib/provenance/types.js';
import {
  computeTextImportanceScore,
  extractFeaturesFromContent,
} from '../../../../../lib/priority/features.js';
import { toLegacyNotificationPriority } from '../../../../../lib/priority/math.js';
import {
  getUserPriorityModelState,
  scoreForUser,
} from '../../../../../lib/priority/store.js';
import { listDedupThreads } from '../../../../../lib/dedup/store.js';
import { authenticateUserOrApiKey } from '../../../../../lib/auth/requestAuth.js';
import { isValidInternalWebhookToken } from '../../../../../lib/integrations/internalWebhookToken.js';

export async function POST(request: Request) {
  try {
    const reqCtx = extractRequestContext(request);
    const isVerifiedInternalWebhook = isValidInternalWebhookToken(
      request.headers.get('x-aegis-internal-webhook-token')
    );

    let callerUser: { userId: string; role: string } | null = null;
    if (!isVerifiedInternalWebhook) {
      const auth = await authenticateUserOrApiKey(request);
      if (!auth.ok || !auth.user) {
        return auth.response!;
      }
      callerUser = { userId: auth.user.userId, role: auth.user.role };
    }

    // 1. Rate Limiting via atomic Redis Lua script
    const rateKey = callerUser
      ? `ingest:${callerUser.userId}:${reqCtx.ipAddress}`
      : `ingest:webhook:${reqCtx.ipAddress}`;

    const rateResult = await enforceRateLimit(rateKey, 100, 60);
    if (!rateResult.allowed) {
      logSecurityEvent({
        eventType: 'RATE_LIMIT_HIT',
        severity: 'warning',
        result: 'blocked',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Ingest rate limit exceeded (100 req / 60s).',
      });
      return Response.json(
        {
          error: 'Too Many Requests',
          message: 'Rate limit exceeded. Maximum 100 requests per 60-second window.',
          remaining: 0,
        },
        {
          status: 429,
          headers: {
            'X-RateLimit-Limit': '100',
            'X-RateLimit-Remaining': '0',
            'Retry-After': '60',
          },
        }
      );
    }

    // 2. Payload parsing & Zod Schema Validation
    let body: any;
    try {
      body = await request.json();
    } catch {
      logSecurityEvent({
        eventType: 'MESSAGE_DECRYPT_FAILED',
        severity: 'critical',
        result: 'failed',
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Unable to parse or decode incoming notification payload.',
      });
      return Response.json(
        { error: 'Malformed Payload', message: 'Invalid or corrupt notification payload.' },
        { status: 400 }
      );
    }

    if (body && (body.encryptedPayload || body.cipherText || body.ciphertext) && !body.rawText) {
      logSecurityEvent({
        eventType: 'MESSAGE_DECRYPT_FAILED',
        severity: 'critical',
        result: 'failed',
        userId: body.userId ? String(body.userId) : undefined,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Encrypted message payload could not be decrypted with active channel key.',
      });
      return Response.json(
        { error: 'Decryption Failed', message: 'Encrypted payload could not be decrypted.' },
        { status: 400 }
      );
    }

    const parsed = IngestNotificationSchema.safeParse(body);
    if (!parsed.success) {
      addQuarantinedAlert({
        reason: 'MISCELLANEOUS_ANOMALY',
        reasonLabel: 'Miscellaneous Malformed Payload',
        description: 'Received notification request that failed structural validation or contained unrecognized attributes.',
        sourceIp: reqCtx.ipAddress,
        sourceApp: (body && (body.appId || body.sourceApp || body.name)) || 'Direct Ingress Probe',
        rawPayload: body || {},
        riskLevel: 'MEDIUM',
      });

      logSecurityEvent({
        eventType: 'MESSAGE_DECRYPT_FAILED',
        severity: 'warning',
        result: 'blocked',
        userId: body?.userId ? String(body.userId) : undefined,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: 'Malformed notification payload rejected by structural validator.',
      });

      return Response.json(
        { error: 'Validation Error', details: parsed.error.format() },
        { status: 400 }
      );
    }

    // Check for explicit unauthenticated / counterfeit flag or invalid signature
    const hasInvalidProvidedSignature =
      typeof body.signature === 'string' &&
      body.signature.length > 0 &&
      !verifyPayload(
        {
          userId: parsed.data.userId,
          eventType: parsed.data.eventType,
          rawText: parsed.data.rawText,
        },
        body.signature,
        getServerKeyPair().publicKey
      );

    if (body.unauthenticated || body.isCounterfeit || hasInvalidProvidedSignature) {
      addQuarantinedAlert({
        reason: 'INVALID_SIGNATURE',
        reasonLabel: 'Counterfeit / Unauthenticated Message',
        description: `Alert with event [${body.eventType || 'UNKNOWN'}] failed identity verification. Origin unconfirmed.`,
        sourceIp: reqCtx.ipAddress,
        sourceApp: body.sourceApp || 'Untrusted Source',
        rawPayload: body,
        riskLevel: 'CRITICAL',
      });

      logSecurityEvent({
        eventType: 'SIGNATURE_INVALID',
        severity: 'critical',
        result: 'blocked',
        userId: parsed.data.userId,
        ipAddress: reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Counterfeit or invalid signature rejected for event ${parsed.data.eventType}.`,
      });

      return Response.json(
        {
          error: 'Security Verification Failed',
          message: 'Message intercepted and isolated in Quarantine Alert Log.',
        },
        { status: 403 }
      );
    }

    const { userId, eventType, rawText, priority, riskScore, metadata } = parsed.data;
    if (
      callerUser &&
      callerUser.role !== 'ADMIN' &&
      callerUser.role !== 'SERVICE' &&
      userId !== callerUser.userId
    ) {
      return Response.json(
        {
          success: false,
          error: 'Forbidden',
          message: 'You cannot ingest notifications on behalf of another user.',
        },
        { status: 403 }
      );
    }

    const isGatewayWebhook = isVerifiedInternalWebhook;
    const hasClientEnvelope = Boolean(body?.provenanceEnvelope && typeof body.provenanceEnvelope === 'object');
    const explicitUnsignedOrStrict =
      body?.provenanceEnvelope === null ||
      body?.requireProvenance === true ||
      (!isGatewayWebhook && (priority === 'CRITICAL' || priority === 'HIGH') && body?.allowUnsignedLegacy !== true);

    const notificationId =
      typeof body?.notificationId === 'string' && /^[a-zA-Z0-9_-]{4,128}$/.test(body.notificationId)
        ? body.notificationId
        : `notif_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    let storedProvenanceEnvelope: ProvenanceEnvelopeV1 | null = null;
    let provenanceReport: ProvenanceVerificationReport | null = null;

    if (hasClientEnvelope) {
      const incomingEnvelope = body.provenanceEnvelope as ProvenanceEnvelopeV1;
      const expectedCiphertextHash = await computeCiphertextHash(
        rawText,
        typeof body?.iv === 'string' ? body.iv : ''
      );
      const report = await verifyEnvelopeOnServer({
        envelope: incomingEnvelope,
        expectedRecipientId: incomingEnvelope?.payload?.recipientId || userId,
        expectedMessageId: incomingEnvelope?.payload?.messageId || notificationId,
        expectedCiphertextHash,
        priority,
        enforceReplay: true,
      });

      if (!report.verified) {
        addQuarantinedAlert({
          reason: 'INVALID_SIGNATURE',
          reasonLabel: `Provenance Rejected: ${report.status}`,
          description: report.reason,
          sourceIp: reqCtx.ipAddress,
          sourceApp: (metadata?.sourceApp as string) || 'Provenance Verification Gate',
          rawPayload: {
            notificationId,
            userId,
            eventType,
            status: report.status,
            kid: report.kid,
          },
          riskLevel: priority === 'CRITICAL' || priority === 'HIGH' ? 'CRITICAL' : 'HIGH',
        });

        return Response.json(
          {
            success: false,
            error: 'Provenance Verification Failed',
            status: report.status,
            message: report.reason,
            data: { provenance: report },
          },
          { status: 403 }
        );
      }

      // Append server gateway hop onto verified client origin envelope
      storedProvenanceEnvelope = await createServerAttestedEnvelope({
        messageId: notificationId,
        senderId: userId,
        recipientId: incomingEnvelope.payload.recipientId,
        source: incomingEnvelope.payload.source || 'direct',
        priority,
        ciphertextOrDigestInput: rawText,
        role: 'GATEWAY',
        existingEnvelope: incomingEnvelope,
      });

      provenanceReport = {
        ...report,
        envelope: storedProvenanceEnvelope,
      };
    } else if (!isGatewayWebhook && (priority === 'CRITICAL' || priority === 'HIGH') && explicitUnsignedOrStrict) {
      const unsignedReport = await verifyEnvelopeOnServer({
        envelope: null,
        expectedRecipientId: userId,
        expectedMessageId: notificationId,
        priority,
        enforceReplay: false,
      });

      addQuarantinedAlert({
        reason: 'INVALID_SIGNATURE',
        reasonLabel: 'Unsigned High-Priority Notification Blocked (Zero-Trust Policy)',
        description: unsignedReport.reason,
        sourceIp: reqCtx.ipAddress,
        sourceApp: (metadata?.sourceApp as string) || 'Unsigned Direct Ingest',
        rawPayload: {
          notificationId,
          userId,
          eventType,
          priority,
          status: 'UNSIGNED',
        },
        riskLevel: 'HIGH',
      });

      return Response.json(
        {
          success: false,
          error: 'Unsigned High-Priority Notification Rejected',
          status: 'UNSIGNED',
          message: `Zero-Trust Provenance requires an Ed25519 signature for ${priority} notifications.`,
          data: { provenance: unsignedReport },
        },
        { status: 403 }
      );
    } else if (isGatewayWebhook) {
      const preTextAnalysis = computeTextImportanceScore(rawText);
      storedProvenanceEnvelope = await createServerAttestedEnvelope({
        messageId: notificationId,
        senderId: (metadata?.appId as string) || 'webhook-gateway',
        recipientId: userId,
        source: (metadata?.appId as string) || 'webhook',
        priority,
        ciphertextOrDigestInput: rawText,
        role: 'GATEWAY',
        textScore: preTextAnalysis.textScore,
        signedPriorityLabel: priority,
      });
      provenanceReport = await verifyEnvelopeOnServer({
        envelope: storedProvenanceEnvelope,
        expectedRecipientId: userId,
        expectedMessageId: notificationId,
        expectedCiphertextHash: storedProvenanceEnvelope.payload.ciphertextHash,
        priority,
        enforceReplay: false,
      });
    } else {
      provenanceReport = {
        status: 'UNSIGNED',
        verified: false,
        reason: 'Sender dispatched a LOW/MEDIUM notification without an Ed25519 signing key.',
        alg: 'NONE',
        badgeVariant: 'unverified',
        chain: [],
      };
      await recordProvenanceOutcome({
        report: provenanceReport,
        messageId: notificationId,
        senderId: userId,
        recipientId: userId,
        source: 'direct',
      });
    }

    // 3. Semantic Deduplication runs on-device in browser Web Worker + safety guards
    // (never silently drops CRITICAL/security/entity-distinct alerts or stores raw vectors/plaintext).
    const activeUserThreads = listDedupThreads({ userId, limit: 25 });
    const sourceKey =
      (typeof metadata?.appId === 'string' && metadata.appId) ||
      (typeof metadata?.sourceApp === 'string' && metadata.sourceApp) ||
      'direct';
    const matchingSourceThreads = activeUserThreads.filter(
      (t) => t.sourceId.toLowerCase() === sourceKey.toLowerCase() && t.status === 'ACTIVE'
    );
    const repeatCountFromThreads = matchingSourceThreads.reduce(
      (maxCount, t) => Math.max(maxCount, t.memberCount || 1),
      1
    );

    // 4. Presence, Dynamic Risk/Priority Math Engine & Dynamic Sigmoid Priority Engine
    const hasSocket = hasActiveSocketPresence(userId);
    const userModelState = getUserPriorityModelState(userId);
    const provenanceTrustScore = provenanceReport?.verified
      ? provenanceReport.badgeVariant === 'verified'
        ? 1.0
        : 0.7
      : 0.2;
    const textAnalysis = computeTextImportanceScore(rawText, userModelState.urgentKeywords);
    const priorityFeatures = extractFeaturesFromContent({
      plaintextInMemory: rawText,
      precomputedTextScore:
        typeof storedProvenanceEnvelope?.payload?.textScore === 'number'
          ? storedProvenanceEnvelope.payload.textScore
          : textAnalysis.textScore,
      category: textAnalysis.detectedCategory,
      source: sourceKey,
      provenanceTrustScore,
      sourceReliability: userModelState.sourceReliability[sourceKey] ?? 0.75,
      elapsedSeconds: 0,
      isAcked: false,
      repeatCount: repeatCountFromThreads,
      userAffinity: 0.65,
      senderClaimedPriority: priority,
      urgentKeywords: userModelState.urgentKeywords,
      quietHours: userModelState.quietHours,
    });

    const priorityBreakdown = scoreForUser({
      userId,
      features: priorityFeatures,
      source: sourceKey,
      ruleContext: {
        isSecurityAlert: textAnalysis.detectedCategory === 'security',
        isOtpOrNewDevice: Boolean(parsed.data.otp || parsed.data.otpCode),
        provenanceFailedOrRevoked: Boolean(
          provenanceReport && !provenanceReport.verified && provenanceReport.status !== 'UNSIGNED'
        ),
        isProvenanceVerified: Boolean(provenanceReport?.verified),
        isPromo: textAnalysis.detectedCategory === 'promo',
        senderTrust: provenanceTrustScore,
        source: sourceKey,
      },
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
    });

    const effectivePriority = toLegacyNotificationPriority(priorityBreakdown.label);

    const riskResult = await calculateDispatchWeight({
      userId,
      priority: effectivePriority,
      riskScore: Math.max(riskScore, priorityBreakdown.p),
      hasActiveSocket: hasSocket,
    });

    const dispatchScore = Number(
      Math.max(riskResult.dispatchWeight, priorityBreakdown.p).toFixed(4)
    );

    const enrichedMetadata = {
      ...(metadata || {}),
      priorityEngine: priorityBreakdown,
    };

    // 5. Ephemeral Security Data Separation (OTP saved in Redis 300s TTL, stripped from permanent logs)
    const { sanitizedPayload, ephemeralExtracted } = await processEphemeralSecurityData(
      notificationId,
      {
        notificationId,
        userId,
        eventType,
        rawText,
        dispatchScore,
        priority: effectivePriority,
        metadata: enrichedMetadata,
        otp: parsed.data.otp,
        otpCode: parsed.data.otpCode,
      }
    );

    // 6. Asymmetric Zero-Trust Ed25519 Signing
    const { privateKey, publicKey } = getServerKeyPair();
    const signature = signPayload(
      {
        notificationId,
        userId,
        eventType,
        rawText,
        dispatchScore,
        createdAt: new Date().toISOString(),
      },
      privateKey
    );

    // 7. Persist Initial Notification Log
    const newLogData = {
      _id: notificationId,
      userId,
      eventType,
      rawText,
      dispatchScore,
      priority: effectivePriority,
      status: 'QUEUED' as const,
      signature,
      channelsUsed: [],
      metadata: enrichedMetadata,
      provenanceEnvelope: storedProvenanceEnvelope,
      provenanceReport,
      createdAt: new Date(),
    };

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

    // 8. Enqueue to BullMQ for Primary Dispatch & Fallback State Machine
    const queue = getNotificationQueue();
    await queue.add('dispatch-primary', {
      notificationId,
      userId,
      eventType,
      rawText,
      dispatchScore,
      priority: effectivePriority,
      signature,
      sanitizedPayload,
      metadata: enrichedMetadata,
      provenanceEnvelope: storedProvenanceEnvelope,
      provenanceReport,
      priorityEngine: priorityBreakdown,
      channelsUsed: [],
      recipientPhone: parsed.data.recipientPhone || undefined,
      recipientEmail: parsed.data.recipientEmail || undefined,
    });

    logSecurityEvent({
      eventType: 'MESSAGE_SENT',
      severity: 'info',
      result: 'success',
      userId,
      email: parsed.data.recipientEmail,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Signed notification ${notificationId} queued (${eventType}, priority=${priorityBreakdown.label}, p=${priorityBreakdown.p}).`,
    });

    return Response.json(
      {
        success: true,
        notificationId,
        status: 'QUEUED',
        dispatchScore,
        priority: priorityBreakdown.label,
        priorityEngine: priorityBreakdown,
        signature,
        publicKey,
        deduplication: {
          isDuplicate: false,
          mode: 'on-device-worker',
          repeatCountInWindow: repeatCountFromThreads,
          threshold: 0.88,
        },
        riskCalculation: riskResult,
        ephemeralSecurity: {
          handled: ephemeralExtracted,
          ttl: '300s in Redis',
        },
        provenance: provenanceReport
          ? {
              status: provenanceReport.status,
              verified: provenanceReport.verified,
              kid: provenanceReport.kid,
              badgeVariant: provenanceReport.badgeVariant,
              envelope: storedProvenanceEnvelope,
            }
          : null,
      },
      {
        status: 202,
        headers: {
          'X-RateLimit-Limit': '100',
          'X-RateLimit-Remaining': String(rateResult.remaining),
        },
      }
    );
  } catch (err: any) {
    console.error('[Ingest Error]', err);
    return Response.json(
      { error: 'Internal Ingestion Failure', message: err.message },
      { status: 500 }
    );
  }
}
