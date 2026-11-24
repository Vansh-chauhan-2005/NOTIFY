import { z } from 'zod';
import {
  getQuarantinedAlerts,
  addQuarantinedAlert,
  updateQuarantinedAlertStatus,
  deleteQuarantinedAlerts,
  type QuarantinedAlert,
} from '../../../../../lib/quarantine/store.js';
import {
  runSmsBruteForceSimulation,
  runSmsSendFloodSimulation,
} from '../../../../../lib/integrations/smsService.js';
import {
  getOrCreateSimulatorTestConnection,
  computeHmacSignature,
} from '../../../../../lib/integrations/connectionsStore.js';
import { POST as ingestConnectionPost } from '../../ingest/[connectionId]/route.js';
import { logSecurityEvent, extractRequestContext } from '../../../../../lib/telemetry/securityLogger.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

const BulkDeleteQuarantineSchema = z.object({
  alertIds: z
    .array(z.string().trim().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/))
    .min(1, 'Select at least one quarantined item to delete.')
    .max(200, 'Cannot delete more than 200 quarantined items in one batch.'),
});

function buildQuarantineSummary(alerts: QuarantinedAlert[]) {
  return {
    total: alerts.length,
    flagged: alerts.filter((a) => a.status === 'FLAGGED').length,
    blocked: alerts.filter((a) => a.status === 'BLOCKED').length,
    dismissed: alerts.filter((a) => a.status === 'DISMISSED').length,
    byRisk: {
      CRITICAL: alerts.filter((a) => a.riskLevel === 'CRITICAL').length,
      HIGH: alerts.filter((a) => a.riskLevel === 'HIGH').length,
      MEDIUM: alerts.filter((a) => a.riskLevel === 'MEDIUM').length,
      LOW: alerts.filter((a) => a.riskLevel === 'LOW').length,
    },
  };
}

function executeBulkDelete(
  request: Request,
  adminUserId: string,
  adminEmail: string | undefined,
  rawIds: unknown
): Response {
  const parsed = BulkDeleteQuarantineSchema.safeParse({ alertIds: rawIds });
  if (!parsed.success) {
    return Response.json(
      {
        success: false,
        message: parsed.error.issues[0]?.message || 'Invalid alertIds array for bulk delete.',
      },
      { status: 400 }
    );
  }

  const { deletedIds, remaining } = deleteQuarantinedAlerts(parsed.data.alertIds);
  const summary = buildQuarantineSummary(remaining);
  const reqCtx = extractRequestContext(request);

  if (deletedIds.length > 0) {
    logSecurityEvent({
      eventType: 'QUARANTINE_BULK_DELETED',
      severity: 'info',
      result: 'success',
      userId: adminUserId,
      email: adminEmail,
      ipAddress: reqCtx.ipAddress,
      userAgent: reqCtx.userAgent,
      details: `Bulk deleted ${deletedIds.length} item(s) from Security Quarantine Log.`,
    });
  }

  return Response.json({
    success: true,
    message:
      deletedIds.length > 0
        ? `Removed ${deletedIds.length} quarantined item(s) from the security log.`
        : 'No matching quarantined items were found.',
    deletedCount: deletedIds.length,
    deletedIds,
    summary,
    alerts: remaining,
    data: {
      deletedCount: deletedIds.length,
      deletedIds,
      summary,
      alerts: remaining,
    },
  });
}

export async function GET(request: Request) {
  const auth = requireAdminRequest(request);
  if (!auth.ok) {
    return auth.response!;
  }
  const alerts = getQuarantinedAlerts();
  const summary = buildQuarantineSummary(alerts);

  return Response.json({
    success: true,
    summary,
    alerts,
  });
}

export async function POST(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return Response.json(
        { success: false, message: 'Request body must be valid JSON.' },
        { status: 400 }
      );
    }

    const { action, alertId, alertIds, newStatus, simulationType } = body;

    if (action === 'BULK_DELETE') {
      return executeBulkDelete(
        request,
        auth.user?.userId || 'admin',
        auth.user?.email,
        alertIds
      );
    }

    if (action === 'UPDATE_STATUS' && alertId && newStatus) {
      const updated = updateQuarantinedAlertStatus(alertId, newStatus);
      if (!updated) {
        return Response.json({ success: false, message: 'Quarantine alert not found' }, { status: 404 });
      }
      return Response.json({ success: true, alert: updated });
    }

    if (action === 'SIMULATE') {
      const reqCtx = extractRequestContext(request);

      if (simulationType === 'SMS_BRUTE_FORCE') {
        const sim = await runSmsBruteForceSimulation({
          ipAddress: '198.51.100.91',
          userAgent: 'Aegis-Attack-Simulator/1.0',
        });
        const created = addQuarantinedAlert({
          reason: 'RATE_LIMIT_EXCEEDED',
          reasonLabel: 'SMS OTP Brute Force Blocked',
          description: `Simulated ${sim.totalAttempts} wrong SMS codes against mock account ${sim.targetMasked}; locked after 5 failed attempts (HTTP ${sim.finalStatus}).`,
          sourceIp: '198.51.100.91',
          sourceApp: 'Attack Simulator (Mock SMS)',
          riskLevel: 'CRITICAL',
          rawPayload: sim,
        });
        return Response.json({
          success: true,
          message: sim.lockedTriggered
            ? `SMS Brute Force blocked: locked out after 5 wrong attempts on ${sim.targetMasked}.`
            : 'SMS Brute Force simulation completed.',
          alert: created,
          simulationResult: sim,
        });
      }

      if (simulationType === 'SMS_SEND_FLOOD') {
        const sim = await runSmsSendFloodSimulation({
          ipAddress: '198.51.100.92',
          userAgent: 'Aegis-Attack-Simulator/1.0',
        });
        const created = addQuarantinedAlert({
          reason: 'RATE_LIMIT_EXCEEDED',
          reasonLabel: 'SMS Send Flood Blocked (429 Cooldown)',
          description: `Simulated rapid SMS send burst against mock account ${sim.targetMasked}; cooldown enforced HTTP 429 (${sim.cooldownSeconds}s wait).`,
          sourceIp: '198.51.100.92',
          sourceApp: 'Attack Simulator (Mock SMS)',
          riskLevel: 'HIGH',
          rawPayload: sim,
        });
        return Response.json({
          success: true,
          message: sim.floodBlocked
            ? `SMS Send Flood blocked: 429 cooldown triggered on ${sim.targetMasked} (${sim.cooldownSeconds}s wait).`
            : 'SMS Send Flood simulation completed.',
          alert: created,
          simulationResult: sim,
        });
      }

      if (simulationType === 'INGEST_FORGED_SIGNATURE') {
        const { record } = getOrCreateSimulatorTestConnection();
        const ts = String(Date.now());
        const bodyStr = JSON.stringify({
          title: 'Simulated Webhook Probe',
          message: 'Unauthorized ingest signature test payload.',
          simulated: true,
        });

        const simReq = new Request(
          `http://localhost:3000/api/v1/ingest/${record.id}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Aegis-Timestamp': ts,
              'X-Aegis-Signature': 'sha256=000000000000000000000000000000000000000000000000000000000000dead',
              'x-forwarded-for': '198.51.100.93',
              'user-agent': 'Aegis-Attack-Simulator/1.0',
            },
            body: bodyStr,
          }
        );

        const res = await ingestConnectionPost(simReq, { params: { connectionId: record.id } });
        const payload = await res.json().catch(() => ({}));
        const rejected = res.status === 401;

        return Response.json({
          success: true,
          message: rejected
            ? 'Forged ingest signature rejected (HTTP 401) and quarantined.'
            : `Simulation returned HTTP ${res.status}.`,
          simulationResult: {
            rejected,
            status: res.status,
            connectionId: record.id,
            detail: payload?.message || 'Signature mismatch',
          },
        });
      }

      if (simulationType === 'INGEST_REPLAY_TIMESTAMP') {
        const { record, signingSecret } = getOrCreateSimulatorTestConnection();
        const staleTs = String(Date.now() - 10 * 60 * 1000); // 10 minutes old
        const bodyStr = JSON.stringify({
          title: 'Simulated Replay Probe',
          message: 'Captured webhook payload replayed outside 5-minute window.',
          simulated: true,
        });
        const validSigForStaleTs = computeHmacSignature(signingSecret, staleTs, bodyStr);

        const simReq = new Request(
          `http://localhost:3000/api/v1/ingest/${record.id}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Aegis-Timestamp': staleTs,
              'X-Aegis-Signature': `sha256=${validSigForStaleTs}`,
              'x-forwarded-for': '198.51.100.94',
              'user-agent': 'Aegis-Attack-Simulator/1.0',
            },
            body: bodyStr,
          }
        );

        const res = await ingestConnectionPost(simReq, { params: { connectionId: record.id } });
        const payload = await res.json().catch(() => ({}));
        const rejected = res.status === 401;

        return Response.json({
          success: true,
          message: rejected
            ? 'Replayed 10-minute-old timestamp rejected (HTTP 401) and quarantined.'
            : `Simulation returned HTTP ${res.status}.`,
          simulationResult: {
            rejected,
            status: res.status,
            connectionId: record.id,
            detail: payload?.message || 'Replay window expired',
          },
        });
      }

      const simulationTypes = [
        {
          reason: 'INVALID_SIGNATURE' as const,
          reasonLabel: 'Forged Cryptographic Signature',
          description: 'Incoming payload claiming to be [Urgent Slack DM] arrived with an unrecognized or tampered Ed25519 signature.',
          sourceIp: '198.51.100.72 (Untrusted Relay)',
          sourceApp: 'Forged Slack Webhook',
          riskLevel: 'CRITICAL' as const,
          rawPayload: {
            text: 'System access compromised. Click here to reset your MFA token immediately.',
            sender: 'security-admin-bot',
            badSignature: '99e3a01bcf...',
          },
        },
        {
          reason: 'MISSING_AUTH_HEADER' as const,
          reasonLabel: 'Missing API Key Authentication',
          description: 'HTTP request attempted to dispatch notification to /api/v1/notifications/ingest without an API key or bearer token.',
          sourceIp: '203.0.113.14',
          sourceApp: 'Anonymous Ingress Probe',
          riskLevel: 'HIGH' as const,
          rawPayload: {
            eventType: 'UNKNOWN_TRIGGER',
            rawText: 'Direct unauthenticated socket trigger test',
          },
        },
        {
          reason: 'MISCELLANEOUS_ANOMALY' as const,
          reasonLabel: 'Miscellaneous Malformed Event',
          description: 'Received binary payload with corrupt header fields and unregistered event parameters.',
          sourceIp: '192.0.2.88',
          sourceApp: 'Legacy Proxy Relay',
          riskLevel: 'MEDIUM' as const,
          rawPayload: {
            raw_bytes: '0xDEADBEEF4412',
            malformed_event_type: '???',
          },
        },
      ];

      const sample = simulationTypes[Math.floor(Math.random() * simulationTypes.length)];
      const created = addQuarantinedAlert(sample);

      logSecurityEvent({
        eventType:
          sample.reason === 'MISCELLANEOUS_ANOMALY'
            ? 'MESSAGE_DECRYPT_FAILED'
            : 'SIGNATURE_INVALID',
        severity: sample.riskLevel === 'CRITICAL' ? 'critical' : 'warning',
        result: 'blocked',
        ipAddress: sample.sourceIp || reqCtx.ipAddress,
        userAgent: reqCtx.userAgent,
        details: `Quarantined ${sample.reasonLabel} from ${sample.sourceApp}.`,
      });

      return Response.json({
        success: true,
        message: 'Simulated unauthenticated alert logged to quarantine successfully',
        alert: created,
      });
    }

    return Response.json({ success: false, message: 'Invalid action parameter' }, { status: 400 });
  } catch (err: any) {
    return Response.json(
      { success: false, message: err?.message || 'Failed to process quarantine request' },
      { status: 500 }
    );
  }
}

export async function DELETE(request: Request) {
  try {
    const auth = requireAdminRequest(request);
    if (!auth.ok) {
      return auth.response!;
    }
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return Response.json(
        { success: false, message: 'Request body must be valid JSON containing alertIds.' },
        { status: 400 }
      );
    }

    return executeBulkDelete(
      request,
      auth.user?.userId || 'admin',
      auth.user?.email,
      (body as Record<string, unknown>).alertIds
    );
  } catch (err: any) {
    return Response.json(
      { success: false, message: err?.message || 'Failed to bulk delete quarantined alerts.' },
      { status: 500 }
    );
  }
}
