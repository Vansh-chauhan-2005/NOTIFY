import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'crypto';
import { mintSessionToken } from '../node_auth.js';
import { getServerKeyPair, signPayload, verifyPayload } from '../../crypto/ed25519.js';
import { escapeHtml, buildFallbackAlertEmailHtml } from '../../integrations/emailService.js';
import { extractRequestContext } from '../../telemetry/securityLogger.js';
import { inMemoryUsers } from '../../../models/User.js';
import { inMemoryNotificationLogs } from '../../../models/NotificationLog.js';

import { POST as registerPost } from '../../../app/api/v1/auth/register/route.js';
import { GET as apiKeysGet, POST as apiKeysPost } from '../../../app/api/v1/auth/api-keys/route.js';
import { GET as otpAuditGet } from '../../../app/api/v1/auth/otp/audit/route.js';
import { POST as ingestPost } from '../../../app/api/v1/notifications/ingest/route.js';
import { GET as historyGet } from '../../../app/api/v1/notifications/history/route.js';
import { POST as ackPost } from '../../../app/api/v1/notifications/ack/[notificationId]/route.js';
import { PATCH as priorityPatch } from '../../../app/api/v1/notifications/priority/route.js';
import { GET as quarantineGet, POST as quarantinePost, DELETE as quarantineDelete } from '../../../app/api/v1/notifications/quarantine/route.js';
import { GET as streamGet } from '../../../app/api/v1/notifications/stream/route.js';
import { GET as prefsGet, PUT as prefsPut } from '../../../app/api/v1/users/preferences/route.js';
import { GET as pushGet, POST as pushPost } from '../../../app/api/v1/users/push-subscription/route.js';
import { GET as integrationsGet, POST as integrationsPost } from '../../../app/api/v1/integrations/route.js';
import { PUT as integrationsPut } from '../../../app/api/v1/integrations/[appId]/route.js';
import { POST as webhookPost } from '../../../app/api/v1/integrations/webhook/route.js';
import { POST as integrationsTestPost } from '../../../app/api/v1/integrations/test/route.js';
import { GET as metricsGet } from '../../../app/api/v1/analytics/metrics/route.js';
import { POST as chatPost } from '../../../app/api/v1/chat/route.js';
import { GET as targetPhoneGet, POST as targetPhonePost } from '../../../app/api/v1/notifications/fallback/target-phone/route.js';

function makeToken(userId: string, role: 'USER' | 'ADMIN' | 'SERVICE' = 'USER'): string {
  return mintSessionToken({ userId, role, email: `${userId}@example.com` }, '1h');
}

describe('Security Hardening & Regression Controls', () => {
  beforeEach(() => {
    inMemoryUsers.clear();
  });

  it('recovers cleanly from non-PEM AEGIS_PUBLIC_KEY / AEGIS_PRIVATE_KEY env values', () => {
    const prevPub = process.env.AEGIS_PUBLIC_KEY;
    const prevPriv = process.env.AEGIS_PRIVATE_KEY;
    try {
      process.env.AEGIS_PUBLIC_KEY = 'aegis_pk_64c9a0a634dbc4913146b3c883f0ae9503b12a6f7901068c';
      process.env.AEGIS_PRIVATE_KEY = 'aegis_sk_non_pem_value';
      const kp = getServerKeyPair();
      expect(kp.publicKey).toContain('BEGIN PUBLIC KEY');
      expect(kp.privateKey).toContain('BEGIN PRIVATE KEY');

      const sig = signPayload({ hello: 'world' }, kp.privateKey);
      expect(verifyPayload({ hello: 'world' }, sig, kp.publicKey)).toBe(true);
    } finally {
      if (prevPub === undefined) delete process.env.AEGIS_PUBLIC_KEY;
      else process.env.AEGIS_PUBLIC_KEY = prevPub;
      if (prevPriv === undefined) delete process.env.AEGIS_PRIVATE_KEY;
      else process.env.AEGIS_PRIVATE_KEY = prevPriv;
    }
  });

  it('prevents self-assigned ADMIN role during registration', async () => {
    const email = `reg_${crypto.randomBytes(4).toString('hex')}@example.com`;
    const res = await registerPost(
      new Request('http://localhost:3000/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password: 'StrongPassword!123',
          role: 'ADMIN',
        }),
      })
    );
    const body = await res.json();
    expect(res.status).toBe(201);
    expect(body.user.role).toBe('USER');
  });

  it('requires auth and enforces role/ownership caps on API keys', async () => {
    const unauth = await apiKeysPost(
      new Request('http://localhost:3000/api/v1/auth/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: 'victim', role: 'ADMIN' }),
      })
    );
    expect(unauth.status).toBe(401);

    const userToken = makeToken('usr_alice', 'USER');
    const escalate = await apiKeysPost(
      new Request('http://localhost:3000/api/v1/auth/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ role: 'ADMIN' }),
      })
    );
    expect(escalate.status).toBe(403);

    const createOwn = await apiKeysPost(
      new Request('http://localhost:3000/api/v1/auth/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ label: 'Alice Key' }),
      })
    );
    expect(createOwn.status).toBe(201);
    const createdJson = await createOwn.json();
    expect(createdJson.metadata.userId).toBe('usr_alice');
    expect(createdJson.metadata.role).toBe('USER');
    expect(createdJson.metadata.keyHash).toBeUndefined();

    const listOther = await apiKeysGet(
      new Request('http://localhost:3000/api/v1/auth/api-keys?userId=usr_bob', {
        headers: { Authorization: `Bearer ${userToken}` },
      })
    );
    expect(listOther.status).toBe(403);
  });

  it('restricts OTP audit logs strictly to ADMIN role', async () => {
    const unauth = await otpAuditGet(new Request('http://localhost:3000/api/v1/auth/otp/audit'));
    expect(unauth.status).toBe(401);

    const userRes = await otpAuditGet(
      new Request('http://localhost:3000/api/v1/auth/otp/audit', {
        headers: { Authorization: `Bearer ${makeToken('usr_bob', 'USER')}` },
      })
    );
    expect(userRes.status).toBe(403);

    const adminRes = await otpAuditGet(
      new Request('http://localhost:3000/api/v1/auth/otp/audit', {
        headers: { Authorization: `Bearer ${makeToken('usr_admin', 'ADMIN')}` },
      })
    );
    expect(adminRes.status).toBe(200);
  });

  it('blocks unauthenticated/forged/cross-user ingest and allows valid authenticated ingest', async () => {
    const unauth = await ingestPost(
      new Request('http://localhost:3000/api/v1/notifications/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': 'aegis-dashboard-master-key',
          'X-Aegis-Gateway-Webhook': '1',
        },
        body: JSON.stringify({
          userId: 'usr_victim',
          eventType: 'ALERT',
          rawText: 'Spoofed alert',
          priority: 'CRITICAL',
          riskScore: 0.9,
        }),
      })
    );
    expect(unauth.status).toBe(401);

    const userToken = makeToken('usr_alice', 'USER');
    const crossUser = await ingestPost(
      new Request('http://localhost:3000/api/v1/notifications/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          userId: 'usr_bob',
          eventType: 'ALERT',
          rawText: 'Cross-user inject',
          priority: 'LOW',
          riskScore: 0.2,
        }),
      })
    );
    expect(crossUser.status).toBe(403);

    // Forged X-Aegis-Gateway-Webhook cannot bypass Ed25519 CRITICAL provenance rule
    const forgedWebhookHeader = await ingestPost(
      new Request('http://localhost:3000/api/v1/notifications/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
          'X-Aegis-Gateway-Webhook': '1',
        },
        body: JSON.stringify({
          userId: 'usr_alice',
          eventType: 'CRITICAL_BYPASS',
          rawText: 'Trying to skip signature',
          priority: 'CRITICAL',
          riskScore: 0.95,
        }),
      })
    );
    expect(forgedWebhookHeader.status).toBe(403);

    const validOwn = await ingestPost(
      new Request('http://localhost:3000/api/v1/notifications/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({
          userId: 'usr_alice',
          eventType: 'INFO_TEST',
          rawText: 'Routine status check',
          priority: 'LOW',
          riskScore: 0.2,
        }),
      })
    );
    expect(validOwn.status).toBe(202);
  });

  it('enforces auth and ownership across history, ack, priority, quarantine, stream, metrics, chat, and user settings', async () => {
    const userA = makeToken('usr_alice', 'USER');
    const userB = makeToken('usr_bob', 'USER');
    const admin = makeToken('usr_admin', 'ADMIN');

    inMemoryNotificationLogs.unshift({
      _id: 'notif_alice_only',
      userId: 'usr_alice',
      eventType: 'INFO',
      rawText: 'Alice private notification',
      dispatchScore: 0.3,
      priority: 'LOW',
      status: 'QUEUED',
      signature: 'sig',
      channelsUsed: [],
      createdAt: new Date(),
    } as any);

    expect((await historyGet(new Request('http://localhost:3000/api/v1/notifications/history'))).status).toBe(401);
    expect(
      (
        await historyGet(
          new Request('http://localhost:3000/api/v1/notifications/history?userId=usr_alice', {
            headers: { Authorization: `Bearer ${userB}` },
          })
        )
      ).status
    ).toBe(403);

    expect(
      (
        await ackPost(
          new Request('http://localhost:3000/api/v1/notifications/ack/notif_alice_only', {
            method: 'POST',
            headers: { Authorization: `Bearer ${userB}` },
          }),
          { params: { notificationId: 'notif_alice_only' } }
        )
      ).status
    ).toBe(403);

    expect(
      (
        await priorityPatch(
          new Request('http://localhost:3000/api/v1/notifications/priority', {
            method: 'PATCH',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userB}`,
            },
            body: JSON.stringify({ notificationId: 'notif_alice_only', priority: 'CRITICAL' }),
          })
        )
      ).status
    ).toBe(403);

    expect((await quarantineGet(new Request('http://localhost:3000/api/v1/notifications/quarantine'))).status).toBe(401);
    expect(
      (
        await quarantinePost(
          new Request('http://localhost:3000/api/v1/notifications/quarantine', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userA}`,
            },
            body: JSON.stringify({ action: 'SIMULATE' }),
          })
        )
      ).status
    ).toBe(403);

    expect((await streamGet(new Request('http://localhost:3000/api/v1/notifications/stream'))).status).toBe(401);
    expect(
      (
        await streamGet(
          new Request('http://localhost:3000/api/v1/notifications/stream?userId=*', {
            headers: { Authorization: `Bearer ${userA}` },
          })
        )
      ).status
    ).toBe(403);

    expect((await prefsGet(new Request('http://localhost:3000/api/v1/users/preferences?userId=usr_alice'))).status).toBe(401);
    expect(
      (
        await prefsPut(
          new Request('http://localhost:3000/api/v1/users/preferences', {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userB}`,
            },
            body: JSON.stringify({ userId: 'usr_alice', dndEnabled: true }),
          })
        )
      ).status
    ).toBe(403);

    expect((await pushGet(new Request('http://localhost:3000/api/v1/users/push-subscription?userId=usr_alice'))).status).toBe(401);
    expect(
      (
        await pushPost(
          new Request('http://localhost:3000/api/v1/users/push-subscription', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userB}`,
            },
            body: JSON.stringify({
              userId: 'usr_alice',
              subscription: {
                endpoint: 'https://push.example.com/sub',
                keys: { p256dh: 'k1', auth: 'k2' },
              },
            }),
          })
        )
      ).status
    ).toBe(403);

    expect((await metricsGet(new Request('http://localhost:3000/api/v1/analytics/metrics'))).status).toBe(401);
    expect((await chatPost(new Request('http://localhost:3000/api/v1/chat', { method: 'POST' }))).status).toBe(401);
    expect((await targetPhoneGet(new Request('http://localhost:3000/api/v1/notifications/fallback/target-phone'))).status).toBe(401);
    expect(
      (
        await targetPhonePost(
          new Request('http://localhost:3000/api/v1/notifications/fallback/target-phone', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userA}`,
            },
            body: JSON.stringify({ targetPhone: '9876543210' }),
          })
        )
      ).status
    ).toBe(403);

    expect((await quarantineGet(new Request('http://localhost:3000/api/v1/notifications/quarantine', { headers: { Authorization: `Bearer ${admin}` } }))).status).toBe(200);

    // Quarantine bulk delete authorization, validation, and deletion
    expect(
      (
        await quarantineDelete(
          new Request('http://localhost:3000/api/v1/notifications/quarantine', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alertIds: ['quar_1'] }),
          })
        )
      ).status
    ).toBe(401);

    expect(
      (
        await quarantineDelete(
          new Request('http://localhost:3000/api/v1/notifications/quarantine', {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${userA}`,
            },
            body: JSON.stringify({ alertIds: ['quar_1'] }),
          })
        )
      ).status
    ).toBe(403);

    expect(
      (
        await quarantineDelete(
          new Request('http://localhost:3000/api/v1/notifications/quarantine', {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${admin}`,
            },
            body: JSON.stringify({ alertIds: [] }),
          })
        )
      ).status
    ).toBe(400);

    const simRes1 = await quarantinePost(
      new Request('http://localhost:3000/api/v1/notifications/quarantine', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${admin}`,
        },
        body: JSON.stringify({ action: 'SIMULATE' }),
      })
    );
    const simRes2 = await quarantinePost(
      new Request('http://localhost:3000/api/v1/notifications/quarantine', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${admin}`,
        },
        body: JSON.stringify({ action: 'SIMULATE' }),
      })
    );
    const simJson1 = await simRes1.json();
    const simJson2 = await simRes2.json();
    const bulkRes = await quarantineDelete(
      new Request('http://localhost:3000/api/v1/notifications/quarantine', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${admin}`,
        },
        body: JSON.stringify({ alertIds: [simJson1.alert.id, simJson2.alert.id] }),
      })
    );
    expect(bulkRes.status).toBe(200);
    const bulkJson = await bulkRes.json();
    expect(bulkJson.success).toBe(true);
    expect(bulkJson.deletedCount).toBe(2);
    expect(bulkJson.deletedIds).toContain(simJson1.alert.id);
    expect(bulkJson.deletedIds).toContain(simJson2.alert.id);
    expect(bulkJson.alerts.some((a: any) => a.id === simJson1.alert.id)).toBe(false);
    expect(bulkJson.alerts.some((a: any) => a.id === simJson2.alert.id)).toBe(false);
  });

  it('protects integrations endpoints, masks keys for non-admins, and enforces webhook auth', async () => {
    const userToken = makeToken('usr_alice', 'USER');
    const adminToken = makeToken('usr_admin', 'ADMIN');

    expect((await integrationsGet(new Request('http://localhost:3000/api/v1/integrations'))).status).toBe(401);

    const userListRes = await integrationsGet(
      new Request('http://localhost:3000/api/v1/integrations', {
        headers: { Authorization: `Bearer ${userToken}` },
      })
    );
    expect(userListRes.status).toBe(200);
    const userListJson = await userListRes.json();
    expect(userListJson.apps[0].apiKey).toMatch(/^\*\*\*\*/);

    const userCreateRes = await integrationsPost(
      new Request('http://localhost:3000/api/v1/integrations', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ name: 'Rogue App' }),
      })
    );
    expect(userCreateRes.status).toBe(403);

    const userPutRes = await integrationsPut(
      new Request('http://localhost:3000/api/v1/integrations/slack', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${userToken}`,
        },
        body: JSON.stringify({ enabled: false }),
      }),
      { params: { appId: 'slack' } }
    );
    expect(userPutRes.status).toBe(403);

    const unauthWebhook = await webhookPost(
      new Request('http://localhost:3000/api/v1/integrations/webhook?appId=slack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: 'Unauth webhook flood' }),
      })
    );
    expect(unauthWebhook.status).toBe(401);

    const testAdminRes = await integrationsTestPost(
      new Request('http://localhost:3000/api/v1/integrations/test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ appId: 'slack' }),
      })
    );
    expect(testAdminRes.status).toBe(200);
  });

  it('escapes HTML in email alert templates and extracts rightmost trusted proxy IP', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    );
    const html = buildFallbackAlertEmailHtml({
      eventType: '<img src=x onerror=alert(1)>',
      rawText: '<script>evil()</script>',
      dispatchScore: 0.95,
      notificationId: 'notif_"1"',
      timestamp: '2026-01-01T00:00:00Z',
    });
    expect(html).not.toContain('<script>evil()</script>');
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;script&gt;evil()&lt;/script&gt;');

    const ctx = extractRequestContext(
      new Request('http://localhost:3000/api/v1/auth/login', {
        headers: {
          'x-forwarded-for': '198.51.100.1, 203.0.113.55',
        },
      })
    );
    // Rightmost trusted hop (trustProxyHops=1) prevents leftmost header spoofing
    expect(ctx.ipAddress).toBe('203.0.113.55');
  });
});
