import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { APP_CATALOG_BY_ID, AppConnectionType } from '../../data/appCatalog.js';
import { classifyTextWithDefaultWeights } from '../priority/tfidfModel.js';

export interface DirectConnectionRecord {
  id: string;
  userId: string;
  appId: string;
  appName: string;
  category: string;
  connectionType: AppConnectionType;
  label: string;
  encryptedSecret: string;
  secretMask: string;
  encryptedBotToken?: string;
  botTokenMask?: string;
  externalWebhookUrl?: string;
  telegramChatId?: string;
  webhookRegistered?: boolean;
  webhookNote?: string;
  enabled: boolean;
  isTestConnection?: boolean;
  receivedCount: number;
  lastReceivedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface PublicConnectionView {
  id: string;
  appId: string;
  appName: string;
  category: string;
  connectionType: AppConnectionType;
  label: string;
  secretMask: string;
  hasBotToken: boolean;
  botTokenMask?: string;
  externalWebhookUrl?: string;
  telegramChatId?: string;
  webhookRegistered?: boolean;
  webhookNote?: string;
  enabled: boolean;
  receivedCount: number;
  lastReceivedAt?: string;
  createdAt: string;
  updatedAt: string;
  ingestPath: string;
}

const CONNECTIONS_FILE = path.resolve(process.cwd(), '.aegis-connections.json');
const REPLAY_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
export const MAX_INGEST_PAYLOAD_BYTES = 64 * 1024; // 64 KB
export const SIMULATOR_TEST_CONNECTION_ID = 'conn_sim_test_only';

declare global {
  var __aegisDirectConnections: Map<string, DirectConnectionRecord> | undefined;
  var __aegisConnectionsHydrated: boolean | undefined;
  var __aegisEphemeralConnEncKey: Buffer | undefined;
}

function getConnectionEncryptionKey(): Buffer {
  const rawEnv = process.env.CONNECTION_ENCRYPTION_KEY?.trim();
  if (rawEnv) {
    if (/^[0-9a-fA-F]{64}$/.test(rawEnv)) {
      return Buffer.from(rawEnv, 'hex');
    }
    try {
      const b64 = Buffer.from(rawEnv, 'base64');
      if (b64.length === 32) {
        return b64;
      }
    } catch {
      // Fall through to deterministic SHA-256 derivation of supplied env string
    }
    return crypto.createHash('sha256').update(rawEnv, 'utf8').digest();
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('CONNECTION_ENCRYPTION_KEY environment variable is required in production.');
  }

  if (!global.__aegisEphemeralConnEncKey) {
    global.__aegisEphemeralConnEncKey = crypto.randomBytes(32);
  }
  return global.__aegisEphemeralConnEncKey;
}

export function encryptSecret(plaintext: string): string {
  const key = getConnectionEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${authTag.toString('base64')}.${encrypted.toString('base64')}`;
}

export function decryptSecret(ciphertext: string): string {
  const parts = String(ciphertext || '').split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted secret payload.');
  }
  const key = getConnectionEncryptionKey();
  const iv = Buffer.from(parts[0], 'base64');
  const authTag = Buffer.from(parts[1], 'base64');
  const encrypted = Buffer.from(parts[2], 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

export function maskSecret(value: string): string {
  const clean = String(value || '').trim();
  if (clean.length <= 4) return '****';
  return `****${clean.slice(-4)}`;
}

function getConnectionsMap(): Map<string, DirectConnectionRecord> {
  if (!global.__aegisDirectConnections) {
    global.__aegisDirectConnections = new Map<string, DirectConnectionRecord>();
  }

  if (!global.__aegisConnectionsHydrated) {
    global.__aegisConnectionsHydrated = true;
    try {
      if (fs.existsSync(CONNECTIONS_FILE)) {
        const raw = fs.readFileSync(CONNECTIONS_FILE, 'utf8');
        const list = JSON.parse(raw);
        if (Array.isArray(list)) {
          for (const item of list) {
            if (item && typeof item.id === 'string' && typeof item.userId === 'string') {
              global.__aegisDirectConnections.set(item.id, item as DirectConnectionRecord);
            }
          }
        }
      }
    } catch {
      // Non-fatal if persistence file doesn't exist or cannot be parsed
    }
  }

  return global.__aegisDirectConnections;
}

function persistConnectionsMap() {
  try {
    const map = getConnectionsMap();
    const list = Array.from(map.values()).filter((c) => !c.isTestConnection);
    fs.writeFileSync(CONNECTIONS_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch {
    // Non-fatal on read-only filesystem
  }
}

export function toPublicConnectionView(record: DirectConnectionRecord): PublicConnectionView {
  return {
    id: record.id,
    appId: record.appId,
    appName: record.appName,
    category: record.category,
    connectionType: record.connectionType,
    label: record.label,
    secretMask: record.secretMask,
    hasBotToken: Boolean(record.encryptedBotToken),
    ...(record.botTokenMask ? { botTokenMask: record.botTokenMask } : {}),
    ...(record.externalWebhookUrl ? { externalWebhookUrl: record.externalWebhookUrl } : {}),
    ...(record.telegramChatId ? { telegramChatId: record.telegramChatId } : {}),
    ...(typeof record.webhookRegistered === 'boolean'
      ? { webhookRegistered: record.webhookRegistered }
      : {}),
    ...(record.webhookNote ? { webhookNote: record.webhookNote } : {}),
    enabled: record.enabled,
    receivedCount: record.receivedCount,
    ...(record.lastReceivedAt ? { lastReceivedAt: record.lastReceivedAt } : {}),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    ingestPath: `/api/v1/ingest/${record.id}`,
  };
}

export function listUserConnections(userId: string): PublicConnectionView[] {
  const map = getConnectionsMap();
  return Array.from(map.values())
    .filter((c) => c.userId === userId && !c.isTestConnection)
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .map(toPublicConnectionView);
}

export function getConnectionById(connectionId: string): DirectConnectionRecord | null {
  const map = getConnectionsMap();
  return map.get(connectionId) || null;
}

export function createUserConnection(params: {
  userId: string;
  appId: string;
  label?: string;
  botToken?: string;
  externalWebhookUrl?: string;
  telegramChatId?: string;
  webhookRegistered?: boolean;
  webhookNote?: string;
}): { connection: DirectConnectionRecord; signingSecretShownOnce: string } {
  const app = APP_CATALOG_BY_ID[params.appId];
  if (!app) {
    throw new Error('Selected app does not exist in catalog.');
  }

  const id = `conn_${crypto.randomBytes(10).toString('hex')}`;
  const signingSecret = `agsec_${crypto.randomBytes(24).toString('hex')}`;
  const nowIso = new Date().toISOString();

  const encryptedSecret = encryptSecret(signingSecret);
  const encryptedBotToken = params.botToken ? encryptSecret(params.botToken) : undefined;

  const record: DirectConnectionRecord = {
    id,
    userId: params.userId,
    appId: app.id,
    appName: app.name,
    category: app.category,
    connectionType: app.connectionType,
    label: (params.label?.trim() || `${app.name} Connection`).slice(0, 80),
    encryptedSecret,
    secretMask: maskSecret(signingSecret),
    ...(encryptedBotToken ? { encryptedBotToken, botTokenMask: maskSecret(params.botToken!) } : {}),
    ...(params.externalWebhookUrl ? { externalWebhookUrl: params.externalWebhookUrl } : {}),
    ...(params.telegramChatId ? { telegramChatId: params.telegramChatId.slice(0, 64) } : {}),
    ...(typeof params.webhookRegistered === 'boolean'
      ? { webhookRegistered: params.webhookRegistered }
      : {}),
    ...(params.webhookNote ? { webhookNote: params.webhookNote.slice(0, 240) } : {}),
    enabled: true,
    receivedCount: 0,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  const map = getConnectionsMap();
  map.set(record.id, record);
  persistConnectionsMap();

  return { connection: record, signingSecretShownOnce: signingSecret };
}

export function updateConnectionWebhookMeta(
  connectionId: string,
  meta: { webhookRegistered: boolean; webhookNote?: string }
): void {
  const map = getConnectionsMap();
  const record = map.get(connectionId);
  if (!record) return;
  record.webhookRegistered = meta.webhookRegistered;
  if (meta.webhookNote) record.webhookNote = meta.webhookNote.slice(0, 240);
  record.updatedAt = new Date().toISOString();
  persistConnectionsMap();
}

export function incrementConnectionReceived(connectionId: string): void {
  const map = getConnectionsMap();
  const record = map.get(connectionId);
  if (!record) return;
  record.receivedCount += 1;
  record.lastReceivedAt = new Date().toISOString();
  record.updatedAt = record.lastReceivedAt;
  if (!record.isTestConnection) {
    persistConnectionsMap();
  }
}

export function deleteUserConnection(userId: string, connectionId: string): boolean {
  const map = getConnectionsMap();
  const existing = map.get(connectionId);
  if (!existing || existing.userId !== userId || existing.isTestConnection) {
    return false;
  }
  map.delete(connectionId);
  persistConnectionsMap();
  return true;
}

export function deleteAllUserConnections(userId: string): number {
  const map = getConnectionsMap();
  let removed = 0;
  for (const [id, rec] of Array.from(map.entries())) {
    if (rec.userId === userId && !rec.isTestConnection) {
      map.delete(id);
      removed += 1;
    }
  }
  if (removed > 0) {
    persistConnectionsMap();
  }
  return removed;
}

/**
 * Isolated test-only connection used strictly by Attack Simulator routes.
 */
export function getOrCreateSimulatorTestConnection(): {
  record: DirectConnectionRecord;
  signingSecret: string;
} {
  const map = getConnectionsMap();
  const existing = map.get(SIMULATOR_TEST_CONNECTION_ID);
  if (existing) {
    try {
      const secret = decryptSecret(existing.encryptedSecret);
      return { record: existing, signingSecret: secret };
    } catch {
      // Regenerate if server restarted in dev with ephemeral key
    }
  }

  const secret = `agsec_sim_${crypto.randomBytes(20).toString('hex')}`;
  const nowIso = new Date().toISOString();
  const record: DirectConnectionRecord = {
    id: SIMULATOR_TEST_CONNECTION_ID,
    userId: 'usr_simulator_isolated',
    appId: 'github',
    appName: 'GitHub (Simulator Test)',
    category: 'Developer',
    connectionType: 'github',
    label: 'Isolated Simulator Test Connection',
    encryptedSecret: encryptSecret(secret),
    secretMask: maskSecret(secret),
    enabled: true,
    isTestConnection: true,
    receivedCount: 0,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
  map.set(record.id, record);
  return { record, signingSecret: secret };
}

/**
 * Strict SSRF host allowlist for optional outbound Discord/Slack webhook forwarding.
 */
export function validateExternalWebhookUrl(
  urlStr: string,
  connectionType: AppConnectionType
): { valid: boolean; normalized?: string; error?: string } {
  const trimmed = urlStr.trim();
  if (!trimmed) return { valid: true };
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: 'Webhook URL must be a valid HTTPS URL.' };
  }

  if (parsed.protocol !== 'https:') {
    return { valid: false, error: 'Webhook URL must use HTTPS.' };
  }

  const host = parsed.hostname.toLowerCase();
  if (connectionType === 'discord') {
    const allowed = host === 'discord.com' || host === 'discordapp.com';
    if (!allowed || !parsed.pathname.startsWith('/api/webhooks/')) {
      return {
        valid: false,
        error: 'Discord webhook URL must point to https://discord.com/api/webhooks/...',
      };
    }
  } else if (connectionType === 'slack') {
    if (host !== 'hooks.slack.com' || !parsed.pathname.startsWith('/services/')) {
      return {
        valid: false,
        error: 'Slack webhook URL must point to https://hooks.slack.com/services/...',
      };
    }
  } else {
    return { valid: false, error: 'External webhook forwarding is only allowed for Discord and Slack.' };
  }

  return { valid: true, normalized: parsed.toString() };
}

export function isTimestampWithinReplayWindow(
  rawTimestamp: string | null | undefined,
  maxSkewMs: number = REPLAY_WINDOW_MS
): { valid: boolean; reason?: string; timestampMs?: number } {
  if (!rawTimestamp || !rawTimestamp.trim()) {
    return { valid: false, reason: 'Missing X-Aegis-Timestamp header.' };
  }

  const trimmed = rawTimestamp.trim();
  let tsMs = NaN;

  if (/^\d{10,13}$/.test(trimmed)) {
    const num = Number(trimmed);
    tsMs = trimmed.length === 10 ? num * 1000 : num;
  } else {
    tsMs = Date.parse(trimmed);
  }

  if (!Number.isFinite(tsMs) || Number.isNaN(tsMs)) {
    return { valid: false, reason: 'Invalid X-Aegis-Timestamp format.' };
  }

  const diff = Math.abs(Date.now() - tsMs);
  if (diff > maxSkewMs) {
    return {
      valid: false,
      reason: `Timestamp outside 5-minute replay window (${Math.round(diff / 1000)}s skew).`,
      timestampMs: tsMs,
    };
  }

  return { valid: true, timestampMs: tsMs };
}

export function computeHmacSignature(secret: string, timestampRaw: string, rawBody: string): string {
  const signedPayload = `${timestampRaw}.${rawBody}`;
  return crypto.createHmac('sha256', secret).update(signedPayload, 'utf8').digest('hex');
}

function timingSafeHexOrStringEqual(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(provided, 'utf8');
  if (a.length !== b.length || a.length === 0) {
    // Compare dummy equal buffers so timing behavior remains consistent
    const dummy = Buffer.alloc(Math.max(1, a.length), 0);
    crypto.timingSafeEqual(dummy, dummy);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * Verifies incoming HMAC-SHA256 signature using crypto.timingSafeEqual:
 * - Standard Aegis format: X-Aegis-Signature: sha256=<hex> (or <hex>) signed over `${timestamp}.${rawBody}`
 * - GitHub Webhook format: X-Hub-Signature-256: sha256=<hex> signed over `rawBody`
 */
export function verifyIngestSignature(params: {
  secret: string;
  rawBody: string;
  timestampRaw?: string | null;
  aegisSignature?: string | null;
  githubSignature?: string | null;
  telegramSecretHeader?: string | null;
  connectionType: AppConnectionType;
}): { valid: boolean; mode: string; reason?: string } {
  const {
    secret,
    rawBody,
    timestampRaw,
    aegisSignature,
    githubSignature,
    telegramSecretHeader,
    connectionType,
  } = params;

  if (connectionType === 'telegram' && telegramSecretHeader) {
    const expectedTelegramToken = crypto
      .createHash('sha256')
      .update(secret, 'utf8')
      .digest('hex')
      .slice(0, 48);
    const ok = timingSafeHexOrStringEqual(expectedTelegramToken, telegramSecretHeader.trim());
    return ok
      ? { valid: true, mode: 'telegram-secret-token' }
      : { valid: false, mode: 'telegram-secret-token', reason: 'Invalid Telegram secret token header.' };
  }

  if (githubSignature) {
    const cleanProvided = githubSignature.trim().replace(/^sha256=/i, '').toLowerCase();
    const expectedHex = crypto
      .createHmac('sha256', secret)
      .update(rawBody, 'utf8')
      .digest('hex')
      .toLowerCase();
    const ok = timingSafeHexOrStringEqual(expectedHex, cleanProvided);
    return ok
      ? { valid: true, mode: 'github-hmac-sha256' }
      : { valid: false, mode: 'github-hmac-sha256', reason: 'Invalid X-Hub-Signature-256 digest.' };
  }

  if (!aegisSignature) {
    return { valid: false, mode: 'aegis-hmac-sha256', reason: 'Missing X-Aegis-Signature header.' };
  }

  if (!timestampRaw) {
    return { valid: false, mode: 'aegis-hmac-sha256', reason: 'Missing X-Aegis-Timestamp header.' };
  }

  const cleanProvided = aegisSignature.trim().replace(/^sha256=/i, '').toLowerCase();
  const expectedHex = computeHmacSignature(secret, timestampRaw.trim(), rawBody).toLowerCase();
  const ok = timingSafeHexOrStringEqual(expectedHex, cleanProvided);

  return ok
    ? { valid: true, mode: 'aegis-hmac-sha256' }
    : { valid: false, mode: 'aegis-hmac-sha256', reason: 'HMAC-SHA256 signature mismatch.' };
}

export function deriveTelegramSecretToken(signingSecret: string): string {
  return crypto.createHash('sha256').update(signingSecret, 'utf8').digest('hex').slice(0, 48);
}

export function sanitizeNotificationText(input: string, maxLen = 500): string {
  const cleaned = String(input || '')
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F]/g, ' ')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length > maxLen) {
    return `${cleaned.slice(0, maxLen - 3)}...`;
  }
  return cleaned;
}

export function classifyIngestedPriority(
  rawText: string,
  hintedPriority?: string
): { priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; riskScore: number } {
  const upperHint = String(hintedPriority || '').toUpperCase();
  if (upperHint === 'CRITICAL') return { priority: 'CRITICAL', riskScore: 0.94 };
  if (upperHint === 'HIGH') return { priority: 'HIGH', riskScore: 0.8 };
  if (upperHint === 'LOW') return { priority: 'LOW', riskScore: 0.25 };

  const text = rawText.toLowerCase();
  if (
    /\b(critical|breach|unauthorized|compromised|ransomware|lockout|otp|security alert|incident)\b/.test(
      text
    )
  ) {
    return { priority: 'CRITICAL', riskScore: 0.92 };
  }
  if (/\b(urgent|failed|failure|warning|payment|fraud|overdue|deadline)\b/.test(text)) {
    return { priority: 'HIGH', riskScore: 0.78 };
  }
  if (/\b(digest|summary|newsletter|promo|offer|update)\b/.test(text)) {
    return { priority: 'LOW', riskScore: 0.28 };
  }

  const tfidfRes = classifyTextWithDefaultWeights(rawText, 'work');
  if (tfidfRes.matchedTermsCount > 0) {
    const mapped =
      tfidfRes.predictedClass === 'Critical'
        ? 'CRITICAL'
        : tfidfRes.predictedClass === 'High'
          ? 'HIGH'
          : tfidfRes.predictedClass === 'Low'
            ? 'LOW'
            : 'MEDIUM';
    return { priority: mapped, riskScore: tfidfRes.tfidfImportanceScore };
  }

  return { priority: 'MEDIUM', riskScore: 0.52 };
}
