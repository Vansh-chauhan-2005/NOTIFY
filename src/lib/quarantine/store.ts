export interface QuarantinedAlert {
  id: string;
  timestamp: string;
  reason:
    | 'INVALID_SIGNATURE'
    | 'MISSING_AUTH_HEADER'
    | 'INVALID_API_KEY'
    | 'UNTRUSTED_WEBHOOK_SOURCE'
    | 'MISCELLANEOUS_ANOMALY'
    | 'RATE_LIMIT_EXCEEDED';
  reasonLabel: string;
  description: string;
  sourceIp: string;
  sourceApp: string;
  rawPayload: Record<string, any>;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'FLAGGED' | 'DISMISSED' | 'BLOCKED' | 'WHITELISTED';
}

export const initialQuarantinedAlerts: QuarantinedAlert[] = [
  {
    id: 'quar_1789038012_x81b',
    timestamp: new Date(Date.now() - 1000 * 60 * 7).toISOString(),
    reason: 'INVALID_SIGNATURE',
    reasonLabel: 'Counterfeit Ed25519 Signature',
    description: 'Incoming notification claiming to be [Stripe Refund] failed cryptographic signature verification against known authority.',
    sourceIp: '185.220.101.44 (Tor Exit Node)',
    sourceApp: 'Spoofed Stripe Webhook',
    rawPayload: {
      event: 'CHARGE_REFUNDED',
      amount: '$14,200.00',
      account: 'acct_primary_treasury',
      signature: 'bad_sig_a8f9c091bc2e8d19...',
    },
    riskLevel: 'CRITICAL',
    status: 'FLAGGED',
  },
  {
    id: 'quar_1789038025_m92k',
    timestamp: new Date(Date.now() - 1000 * 60 * 32).toISOString(),
    reason: 'MISSING_AUTH_HEADER',
    reasonLabel: 'Unauthenticated Anonymous Post',
    description: 'HTTP POST to /api/v1/notifications/ingest was dispatched without X-API-Key or Authorization Bearer header.',
    sourceIp: '45.154.255.89',
    sourceApp: 'Direct API Probe',
    rawPayload: {
      userId: 'usr_sec_admin_01',
      eventType: 'SYSTEM_STATUS_PING',
      rawText: 'Anomalous unauthenticated probe attempting discovery',
    },
    riskLevel: 'HIGH',
    status: 'FLAGGED',
  },
  {
    id: 'quar_1789038048_z44p',
    timestamp: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
    reason: 'MISCELLANEOUS_ANOMALY',
    reasonLabel: 'Miscellaneous Malformed Message',
    description: 'Message arrived with malformed JSON body encoding and unrecognized metadata headers.',
    sourceIp: '103.145.74.2',
    sourceApp: 'Unidentified Gateway',
    rawPayload: {
      corrupt_bytes: '0x7f454c46020101000000',
      origin: 'raw_socket_scanner',
    },
    riskLevel: 'MEDIUM',
    status: 'FLAGGED',
  },
  {
    id: 'quar_1789038062_q11r',
    timestamp: new Date(Date.now() - 1000 * 60 * 140).toISOString(),
    reason: 'UNTRUSTED_WEBHOOK_SOURCE',
    reasonLabel: 'Untrusted Webhook Source IP',
    description: 'Incoming GitHub Webhook payload originated from an IP outside the official GitHub Meta IP ranges.',
    sourceIp: '194.26.29.113',
    sourceApp: 'Forged GitHub Event',
    rawPayload: {
      action: 'repository_compromised',
      repo: 'core-crypto-contracts',
    },
    riskLevel: 'HIGH',
    status: 'BLOCKED',
  },
];

declare global {
  var aegisQuarantineStore: QuarantinedAlert[] | undefined;
}

if (!global.aegisQuarantineStore) {
  global.aegisQuarantineStore = [...initialQuarantinedAlerts];
}

export function getQuarantinedAlerts(): QuarantinedAlert[] {
  return global.aegisQuarantineStore || initialQuarantinedAlerts;
}

export function addQuarantinedAlert(
  item: Omit<QuarantinedAlert, 'id' | 'timestamp' | 'status'>
): QuarantinedAlert {
  const store = getQuarantinedAlerts();
  const alert: QuarantinedAlert = {
    ...item,
    id: `quar_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: new Date().toISOString(),
    status: 'FLAGGED',
  };
  store.unshift(alert);
  return alert;
}

export function updateQuarantinedAlertStatus(
  id: string,
  status: QuarantinedAlert['status']
): QuarantinedAlert | null {
  const store = getQuarantinedAlerts();
  const alert = store.find((a) => a.id === id);
  if (!alert) return null;
  alert.status = status;
  return alert;
}

export function deleteQuarantinedAlerts(ids: string[]): {
  deletedIds: string[];
  remaining: QuarantinedAlert[];
} {
  const store = getQuarantinedAlerts();
  const targetSet = new Set(
    ids
      .map((id) => String(id || '').trim())
      .filter((id) => id.length > 0 && id.length <= 128)
      .slice(0, 500)
  );
  if (targetSet.size === 0) {
    return { deletedIds: [], remaining: store };
  }

  const deletedIds: string[] = [];
  for (let i = store.length - 1; i >= 0; i -= 1) {
    if (targetSet.has(store[i].id)) {
      deletedIds.unshift(store[i].id);
      store.splice(i, 1);
    }
  }
  return { deletedIds, remaining: store };
}

export function clearQuarantinedAlerts(): void {
  if (global.aegisQuarantineStore) {
    global.aegisQuarantineStore = [];
  }
}
