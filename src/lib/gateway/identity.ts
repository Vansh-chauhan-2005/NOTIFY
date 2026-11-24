import crypto from 'crypto';
import type { ClientIdentity, RouteGroup } from './types.js';

let ephemeralProcessSalt: string | null = null;

function getProcessSalt(): string {
  const configured = (process.env.GATEWAY_IP_SALT || '')
    .trim()
    .replace(/^["']+|["']+$/g, '');
  if (configured) return configured;
  if (!ephemeralProcessSalt) {
    // Ephemeral process-local salt if operator has not configured GATEWAY_IP_SALT yet
    ephemeralProcessSalt = crypto.randomBytes(32).toString('hex');
  }
  return ephemeralProcessSalt;
}

export function getTrustProxyHops(): number {
  const rawStr = String(process.env.TRUST_PROXY_HOPS ?? '1')
    .trim()
    .replace(/^["']+|["']+$/g, '');
  const raw = Number(rawStr);
  if (!Number.isFinite(raw) || raw < 0) return 0;
  return Math.min(10, Math.floor(raw));
}

/**
 * Extracts client IP ONLY from the trusted hop position in X-Forwarded-For.
 * Attackers often prepend spoofed entries on the left of X-Forwarded-For;
 * reading from the right by `trustProxyHops` prevents spoofing bypasses.
 */
export function parseTrustedClientIp(params: {
  socketRemoteAddress?: string | null;
  xForwardedFor?: string | string[] | null;
  trustProxyHops?: number;
}): string {
  const hops =
    typeof params.trustProxyHops === 'number'
      ? Math.max(0, Math.min(10, Math.floor(params.trustProxyHops)))
      : getTrustProxyHops();

  const fallbackIp = String(params.socketRemoteAddress || '127.0.0.1').trim() || '127.0.0.1';

  if (hops === 0 || !params.xForwardedFor) {
    return normalizeIp(fallbackIp);
  }

  const headerVal = Array.isArray(params.xForwardedFor)
    ? params.xForwardedFor.join(',')
    : String(params.xForwardedFor);

  const chain = headerVal
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && part.length <= 128);

  if (chain.length === 0) {
    return normalizeIp(fallbackIp);
  }

  // With trustProxyHops = 1, a single trusted proxy appends the true client IP as the
  // rightmost entry (index chain.length - 1). With N hops, walk back N entries from right.
  const trustedIndex = Math.max(0, chain.length - hops);
  const candidate = chain[trustedIndex] || fallbackIp;
  return normalizeIp(candidate);
}

/**
 * Expands compressed IPv6 and collapses any non-IPv4-mapped IPv6 address to its /64 prefix
 * so rotating lower 64 interface bits does not evade IP rate limits.
 * IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) normalize cleanly to IPv4 (a.b.c.d).
 */
export function normalizeIp(rawInput: string): string {
  let raw = String(rawInput || '').trim();
  if (!raw) return '127.0.0.1';

  // Strip IPv6 zone identifier (e.g. %eth0)
  const zoneIdx = raw.indexOf('%');
  if (zoneIdx >= 0) {
    raw = raw.slice(0, zoneIdx);
  }

  // Handle bracketed IPv6 with optional port: [::1]:8080
  if (raw.startsWith('[')) {
    const closeIdx = raw.indexOf(']');
    if (closeIdx > 0) {
      raw = raw.slice(1, closeIdx);
    }
  } else if (raw.includes('.') && raw.includes(':') && !raw.includes('::') && raw.split(':').length === 2) {
    // IPv4 with port: 192.0.2.1:54321
    raw = raw.split(':')[0];
  }

  const lower = raw.toLowerCase();
  if (lower === '::1') return '127.0.0.1';

  // IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.10 or 0:0:0:0:0:ffff:192.0.2.10)
  const v4MappedMatch = lower.match(/^(?:0{0,4}:){0,5}(?:::)?ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4MappedMatch) {
    return v4MappedMatch[1];
  }

  // Hex IPv4-mapped IPv6 (e.g. ::ffff:c000:0201)
  const hexMappedMatch = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMappedMatch) {
    const hi = parseInt(hexMappedMatch[1], 16);
    const lo = parseInt(hexMappedMatch[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }

  // Plain IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(lower)) {
    return lower;
  }

  // Full IPv6 -> /64 prefix normalization
  const expanded = expandIpv6(lower);
  if (expanded) {
    const groups = expanded.split(':');
    return `${groups.slice(0, 4).join(':')}::/64`;
  }

  return lower.slice(0, 64);
}

function expandIpv6(addr: string): string | null {
  if (!addr.includes(':')) return null;
  const halves = addr.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];

  // Handle embedded trailing IPv4 in IPv6 (e.g. ::192.0.2.1)
  if (right.length > 0 && right[right.length - 1].includes('.')) {
    const v4 = right.pop()!;
    const octets = v4.split('.').map((n) => Number(n));
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return null;
    }
    right.push(((octets[0] << 8) | octets[1]).toString(16));
    right.push(((octets[2] << 8) | octets[3]).toString(16));
  }

  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const middle = halves.length === 2 ? Array(missing).fill('0000') : [];
  const full = [...left, ...middle, ...right];
  if (full.length !== 8) return null;

  return full
    .map((g) => {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      return g.padStart(4, '0');
    })
    .every((g) => g !== null)
    ? full.map((g) => g.padStart(4, '0')).join(':')
    : null;
}

/**
 * Irreversible SHA-256 hash of normalized IP + server salt (GATEWAY_IP_SALT).
 * Raw IPs are NEVER written to logs or telemetry.
 */
export function hashIp(normalizedIp: string, salt?: string): string {
  const activeSalt = salt ?? getProcessSalt();
  return crypto
    .createHash('sha256')
    .update(`${activeSalt}:${normalizedIp}`)
    .digest('hex');
}

export function hashIdentifier(rawValue: string, salt?: string): string {
  const activeSalt = salt ?? getProcessSalt();
  return crypto
    .createHash('sha256')
    .update(`${activeSalt}:id:${rawValue.trim().toLowerCase()}`)
    .digest('hex');
}

export function shortKeyHash(fullHash: string): string {
  return String(fullHash || '').slice(0, 8);
}

export function buildClientIdentity(params: {
  socketRemoteAddress?: string | null;
  xForwardedFor?: string | string[] | null;
  trustProxyHops?: number;
  userId?: string;
  accountKey?: string;
  connectionId?: string;
  routeGroup: RouteGroup;
  salt?: string;
}): ClientIdentity {
  const rawIpNormalized = parseTrustedClientIp({
    socketRemoteAddress: params.socketRemoteAddress,
    xForwardedFor: params.xForwardedFor,
    trustProxyHops: params.trustProxyHops,
  });

  const ipHash = hashIp(rawIpNormalized, params.salt);
  const shortIpHash = shortKeyHash(ipHash);

  const cleanUserId = params.userId?.trim() || undefined;
  const cleanConnId = params.connectionId?.trim() || undefined;
  const cleanAcctHash = params.accountKey?.trim()
    ? shortKeyHash(hashIdentifier(params.accountKey, params.salt))
    : undefined;

  const ipOnly = `ip:${ipHash}`;
  const ipGroup = `ip:${ipHash}:group:${params.routeGroup}`;
  const userOnly = cleanUserId ? `user:${cleanUserId}` : undefined;
  const userGroup = cleanUserId ? `user:${cleanUserId}:group:${params.routeGroup}` : undefined;
  const connection = cleanConnId ? `conn:${cleanConnId}` : undefined;
  const accountHourly = cleanAcctHash ? `acct:${cleanAcctHash}` : undefined;

  let mostSpecific = ipGroup;
  if (connection) {
    mostSpecific = `${connection}:ip:${ipHash}`;
  } else if (userGroup) {
    mostSpecific = userGroup;
  } else if (accountHourly) {
    mostSpecific = `${ipGroup}:acct:${cleanAcctHash}`;
  }

  const allLimitKeys: string[] = [mostSpecific];
  if (userGroup && !allLimitKeys.includes(userGroup)) allLimitKeys.push(userGroup);
  if (userOnly && !allLimitKeys.includes(userOnly)) allLimitKeys.push(userOnly);
  if (connection && !allLimitKeys.includes(connection)) allLimitKeys.push(connection);
  if (!allLimitKeys.includes(ipGroup)) allLimitKeys.push(ipGroup);
  if (!allLimitKeys.includes(ipOnly)) allLimitKeys.push(ipOnly);

  return {
    rawIpNormalized,
    ipHash,
    shortIpHash,
    userId: cleanUserId,
    accountKey: cleanAcctHash,
    connectionId: cleanConnId,
    routeGroup: params.routeGroup,
    keys: {
      mostSpecific,
      ipGroup,
      ipOnly,
      userGroup,
      userOnly,
      connection,
      accountHourly,
    },
    allLimitKeys,
  };
}
