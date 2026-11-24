import type { RoutePolicy } from './types.js';

export interface HardeningViolation {
  ok: boolean;
  statusCode?: number;
  outcome?: 'oversize' | 'malformed';
  message?: string;
  headers?: Record<string, string>;
}

const FORBIDDEN_POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Cheap pre-body request hardening checks:
 * 1. URL length limit (414)
 * 2. Header count & total header bytes limit (431)
 * 3. Expected HTTP method per route policy (405)
 * 4. Content-Type validation on mutating requests (415)
 * 5. Declared Content-Length cap BEFORE reading body (413)
 */
export function validateCheapRequestHardening(params: {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  policy: RoutePolicy;
}): HardeningViolation {
  const method = params.method.toUpperCase();

  // 1. URL length guard
  if (params.url.length > params.policy.maxUrlLength) {
    return {
      ok: false,
      statusCode: 414,
      outcome: 'oversize',
      message: `Request URL exceeds maximum allowed length (${params.policy.maxUrlLength} chars).`,
    };
  }

  // 2. Header count & cumulative byte size guard
  const entries = Object.entries(params.headers);
  if (entries.length > 80) {
    return {
      ok: false,
      statusCode: 431,
      outcome: 'oversize',
      message: 'Too many HTTP request headers.',
    };
  }

  let headerBytes = 0;
  for (const [k, v] of entries) {
    headerBytes += k.length;
    if (Array.isArray(v)) {
      for (const item of v) headerBytes += String(item || '').length;
    } else if (v !== undefined) {
      headerBytes += String(v).length;
    }
    if (headerBytes > 16 * 1024) {
      return {
        ok: false,
        statusCode: 431,
        outcome: 'oversize',
        message: 'HTTP request headers exceed 16 KB security limit.',
      };
    }
  }

  // Allow CORS preflight OPTIONS immediately after basic URL/header hygiene
  if (method === 'OPTIONS') {
    return { ok: true };
  }

  // 3. Allowed HTTP methods per route group
  if (!params.policy.allowedMethods.includes(method)) {
    return {
      ok: false,
      statusCode: 405,
      outcome: 'malformed',
      message: `HTTP method ${method} is not allowed on ${params.policy.group} routes.`,
      headers: {
        Allow: params.policy.allowedMethods.join(', '),
      },
    };
  }

  // 4. Declared Content-Length pre-read cap
  const rawContentLength = params.headers['content-length'];
  const clStr = Array.isArray(rawContentLength) ? rawContentLength[0] : rawContentLength;
  if (clStr !== undefined && clStr !== '') {
    const parsedLength = Number(clStr);
    if (!Number.isFinite(parsedLength) || parsedLength < 0) {
      return {
        ok: false,
        statusCode: 400,
        outcome: 'malformed',
        message: 'Invalid Content-Length header.',
      };
    }
    if (parsedLength > params.policy.maxBodyBytes) {
      return {
        ok: false,
        statusCode: 413,
        outcome: 'oversize',
        message: `Payload size (${parsedLength} bytes) exceeds ${Math.round(
          params.policy.maxBodyBytes / 1024
        )} KB limit for ${params.policy.group} routes.`,
      };
    }
  }

  // 5. Content-Type check when body is expected/declared
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
    const hasBody = Number(clStr || '0') > 0 || Boolean(params.headers['transfer-encoding']);
    const ctHeaderRaw = params.headers['content-type'];
    const ctHeader = (Array.isArray(ctHeaderRaw) ? ctHeaderRaw[0] : ctHeaderRaw) || '';
    const ctBase = ctHeader.split(';')[0].trim().toLowerCase();

    if (hasBody || ctBase.length > 0) {
      const allowed = params.policy.allowedContentTypes.some(
        (allowedCt) => ctBase === allowedCt || ctBase.startsWith(`${allowedCt}`)
      );
      if (!allowed) {
        return {
          ok: false,
          statusCode: 415,
          outcome: 'malformed',
          message: `Unsupported Content-Type "${ctBase || 'none'}". Expected ${params.policy.allowedContentTypes.join(' or ')}.`,
        };
      }
    }
  }

  return { ok: true };
}

/**
 * Validates raw JSON text BEFORE or AFTER JSON.parse for:
 * - __proto__ / constructor / prototype keys (prototype pollution defense)
 * - JSON bomb maximum nesting depth
 * - Maximum total key count
 * - Maximum array length
 */
export function inspectRawJsonTextForPollution(rawJson: string): HardeningViolation {
  if (/"(__proto__|constructor|prototype)"\s*:/i.test(rawJson)) {
    return {
      ok: false,
      statusCode: 400,
      outcome: 'malformed',
      message: 'Rejected payload containing forbidden prototype-pollution keys.',
    };
  }
  return { ok: true };
}

export function validateParsedJsonSafety(
  value: unknown,
  limits: { maxDepth: number; maxKeys: number; maxArrayLength: number }
): HardeningViolation {
  let totalKeys = 0;

  const stack: Array<{ node: unknown; depth: number }> = [{ node: value, depth: 1 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    if (node === null || typeof node !== 'object') {
      continue;
    }

    if (depth > limits.maxDepth) {
      return {
        ok: false,
        statusCode: 400,
        outcome: 'malformed',
        message: `JSON nesting depth exceeds maximum allowed limit (${limits.maxDepth}).`,
      };
    }

    if (Array.isArray(node)) {
      if (node.length > limits.maxArrayLength) {
        return {
          ok: false,
          statusCode: 400,
          outcome: 'malformed',
          message: `JSON array length (${node.length}) exceeds maximum allowed (${limits.maxArrayLength}).`,
        };
      }
      for (let i = 0; i < node.length; i++) {
        if (node[i] !== null && typeof node[i] === 'object') {
          stack.push({ node: node[i], depth: depth + 1 });
        }
      }
      continue;
    }

    const keys = Object.keys(node as Record<string, unknown>);
    totalKeys += keys.length;
    if (totalKeys > limits.maxKeys) {
      return {
        ok: false,
        statusCode: 400,
        outcome: 'malformed',
        message: `JSON total key count exceeds maximum allowed limit (${limits.maxKeys}).`,
      };
    }

    for (const key of keys) {
      if (FORBIDDEN_POLLUTION_KEYS.has(key)) {
        return {
          ok: false,
          statusCode: 400,
          outcome: 'malformed',
          message: `Forbidden key "${key}" rejected by prototype-pollution guard.`,
        };
      }
      const child = (node as Record<string, unknown>)[key];
      if (child !== null && typeof child === 'object') {
        stack.push({ node: child, depth: depth + 1 });
      }
    }
  }

  return { ok: true };
}
