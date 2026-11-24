#!/usr/bin/env node
/**
 * Local-only Gateway Load Test Helper (Node 22 native fetch)
 *
 * SAFETY WARNING:
 * Run ONLY against http://localhost:3000 (or 127.0.0.1:3000).
 * Never aim load generators at third-party servers, public endpoints, or cloud sandboxes you do not own.
 *
 * Usage:
 *   node scripts/load-test-gateway.mjs
 *   TARGET_URL=http://127.0.0.1:3000/api/v1/auth/login TOTAL_REQUESTS=40 CONCURRENCY=8 node scripts/load-test-gateway.mjs
 */

const targetUrl = process.env.TARGET_URL || 'http://127.0.0.1:3000/api/v1/gateway/health';
const totalRequests = Math.max(1, Math.min(2000, Number(process.env.TOTAL_REQUESTS || 120)));
const concurrency = Math.max(1, Math.min(50, Number(process.env.CONCURRENCY || 10)));

const parsed = new URL(targetUrl);
if (parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
  console.error('Refusing to run: TARGET_URL must point to localhost or 127.0.0.1 only.');
  process.exit(1);
}

const isPostAuth = parsed.pathname.includes('/auth/login');
const latencies = [];
const statusCounts = new Map();
let completed = 0;

async function worker(queue) {
  while (queue.length > 0) {
    queue.pop();
    const start = performance.now();
    try {
      const res = await fetch(targetUrl, {
        method: isPostAuth ? 'POST' : 'GET',
        headers: isPostAuth ? { 'content-type': 'application/json' } : {},
        body: isPostAuth ? JSON.stringify({ email: 'loadtest@local.test', password: 'wrong' }) : undefined,
      });
      statusCounts.set(res.status, (statusCounts.get(res.status) || 0) + 1);
    } catch {
      statusCounts.set('ERR', (statusCounts.get('ERR') || 0) + 1);
    } finally {
      latencies.push(performance.now() - start);
      completed += 1;
    }
  }
}

const runStart = performance.now();
const queue = Array.from({ length: totalRequests }, (_, i) => i);
await Promise.all(Array.from({ length: concurrency }, () => worker(queue)));
const elapsedSec = (performance.now() - runStart) / 1000;

latencies.sort((a, b) => a - b);
const pct = (p) => latencies[Math.min(latencies.length - 1, Math.floor((latencies.length - 1) * p))] || 0;

console.log('=== AegisNotify Local Gateway Load Test ===');
console.log(`Target:      ${targetUrl}`);
console.log(`Requests:    ${completed} (concurrency=${concurrency})`);
console.log(`Duration:    ${elapsedSec.toFixed(2)}s`);
console.log(`Throughput:  ${(completed / elapsedSec).toFixed(2)} req/sec`);
console.log(`Latency ms:  p50=${pct(0.5).toFixed(2)}ms  p95=${pct(0.95).toFixed(2)}ms  p99=${pct(0.99).toFixed(2)}ms`);
console.log('Status Breakdown:', Object.fromEntries(statusCounts.entries()));
