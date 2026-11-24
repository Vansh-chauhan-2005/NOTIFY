import { dedupError, dedupSuccess, enforceDedupRateLimit } from '../../../../../lib/dedup/http.js';
import { runDedupSimulationSuite } from '../../../../../lib/dedup/simulator.js';
import { assertNoPlaintextOrVectors } from '../../../../../lib/dedup/store.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

export async function POST(request: Request): Promise<Response> {
  const limited = enforceDedupRateLimit(request, 'simulate', 30, 60_000);
  if (limited) return limited;

  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return dedupError(400, 'Invalid JSON body.');
  }

  const firewall = assertNoPlaintextOrVectors(body);
  if (!firewall.ok) {
    return dedupError(400, firewall.reason);
  }

  if (body?.demoMode !== true) {
    return dedupError(
      400,
      'Demo Mode must be explicitly enabled (demoMode: true) before running deduplication simulator scenarios.'
    );
  }

  const scenario = typeof body?.scenario === 'string' ? body.scenario.trim() : 'all';
  const results = await runDedupSimulationSuite({ scenario });
  const passedCount = results.filter((r) => r.passed).length;

  return dedupSuccess(
    `Executed ${results.length} deduplication simulation scenario(s): ${passedCount}/${results.length} passed.`,
    {
      results,
      passedCount,
      totalCount: results.length,
    }
  );
}
