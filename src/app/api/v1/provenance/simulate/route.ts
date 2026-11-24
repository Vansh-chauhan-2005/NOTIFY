import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { runProvenanceAttackSimulator } from '../../../../../lib/provenance/simulator.js';
import { checkProvenanceRouteRateLimit, provenanceJson } from '../../../../../lib/provenance/http.js';

export async function POST(request: Request) {
  const adminCheck = requireAdminRequest(request);
  if (!adminCheck.ok) {
    return adminCheck.response!;
  }

  const rl = checkProvenanceRouteRateLimit('prov_simulate_admin', 20, 60_000);
  if (!rl.allowed) {
    return provenanceJson(
      { success: false, message: `Rate limit exceeded. Retry in ${rl.retryAfterSeconds}s.` },
      429
    );
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return provenanceJson({ success: false, message: 'Invalid JSON request body.' }, 400);
  }

  if (body?.demoMode !== true) {
    return provenanceJson(
      {
        success: false,
        message: 'Demo Mode must be explicitly enabled to run Provenance Attack Simulator scenarios.',
      },
      403
    );
  }

  try {
    const scenariosFilter = Array.isArray(body?.scenarios)
      ? body.scenarios.map((s: unknown) => String(s).trim().toLowerCase())
      : undefined;

    const report = await runProvenanceAttackSimulator(scenariosFilter);
    return provenanceJson({
      success: true,
      message: `Provenance Attack Simulator finished (${report.passedCount}/${report.totalCount} passed).`,
      data: report,
    });
  } catch (err: any) {
    return provenanceJson(
      { success: false, message: err?.message || 'Provenance simulator execution failed.' },
      500
    );
  }
}
