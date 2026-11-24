import { runGatewaySimulation } from '../../../../../lib/gateway/simulator.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';

export async function POST(request: Request): Promise<Response> {
  const auth = requireAdminRequest(request);
  if (!auth.ok || !auth.user) return auth.response!;

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') {
    return Response.json(
      { success: false, message: 'Request body must be valid JSON.' },
      { status: 400 }
    );
  }

  if (body.demoMode !== true) {
    return Response.json(
      {
        success: false,
        message: 'Gateway attack simulation is disabled unless Demo Mode is explicitly toggled ON.',
      },
      { status: 400 }
    );
  }

  const scenario = String(body.scenario || 'all').trim().toLowerCase();
  const results = await runGatewaySimulation(scenario);

  if (results.length === 0) {
    return Response.json(
      { success: false, message: `Unknown simulation scenario code: ${scenario}` },
      { status: 400 }
    );
  }

  const passedCount = results.filter((r) => r.passed).length;
  return Response.json({
    success: true,
    message: `Completed ${results.length} gateway simulation scenario(s): ${passedCount}/${results.length} passed.`,
    data: {
      passedCount,
      totalCount: results.length,
      results,
    },
  });
}
