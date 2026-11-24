import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { ephemeralJson } from '../../../../../lib/ephemeral/http.js';
import {
  EPHEMERAL_SIMULATOR_SCENARIOS,
  runAllEphemeralScenarios,
  runEphemeralScenario,
  type EphemeralScenarioId,
} from '../../../../../lib/ephemeral/simulator.js';

const VALID_IDS = new Set(EPHEMERAL_SIMULATOR_SCENARIOS.map((s) => s.id));

export async function POST(request: Request) {
  const auth = requireAdminRequest(request);
  if (!auth.ok) {
    return auth.response!;
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return ephemeralJson(
      {
        success: false,
        message: 'Invalid JSON request body.',
      },
      400
    );
  }

  if (body?.demoMode !== true) {
    return ephemeralJson(
      {
        success: false,
        message: 'Demo Mode must be explicitly enabled to run Expiry Simulator scenarios.',
      },
      403
    );
  }

  const firebaseIdToken = request.headers.get('x-firebase-id-token')?.trim() || undefined;
  const action = String(body?.action || 'RUN_ALL').trim().toUpperCase();

  try {
    if (action === 'RUN_SCENARIO') {
      const scenarioId = String(body?.scenarioId || '').trim().toLowerCase() as EphemeralScenarioId;
      if (!VALID_IDS.has(scenarioId)) {
        return ephemeralJson(
          {
            success: false,
            message: 'Invalid scenarioId. Must be one of a through j.',
          },
          400
        );
      }

      const result = await runEphemeralScenario(scenarioId, { firebaseIdToken });
      return ephemeralJson({
        success: true,
        message: `Scenario ${scenarioId.toUpperCase()} ${result.passed ? 'passed' : 'failed'}.`,
        data: { result },
      });
    }

    const summary = await runAllEphemeralScenarios({ firebaseIdToken });
    return ephemeralJson({
      success: true,
      message: `Expiry Simulator completed (${summary.passedCount}/${summary.results.length} passed).`,
      data: summary,
    });
  } catch (err: any) {
    return ephemeralJson(
      {
        success: false,
        message: err?.message || 'Expiry simulator run failed.',
      },
      500
    );
  }
}
