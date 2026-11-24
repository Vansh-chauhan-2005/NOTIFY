import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { resetBreaker } from '../../../../../lib/delivery/circuitBreaker.js';
import {
  runAllSimulatorScenarios,
  runCustomDemoFaultJob,
  runSimulatorScenario,
  type SimulatorScenarioId,
} from '../../../../../lib/delivery/simulator.js';

const VALID_SCENARIOS: SimulatorScenarioId[] = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];

export async function POST(request: Request) {
  const adminCheck = requireAdminRequest(request);
  if (!adminCheck.ok) {
    return adminCheck.response!;
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { success: false, message: 'Invalid JSON request body.', data: null },
      { status: 400 }
    );
  }

  if (body?.demoMode !== true) {
    return Response.json(
      {
        success: false,
        message: 'Demo Mode must be explicitly enabled (demoMode: true) before running fault simulations.',
        data: null,
      },
      { status: 400 }
    );
  }

  const action = String(body?.action || 'RUN_ALL').trim().toUpperCase();

  try {
    if (action === 'RESET_SIM_BREAKERS') {
      resetBreaker(undefined, 'sim');
      return Response.json({
        success: true,
        message: 'Isolated simulator circuit breakers reset to CLOSED.',
        data: { reset: true },
      });
    }

    if (action === 'RUN_SCENARIO') {
      const scenarioId = String(body?.scenarioId || '').trim().toLowerCase() as SimulatorScenarioId;
      if (!VALID_SCENARIOS.includes(scenarioId)) {
        return Response.json(
          {
            success: false,
            message: 'Invalid scenarioId. Must be one of a, b, c, d, e, f, g.',
            data: null,
          },
          { status: 400 }
        );
      }
      const result = await runSimulatorScenario(scenarioId);
      return Response.json({
        success: true,
        message: result.passed
          ? `Scenario (${scenarioId}) passed.`
          : `Scenario (${scenarioId}) completed with failure.`,
        data: { result },
      });
    }

    if (action === 'INJECT_FAULTS') {
      const faults = body?.faults && typeof body.faults === 'object' ? body.faults : {};
      const priority = ['CRITICAL', 'HIGH', 'NORMAL', 'LOW'].includes(String(body?.priority || '').toUpperCase())
        ? (String(body.priority).toUpperCase() as 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW')
        : 'CRITICAL';
      const job = await runCustomDemoFaultJob(faults, priority);
      return Response.json({
        success: true,
        message: `Isolated demo fault simulation finished in state ${job.state}.`,
        data: { job },
      });
    }

    if (action === 'RUN_ALL') {
      const summary = await runAllSimulatorScenarios();
      return Response.json({
        success: true,
        message: summary.allPassed
          ? `All ${summary.totalCount} delivery failure scenarios passed.`
          : `${summary.passedCount}/${summary.totalCount} scenarios passed.`,
        data: summary,
      });
    }

    return Response.json(
      {
        success: false,
        message: `Unsupported simulator action "${action}".`,
        data: null,
      },
      { status: 400 }
    );
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Failure simulator execution failed.',
        data: null,
      },
      { status: 500 }
    );
  }
}
