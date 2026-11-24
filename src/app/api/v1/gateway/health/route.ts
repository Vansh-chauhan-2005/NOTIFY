import { getGlobalLoadController } from '../../../../../lib/gateway/loadShedder.js';
import { getGatewayStore } from '../../../../../lib/gateway/store/index.js';

/**
 * Public lightweight gateway health check (contains zero sensitive data, keys, or PII).
 */
export async function GET(): Promise<Response> {
  const loadLevel = getGlobalLoadController().getCurrentLevel();
  const storeMode = getGatewayStore().mode;

  return Response.json({
    success: true,
    message: 'Ingress gateway operational.',
    data: {
      status: loadLevel === 'CRITICAL' ? 'degraded' : 'ok',
      loadLevel,
      storeMode,
      timestamp: new Date().toISOString(),
    },
  });
}
