import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { getEphemeralStats, getEphemeralTombstones } from '../../../../../lib/ephemeral/ephemeralStore.js';
import { ephemeralJson } from '../../../../../lib/ephemeral/http.js';

export async function GET(request: Request) {
  const auth = requireAdminRequest(request);
  if (!auth.ok) {
    return auth.response!;
  }

  try {
    const stats = getEphemeralStats();
    const tombstones = getEphemeralTombstones({ includeDemo: true, limit: 25 });

    return ephemeralJson({
      success: true,
      message: 'Ephemeral data telemetry stats loaded.',
      data: {
        stats,
        recentTombstones: tombstones,
      },
    });
  } catch (err: any) {
    return ephemeralJson(
      {
        success: false,
        message: err?.message || 'Unable to compute ephemeral telemetry stats.',
      },
      500
    );
  }
}
