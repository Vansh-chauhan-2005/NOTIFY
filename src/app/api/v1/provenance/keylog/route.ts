import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { getKeyLogPage, verifyKeyLogChain } from '../../../../../lib/provenance/store.js';
import { provenanceJson } from '../../../../../lib/provenance/http.js';

export async function GET(request: Request) {
  const adminCheck = requireAdminRequest(request);
  if (!adminCheck.ok) {
    const userCheck = authenticateUserRequest(request);
    if (!userCheck.ok) {
      return userCheck.response!;
    }
  }

  try {
    const url = new URL(request.url);
    const offset = Number(url.searchParams.get('offset') || '0');
    const limit = Number(url.searchParams.get('limit') || '100');
    const userId = url.searchParams.get('userId')?.trim() || undefined;
    const verifyParam = url.searchParams.get('verify');

    const page = await getKeyLogPage({ offset, limit, userId });
    const verification =
      verifyParam === '1' || verifyParam === 'true'
        ? await verifyKeyLogChain()
        : undefined;

    return provenanceJson({
      success: true,
      message: `Loaded ${page.entries.length} hash-chained key transparency log entries.`,
      data: {
        entries: page.entries,
        total: page.total,
        headHash: page.headHash,
        ...(verification ? { verification } : {}),
      },
    });
  } catch (err: any) {
    return provenanceJson(
      { success: false, message: err?.message || 'Failed to read key transparency log.' },
      500
    );
  }
}
