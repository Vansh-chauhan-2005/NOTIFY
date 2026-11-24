import { authenticateUserRequest } from '../../../../../lib/auth/requestAuth.js';
import { requireAdminRequest } from '../../../../../lib/telemetry/adminAuth.js';
import { getProvenanceQuarantineAndStats } from '../../../../../lib/provenance/store.js';
import { provenanceJson } from '../../../../../lib/provenance/http.js';

export async function GET(request: Request) {
  const adminCheck = requireAdminRequest(request);
  let isAdmin = adminCheck.ok;
  let userId: string | undefined;

  if (!isAdmin) {
    const userCheck = authenticateUserRequest(request);
    if (!userCheck.ok || !userCheck.user) {
      return userCheck.response!;
    }
    isAdmin = String(userCheck.user.role || '').toUpperCase() === 'ADMIN';
    userId = userCheck.user.userId;
  }

  try {
    const url = new URL(request.url);
    const limit = Number(url.searchParams.get('limit') || '100');
    const data = await getProvenanceQuarantineAndStats({
      userId,
      isAdmin,
      limit,
    });

    return provenanceJson({
      success: true,
      message: 'Provenance verification statistics and quarantine records loaded.',
      data,
    });
  } catch (err: any) {
    return provenanceJson(
      { success: false, message: err?.message || 'Unable to load provenance quarantine.' },
      500
    );
  }
}
