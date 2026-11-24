export const NO_STORE_HEADERS: Record<string, string> = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  Expires: '0',
};

export function ephemeralJson(
  payload: { success: boolean; message: string; data?: any },
  status: number = 200
): Response {
  return Response.json(
    {
      success: payload.success,
      message: payload.message,
      data: payload.data ?? null,
    },
    {
      status,
      headers: NO_STORE_HEADERS,
    }
  );
}
