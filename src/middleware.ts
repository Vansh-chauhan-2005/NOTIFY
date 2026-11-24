export async function middleware(request: Request) {
  const url = new URL(request.url);
  const origin = request.headers.get('origin');

  const responseHeaders = new Headers();
  responseHeaders.set('X-Content-Type-Options', 'nosniff');
  responseHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  responseHeaders.set('X-Permitted-Cross-Domain-Policies', 'none');
  responseHeaders.set('Vary', 'Origin');

  if (request.method === 'OPTIONS') {
    if (origin && origin === url.origin) {
      responseHeaders.set('Access-Control-Allow-Origin', origin);
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
      return new Response(null, { status: 204, headers: responseHeaders });
    }
    return new Response(null, { status: 403, headers: responseHeaders });
  }

  return null; // Continue processing
}

export const config = {
  matcher: ['/api/v1/:path*'],
};
