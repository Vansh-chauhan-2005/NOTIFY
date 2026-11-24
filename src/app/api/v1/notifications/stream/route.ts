import { activeSocketConnections } from '../../../../../lib/queue/worker.js';
import { verifySessionToken } from '../../../../../lib/auth/requestAuth.js';

export async function GET(request: Request) {
  const url = new URL(request.url);
  const authHeader = request.headers.get('authorization');
  const bearerToken =
    authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const queryToken = url.searchParams.get('token') || '';
  const caller = verifySessionToken(bearerToken || queryToken);

  if (!caller) {
    return Response.json(
      {
        success: false,
        error: 'Unauthorized',
        message: 'Authentication required to access notification stream.',
      },
      { status: 401 }
    );
  }

  const requestedUserId = url.searchParams.get('userId');
  const isAdmin = caller.role === 'ADMIN';
  if (requestedUserId && !isAdmin && requestedUserId !== caller.userId) {
    return Response.json(
      {
        success: false,
        error: 'Forbidden',
        message: 'Cannot subscribe to another user\'s notification stream.',
      },
      { status: 403 }
    );
  }

  const userId = isAdmin && requestedUserId ? requestedUserId : caller.userId;

  // Server-Sent Events (SSE) fallback stream or WebSocket connection handshake info
  const acceptHeader = request.headers.get('accept') || '';

  if (acceptHeader.includes('text/event-stream')) {
    let closed = false;
    const stream = new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder();

        const sendEvent = (data: string) => {
          if (closed) return;
          try {
            controller.enqueue(encoder.encode(`data: ${data}\n\n`));
          } catch {}
        };

        // Register client in active connection registry
        const socketId = `sse_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
        let sockets = activeSocketConnections.get(userId);
        if (!sockets) {
          sockets = new Set();
          activeSocketConnections.set(userId, sockets);
        }
        sockets.add({ id: socketId, send: sendEvent });

        // Initial connect event
        sendEvent(
          JSON.stringify({
            type: 'CONNECTION_ESTABLISHED',
            socketId,
            userId,
            transport: 'SSE_FALLBACK',
            timestamp: new Date().toISOString(),
          })
        );

        request.signal.addEventListener('abort', () => {
          closed = true;
          const userSockets = activeSocketConnections.get(userId);
          if (userSockets) {
            for (const s of Array.from(userSockets)) {
              if (s.id === socketId) userSockets.delete(s);
            }
          }
        });
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      },
    });
  }

  // Regular JSON info for WebSocket connection parameters
  const userSockets = activeSocketConnections.get(userId);
  const activeCount = userSockets ? userSockets.size : 0;

  return Response.json({
    status: 'ONLINE',
    streamEndpoint: '/ws',
    protocol: 'ws:// or wss://',
    sseFallback: '/api/v1/notifications/stream?userId=' + encodeURIComponent(userId),
    activeConnectionsForUser: activeCount,
    ...(isAdmin
      ? {
          totalGlobalConnections: Array.from(activeSocketConnections.values()).reduce(
            (acc, s) => acc + s.size,
            0
          ),
        }
      : {}),
    handshakeGuide: 'Connect via WebSocket to ws://<host>/ws with query param ?token=<jwt>',
  });
}
