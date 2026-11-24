/* Service Worker for WebPush instant device-level notifications */
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Zero-leak guarantee: never cache or intercept ephemeral message/key API responses
self.addEventListener('fetch', (event) => {
  try {
    const reqUrl = new URL(event.request.url);
    if (reqUrl.pathname.startsWith('/api/v1/ephemeral')) {
      return;
    }
  } catch {
    // Ignore malformed URLs and allow normal browser fetch
  }
});

self.addEventListener('push', (event) => {
  let data = {
    title: 'Aegis Sentinel Alert',
    body: 'High-priority notification fallback triggered.',
    icon: '/assets/logo.png',
    badge: '/assets/logo.png',
    data: { url: '/' },
  };

  if (event.data) {
    try {
      const parsed = event.data.json();
      data = { ...data, ...parsed };
    } catch {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body,
    icon: data.icon || '/assets/logo.png',
    badge: data.badge || '/assets/logo.png',
    vibrate: [200, 100, 200, 100, 200],
    tag: data.tag || 'aegis-notification-' + Date.now(),
    renotify: true,
    requireInteraction: true,
    data: data.data || { url: '/' },
  };

  event.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const urlToOpen = (event.notification.data && event.notification.data.url) || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.includes(urlToOpen) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});
