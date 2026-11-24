import webpush from 'web-push';

export interface WebPushPayload {
  title: string;
  body: string;
  icon?: string;
  badge?: string;
  data?: Record<string, any>;
  tag?: string;
}

export interface StoredSubscription {
  endpoint: string;
  expirationTime?: number | null;
  keys: {
    p256dh: string;
    auth: string;
  };
}

let vapidKeys = {
  publicKey: process.env.VAPID_PUBLIC_KEY?.trim() || '',
  privateKey: process.env.VAPID_PRIVATE_KEY?.trim() || '',
};

// Generate deterministic or dynamic VAPID keys if none configured
if (!vapidKeys.publicKey || !vapidKeys.privateKey) {
  try {
    const generated = webpush.generateVAPIDKeys();
    vapidKeys = generated;
    console.log('[WebPush] Generated in-memory VAPID keys for browser push subscriptions');
  } catch (err) {
    console.warn('[WebPush] Error generating VAPID keys:', err);
  }
}

// In-memory registry of active device subscriptions
const globalSubscriptionStore = new Map<string, StoredSubscription>();

export function getVapidPublicKey(): string {
  return vapidKeys.publicKey;
}

export function isWebPushConfigured(): boolean {
  return Boolean(vapidKeys.publicKey && vapidKeys.privateKey);
}

// Initialize VAPID details with webpush library
if (vapidKeys.publicKey && vapidKeys.privateKey) {
  try {
    webpush.setVapidDetails(
      'mailto:admin@aegis-sentinel.internal',
      vapidKeys.publicKey,
      vapidKeys.privateKey
    );
  } catch (err: any) {
    console.warn('[WebPush] VAPID details setup warning:', err.message);
  }
}

export function registerDeviceSubscription(userId: string, subscription: StoredSubscription) {
  globalSubscriptionStore.set(userId, subscription);
  // Also register under general broadcast key if applicable
  globalSubscriptionStore.set(subscription.endpoint, subscription);
  console.log(`[WebPush] Device subscription registered for user ${userId}. Total devices: ${globalSubscriptionStore.size}`);
}

export function getAllDeviceSubscriptions(): StoredSubscription[] {
  // Deduplicate by endpoint
  const map = new Map<string, StoredSubscription>();
  for (const sub of globalSubscriptionStore.values()) {
    map.set(sub.endpoint, sub);
  }
  return Array.from(map.values());
}

export async function sendWebPushAlert(
  subscription: StoredSubscription,
  payload: WebPushPayload
): Promise<{ success: boolean; statusCode?: number; error?: string }> {
  try {
    const stringified = JSON.stringify(payload);
    const result = await webpush.sendNotification(subscription as any, stringified);
    return {
      success: true,
      statusCode: result.statusCode,
    };
  } catch (err: any) {
    console.warn(`[WebPush Alert] Failed sending to endpoint ${subscription.endpoint.slice(0, 30)}...:`, err.message);
    // If subscription is expired or unsubscribed (404/410), remove it
    if (err.statusCode === 404 || err.statusCode === 410) {
      globalSubscriptionStore.delete(subscription.endpoint);
    }
    return {
      success: false,
      statusCode: err.statusCode,
      error: err.message,
    };
  }
}

export async function broadcastWebPushAlert(payload: WebPushPayload): Promise<{
  successCount: number;
  failureCount: number;
  totalSubscribers: number;
}> {
  const subscriptions = getAllDeviceSubscriptions();
  let successCount = 0;
  let failureCount = 0;

  await Promise.all(
    subscriptions.map(async (sub) => {
      const res = await sendWebPushAlert(sub, payload);
      if (res.success) {
        successCount++;
      } else {
        failureCount++;
      }
    })
  );

  console.log(`[WebPush Broadcast] Dispatched alert to ${subscriptions.length} devices (${successCount} succeeded, ${failureCount} failed)`);
  return {
    successCount,
    failureCount,
    totalSubscribers: subscriptions.length,
  };
}
