import { APP_CATALOG, CatalogApp } from '../../data/appCatalog';

export type AppDetectionStatus = 'Detected' | 'Launchable' | 'Marked by you' | 'Unknown';

export type DeepLinkConfirmation = 'yes' | 'no' | 'untested';

export interface AppCatalogState {
  appId: string;
  markedByUser: boolean;
  deepLinkConfirmed: DeepLinkConfirmation;
  relatedAppDetected: boolean;
  updatedAt: string;
}

export interface DeviceScanResult {
  apiSupported: boolean;
  relatedAppsCount: number;
  detectedIds: string[];
  message: string;
  scannedAt: string;
}

const STORAGE_PREFIX = 'aegis_catalog_states_v1_';

function isSafeStorageKey(userId?: string): string {
  const clean = (userId || 'guest').replace(/[^a-zA-Z0-9_-]/g, '_');
  return `${STORAGE_PREFIX}${clean}`;
}

export function loadLocalCatalogStates(userId?: string): Record<string, AppCatalogState> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(isSafeStorageKey(userId));
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return {};
    return parsed as Record<string, AppCatalogState>;
  } catch {
    return {};
  }
}

export function saveLocalCatalogStates(
  userId: string | undefined,
  states: Record<string, AppCatalogState>
): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(isSafeStorageKey(userId), JSON.stringify(states));
  } catch {
    // Non-fatal if storage quota is full
  }
}

export function clearLocalCatalogStates(userId?: string): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(isSafeStorageKey(userId));
  } catch {
    // Ignore
  }
}

/**
 * Honest status resolution per app:
 * 1. "Detected": ONLY if navigator.getInstalledRelatedApps() positively reported it
 * 2. "Marked by you": user toggled "I use this app" OR confirmed "Yes" after deep-link test
 * 3. "Launchable": a deepLink exists so the app can be opened (never claims installation)
 * 4. "Unknown": none of the above
 */
export function resolveHonestAppStatus(
  app: CatalogApp,
  state?: AppCatalogState
): AppDetectionStatus {
  if (state?.relatedAppDetected) {
    return 'Detected';
  }
  if (state?.markedByUser || state?.deepLinkConfirmed === 'yes') {
    return 'Marked by you';
  }
  if (app.deepLink && app.deepLink.trim().length > 0) {
    return 'Launchable';
  }
  return 'Unknown';
}

export function isRelatedAppsApiSupported(): boolean {
  if (typeof navigator === 'undefined') return false;
  return typeof (navigator as any).getInstalledRelatedApps === 'function';
}

/**
 * Best-effort device scan restricted strictly to the 30-app catalog.
 * Never scans outside the catalog, never blocks the UI thread, and always reports API limits honestly.
 */
export async function scanCatalogOnDevice(): Promise<DeviceScanResult> {
  const scannedAt = new Date().toISOString();

  if (typeof navigator === 'undefined') {
    return {
      apiSupported: false,
      relatedAppsCount: 0,
      detectedIds: [],
      message: 'Device detection can only run in an interactive browser session.',
      scannedAt,
    };
  }

  const getInstalledRelatedApps = (navigator as any).getInstalledRelatedApps;
  if (typeof getInstalledRelatedApps !== 'function') {
    return {
      apiSupported: false,
      relatedAppsCount: 0,
      detectedIds: [],
      message:
        'This browser does not support navigator.getInstalledRelatedApps(). Apps with URL schemes remain marked "Launchable", or you can toggle "I use this app" manually.',
      scannedAt,
    };
  }

  try {
    const relatedApps: Array<{ id?: string; platform?: string; url?: string }> =
      await Promise.race([
        getInstalledRelatedApps.call(navigator),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Device scan timed out.')), 4000)
        ),
      ]);

    const detectedIds: string[] = [];
    if (Array.isArray(relatedApps) && relatedApps.length > 0) {
      const catalogMatchers = APP_CATALOG.map((app) => ({
        id: app.id,
        nameLower: app.name.toLowerCase(),
        hostLower: (() => {
          try {
            return new URL(app.webUrl).hostname.toLowerCase();
          } catch {
            return '';
          }
        })(),
      }));

      for (const related of relatedApps) {
        const relId = String(related?.id || '').toLowerCase();
        const relUrl = String(related?.url || '').toLowerCase();
        const matched = catalogMatchers.find(
          (c) =>
            (relId && (relId.includes(c.id) || relId.includes(c.nameLower))) ||
            (relUrl && c.hostLower && relUrl.includes(c.hostLower))
        );
        if (matched && !detectedIds.includes(matched.id)) {
          detectedIds.push(matched.id);
        }
      }
    }

    return {
      apiSupported: true,
      relatedAppsCount: Array.isArray(relatedApps) ? relatedApps.length : 0,
      detectedIds,
      message:
        detectedIds.length > 0
          ? `Found ${detectedIds.length} related catalog app(s) declared in the web manifest.`
          : 'Browser supports getInstalledRelatedApps(), and 0 related installed apps matched this origin’s web manifest. That is normal for web apps — use "Test deep link" or "I use this app" instead.',
      scannedAt,
    };
  } catch (err: any) {
    return {
      apiSupported: true,
      relatedAppsCount: 0,
      detectedIds: [],
      message:
        err?.message ||
        'Related-app query could not complete in this browser context. You can still test deep links or mark apps manually.',
      scannedAt,
    };
  }
}

/**
 * Open a safe external URL or deep link strictly inside a user click handler without calling window.open or window.alert.
 */
export function triggerSafeSchemeOrWebLink(targetUrl: string): boolean {
  if (typeof document === 'undefined' || !targetUrl) return false;
  try {
    const trimmed = targetUrl.trim();
    // Block unsafe javascript: or data: URIs
    if (/^(javascript|data|vbscript):/i.test(trimmed)) {
      return false;
    }
    const anchor = document.createElement('a');
    anchor.href = trimmed;
    if (/^https?:\/\//i.test(trimmed)) {
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer';
    }
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    return true;
  } catch {
    return false;
  }
}
