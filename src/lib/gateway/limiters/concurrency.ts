export interface ConcurrencyAcquireResult {
  allowed: boolean;
  reason?: string;
  userActive: number;
  routeActive: number;
  globalActive: number;
  release: () => void;
}

/**
 * Tracks active in-flight requests globally, per route group, and per user/IP key.
 * Always exposes an idempotent `release()` handle so error paths never leak slots.
 */
export class ConcurrencyLimiter {
  private globalCount = 0;
  private readonly perRoute = new Map<string, number>();
  private readonly perKey = new Map<string, number>();

  acquire(params: {
    routeGroup: string;
    userOrIpKey: string;
    maxPerUser: number;
    maxPerRoute: number;
    maxGlobal?: number;
  }): ConcurrencyAcquireResult {
    const routeActive = this.perRoute.get(params.routeGroup) || 0;
    const userActive = this.perKey.get(params.userOrIpKey) || 0;
    const maxGlobal = params.maxGlobal ?? 1000;

    if (this.globalCount >= maxGlobal) {
      return {
        allowed: false,
        reason: `Global concurrency cap (${maxGlobal}) reached.`,
        userActive,
        routeActive,
        globalActive: this.globalCount,
        release: () => {},
      };
    }

    if (routeActive >= params.maxPerRoute) {
      return {
        allowed: false,
        reason: `Route concurrency cap (${params.maxPerRoute}) reached for ${params.routeGroup}.`,
        userActive,
        routeActive,
        globalActive: this.globalCount,
        release: () => {},
      };
    }

    if (userActive >= params.maxPerUser) {
      return {
        allowed: false,
        reason: `Per-client concurrency cap (${params.maxPerUser}) reached.`,
        userActive,
        routeActive,
        globalActive: this.globalCount,
        release: () => {},
      };
    }

    this.globalCount += 1;
    this.perRoute.set(params.routeGroup, routeActive + 1);
    this.perKey.set(params.userOrIpKey, userActive + 1);

    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      this.globalCount = Math.max(0, this.globalCount - 1);

      const curRoute = this.perRoute.get(params.routeGroup) || 0;
      if (curRoute <= 1) {
        this.perRoute.delete(params.routeGroup);
      } else {
        this.perRoute.set(params.routeGroup, curRoute - 1);
      }

      const curKey = this.perKey.get(params.userOrIpKey) || 0;
      if (curKey <= 1) {
        this.perKey.delete(params.userOrIpKey);
      } else {
        this.perKey.set(params.userOrIpKey, curKey - 1);
      }
    };

    return {
      allowed: true,
      userActive: userActive + 1,
      routeActive: routeActive + 1,
      globalActive: this.globalCount,
      release,
    };
  }

  getGlobalCount(): number {
    return this.globalCount;
  }

  getRouteCount(routeGroup: string): number {
    return this.perRoute.get(routeGroup) || 0;
  }

  getClientCount(userOrIpKey: string): number {
    return this.perKey.get(userOrIpKey) || 0;
  }

  reset(): void {
    this.globalCount = 0;
    this.perRoute.clear();
    this.perKey.clear();
  }
}
