export interface ConnectedApp {
  id: string;
  name: string;
  category: 'Dev' | 'Payments' | 'Chat' | 'Security' | 'Custom';
  description: string;
  iconName: string; // lucide icon identifier
  status: 'CONNECTED' | 'DISCONNECTED';
  enabled: boolean;
  webhookUrl: string;
  apiKey: string;
  rules: {
    urgencyOverride: 'AUTO' | 'HIGH_ONLY' | 'ALL_CRITICAL' | 'NORMAL';
    filterDuplicates: boolean;
    duplicateSensitivity: 'STANDARD' | 'STRICT' | 'RELAXED';
    forwardToBackup: boolean; // escalate to email/push if missed
    quietHoursMuted: boolean;
  };
  stats: {
    totalReceived: number;
    filteredCount: number;
    lastReceivedAt?: string;
  };
}

export const defaultConnectedApps: ConnectedApp[] = [
  {
    id: 'slack',
    name: 'Slack',
    category: 'Chat',
    description: 'Direct mentions, security channel alerts, and incident room updates',
    iconName: 'MessageSquare',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=slack',
    apiKey: 'aegis_app_slack_live_9921',
    rules: {
      urgencyOverride: 'AUTO',
      filterDuplicates: true,
      duplicateSensitivity: 'STANDARD',
      forwardToBackup: true,
      quietHoursMuted: false,
    },
    stats: {
      totalReceived: 42,
      filteredCount: 11,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    },
  },
  {
    id: 'github',
    name: 'GitHub',
    category: 'Dev',
    description: 'Security vulnerability alerts (Dependabot), CI/CD pipeline failures, and critical PRs',
    iconName: 'GitBranch',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=github',
    apiKey: 'aegis_app_gh_sec_4102',
    rules: {
      urgencyOverride: 'HIGH_ONLY',
      filterDuplicates: true,
      duplicateSensitivity: 'STRICT',
      forwardToBackup: true,
      quietHoursMuted: true,
    },
    stats: {
      totalReceived: 89,
      filteredCount: 34,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    },
  },
  {
    id: 'stripe',
    name: 'Stripe',
    category: 'Payments',
    description: 'High-value transactions, fraudulent charge disputes, and failed payouts',
    iconName: 'CreditCard',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=stripe',
    apiKey: 'aegis_app_stripe_pay_7721',
    rules: {
      urgencyOverride: 'ALL_CRITICAL',
      filterDuplicates: false,
      duplicateSensitivity: 'STANDARD',
      forwardToBackup: true,
      quietHoursMuted: false,
    },
    stats: {
      totalReceived: 18,
      filteredCount: 0,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    },
  },
  {
    id: 'jira',
    name: 'Jira & Atlassian',
    category: 'Dev',
    description: 'P0 incident escalation tickets and blocker bug assignments',
    iconName: 'CheckSquare',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=jira',
    apiKey: 'aegis_app_jira_prod_3391',
    rules: {
      urgencyOverride: 'AUTO',
      filterDuplicates: true,
      duplicateSensitivity: 'STANDARD',
      forwardToBackup: false,
      quietHoursMuted: true,
    },
    stats: {
      totalReceived: 27,
      filteredCount: 8,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    },
  },
  {
    id: 'google_workspace',
    name: 'Google Workspace',
    category: 'Security',
    description: 'Admin audit logs, unexpected new admin privileges, and file sharing warnings',
    iconName: 'Mail',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=google_workspace',
    apiKey: 'aegis_app_gsuite_sec_1092',
    rules: {
      urgencyOverride: 'HIGH_ONLY',
      filterDuplicates: true,
      duplicateSensitivity: 'STANDARD',
      forwardToBackup: true,
      quietHoursMuted: false,
    },
    stats: {
      totalReceived: 14,
      filteredCount: 2,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    },
  },
  {
    id: 'custom_api',
    name: 'Custom Webhook / Your App',
    category: 'Custom',
    description: 'Connect any website, mobile app, microservice, or backend script',
    iconName: 'Globe',
    status: 'CONNECTED',
    enabled: true,
    webhookUrl: '/api/v1/integrations/webhook?appId=custom_api',
    apiKey: 'aegis_app_custom_hook_5580',
    rules: {
      urgencyOverride: 'AUTO',
      filterDuplicates: true,
      duplicateSensitivity: 'STANDARD',
      forwardToBackup: true,
      quietHoursMuted: false,
    },
    stats: {
      totalReceived: 5,
      filteredCount: 1,
      lastReceivedAt: new Date(Date.now() - 1000 * 60 * 300).toISOString(),
    },
  },
];

// Global in-memory registry
declare global {
  var aegisIntegrations: ConnectedApp[] | undefined;
}

if (!global.aegisIntegrations) {
  global.aegisIntegrations = [...defaultConnectedApps];
}

export function getConnectedApps(): ConnectedApp[] {
  return global.aegisIntegrations || defaultConnectedApps;
}

export function getConnectedAppById(id: string): ConnectedApp | undefined {
  return getConnectedApps().find((a) => a.id === id);
}

export function updateConnectedApp(id: string, patch: Partial<ConnectedApp>): ConnectedApp | null {
  const apps = getConnectedApps();
  const index = apps.findIndex((a) => a.id === id);
  if (index === -1) return null;

  apps[index] = {
    ...apps[index],
    ...patch,
    rules: {
      ...apps[index].rules,
      ...(patch.rules || {}),
    },
    stats: {
      ...apps[index].stats,
      ...(patch.stats || {}),
    },
  };

  return apps[index];
}

export function addConnectedApp(newApp: Omit<ConnectedApp, 'id' | 'webhookUrl' | 'apiKey' | 'stats'>): ConnectedApp {
  const apps = getConnectedApps();
  const id = `custom_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
  const fullApp: ConnectedApp = {
    ...newApp,
    id,
    webhookUrl: `/api/v1/integrations/webhook?appId=${id}`,
    apiKey: `aegis_app_custom_${Date.now()}`,
    stats: {
      totalReceived: 0,
      filteredCount: 0,
    },
  };
  apps.push(fullApp);
  return fullApp;
}
