export type AppCategory =
  | 'Messaging'
  | 'Email'
  | 'Social'
  | 'Work'
  | 'Developer'
  | 'Finance'
  | 'Shopping'
  | 'Entertainment';

export type AppConnectionType =
  | 'webhook'
  | 'whatsapp'
  | 'telegram'
  | 'discord'
  | 'slack'
  | 'github'
  | 'manual'
  | 'launch-only';

export type SiIconKey =
  | 'SiWhatsapp'
  | 'SiTelegram'
  | 'SiGmail'
  | 'SiInstagram'
  | 'SiX'
  | 'SiDiscord'
  | 'SiGithub'
  | 'SiGitlab'
  | 'SiJira'
  | 'SiNotion'
  | 'SiTrello'
  | 'SiGooglecalendar'
  | 'SiZoom'
  | 'SiGooglemeet'
  | 'SiPaytm'
  | 'SiGooglepay'
  | 'SiPhonepe'
  | 'SiSwiggy'
  | 'SiZomato'
  | 'SiSpotify'
  | 'SiYoutube'
  | 'SiNetflix'
  | 'SiUber';

export interface CatalogApp {
  id: string;
  name: string;
  category: AppCategory;
  brandColor: string;
  icon: SiIconKey | null;
  letterFallback: string;
  deepLink?: string;
  webUrl: string;
  connectionType: AppConnectionType;
  description: string;
}

export const APP_CATEGORIES: AppCategory[] = [
  'Messaging',
  'Email',
  'Social',
  'Work',
  'Developer',
  'Finance',
  'Shopping',
  'Entertainment',
];

export const APP_CATALOG: CatalogApp[] = [
  {
    id: 'whatsapp',
    name: 'WhatsApp',
    category: 'Messaging',
    brandColor: '#25D366',
    icon: 'SiWhatsapp',
    letterFallback: 'W',
    deepLink: 'whatsapp://send',
    webUrl: 'https://web.whatsapp.com',
    connectionType: 'whatsapp',
    description: 'Connect Meta WhatsApp Business Cloud API webhooks or dispatch verified WhatsApp fallback alerts.',
  },
  {
    id: 'telegram',
    name: 'Telegram',
    category: 'Messaging',
    brandColor: '#26A5E4',
    icon: 'SiTelegram',
    letterFallback: 'T',
    deepLink: 'tg://resolve',
    webUrl: 'https://web.telegram.org',
    connectionType: 'telegram',
    description: 'Connect a personal Telegram Bot via BotFather to forward bot messages securely.',
  },
  {
    id: 'discord',
    name: 'Discord',
    category: 'Messaging',
    brandColor: '#5865F2',
    icon: 'SiDiscord',
    letterFallback: 'D',
    deepLink: 'discord://',
    webUrl: 'https://discord.com/app',
    connectionType: 'discord',
    description: 'Send signed alerts to Aegis or bridge events with a Discord server webhook.',
  },
  {
    id: 'gmail',
    name: 'Gmail',
    category: 'Email',
    brandColor: '#EA4335',
    icon: 'SiGmail',
    letterFallback: 'G',
    deepLink: 'googlegmail://',
    webUrl: 'https://mail.google.com',
    connectionType: 'manual',
    description: 'Open Gmail on web/app and test inbox notification routing manually.',
  },
  {
    id: 'email-alerts',
    name: 'Email / Gmail Alerts',
    category: 'Email',
    brandColor: '#D9468F',
    icon: 'SiGmail',
    letterFallback: 'EM',
    deepLink: 'googlegmail://',
    webUrl: 'https://mail.google.com',
    connectionType: 'webhook',
    description: 'Forward Gmail Apps Script, Zapier, Mailgun, or SendGrid inbound emails over a signed Aegis webhook.',
  },
  {
    id: 'outlook',
    name: 'Outlook',
    category: 'Email',
    brandColor: '#0078D4',
    icon: null,
    letterFallback: 'OL',
    deepLink: 'ms-outlook://',
    webUrl: 'https://outlook.live.com',
    connectionType: 'manual',
    description: 'Launch Microsoft Outlook or simulate email priority notifications.',
  },
  {
    id: 'instagram',
    name: 'Instagram',
    category: 'Social',
    brandColor: '#E4405F',
    icon: 'SiInstagram',
    letterFallback: 'IG',
    deepLink: 'instagram://app',
    webUrl: 'https://www.instagram.com',
    connectionType: 'launch-only',
    description: 'Quick-launch Instagram and track whether you use it on this device.',
  },
  {
    id: 'x',
    name: 'X',
    category: 'Social',
    brandColor: '#16161D',
    icon: 'SiX',
    letterFallback: 'X',
    deepLink: 'twitter://timeline',
    webUrl: 'https://x.com',
    connectionType: 'launch-only',
    description: 'Open X on your device or test social mention alerts.',
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    category: 'Social',
    brandColor: '#0A66C2',
    icon: null,
    letterFallback: 'in',
    deepLink: 'linkedin://feed',
    webUrl: 'https://www.linkedin.com',
    connectionType: 'launch-only',
    description: 'Launch LinkedIn and send simulated professional alert notifications.',
  },
  {
    id: 'slack',
    name: 'Slack',
    category: 'Work',
    brandColor: '#4A154B',
    icon: null,
    letterFallback: 'SL',
    deepLink: 'slack://open',
    webUrl: 'https://app.slack.com',
    connectionType: 'slack',
    description: 'Connect Slack workflows via signed webhook or bridge to a Slack incoming webhook.',
  },
  {
    id: 'microsoft-teams',
    name: 'Microsoft Teams',
    category: 'Work',
    brandColor: '#6264A7',
    icon: null,
    letterFallback: 'MT',
    deepLink: 'msteams://',
    webUrl: 'https://teams.microsoft.com',
    connectionType: 'webhook',
    description: 'Receive Teams workflow alerts through your dedicated HMAC-signed ingest URL.',
  },
  {
    id: 'notion',
    name: 'Notion',
    category: 'Work',
    brandColor: '#1F1F24',
    icon: 'SiNotion',
    letterFallback: 'N',
    deepLink: 'notion://',
    webUrl: 'https://www.notion.so',
    connectionType: 'webhook',
    description: 'Receive Notion automation webhook events verified by HMAC-SHA256.',
  },
  {
    id: 'trello',
    name: 'Trello',
    category: 'Work',
    brandColor: '#0052CC',
    icon: 'SiTrello',
    letterFallback: 'TR',
    webUrl: 'https://trello.com',
    connectionType: 'webhook',
    description: 'Connect Trello board webhooks directly to your Aegis ingest endpoint.',
  },
  {
    id: 'google-calendar',
    name: 'Google Calendar',
    category: 'Work',
    brandColor: '#4285F4',
    icon: 'SiGooglecalendar',
    letterFallback: 'GC',
    deepLink: 'googlecalendar://',
    webUrl: 'https://calendar.google.com',
    connectionType: 'manual',
    description: 'Quick-launch Calendar and test reminder alert delivery.',
  },
  {
    id: 'zoom',
    name: 'Zoom',
    category: 'Work',
    brandColor: '#0B5CFF',
    icon: 'SiZoom',
    letterFallback: 'ZM',
    deepLink: 'zoommtg://',
    webUrl: 'https://zoom.us',
    connectionType: 'launch-only',
    description: 'Launch Zoom meetings or trigger simulated meeting alert tests.',
  },
  {
    id: 'google-meet',
    name: 'Google Meet',
    category: 'Work',
    brandColor: '#00897B',
    icon: 'SiGooglemeet',
    letterFallback: 'GM',
    webUrl: 'https://meet.google.com',
    connectionType: 'launch-only',
    description: 'Open Google Meet in your browser and run simulated alert checks.',
  },
  {
    id: 'github',
    name: 'GitHub',
    category: 'Developer',
    brandColor: '#181717',
    icon: 'SiGithub',
    letterFallback: 'GH',
    deepLink: 'github://',
    webUrl: 'https://github.com',
    connectionType: 'github',
    description: 'Connect repository webhooks with HMAC-SHA256 signature verification.',
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    category: 'Developer',
    brandColor: '#FC6D26',
    icon: 'SiGitlab',
    letterFallback: 'GL',
    webUrl: 'https://gitlab.com',
    connectionType: 'webhook',
    description: 'Stream GitLab CI/CD and issue alerts over a signed Aegis ingest URL.',
  },
  {
    id: 'jira',
    name: 'Jira',
    category: 'Developer',
    brandColor: '#0052CC',
    icon: 'SiJira',
    letterFallback: 'JR',
    webUrl: 'https://www.atlassian.com/software/jira',
    connectionType: 'webhook',
    description: 'Route Jira incident and ticket webhooks through Aegis priority scoring.',
  },
  {
    id: 'paytm',
    name: 'Paytm',
    category: 'Finance',
    brandColor: '#00BAF2',
    icon: 'SiPaytm',
    letterFallback: 'PT',
    deepLink: 'paytmmp://',
    webUrl: 'https://paytm.com',
    connectionType: 'launch-only',
    description: 'Launch Paytm app or run simulated payment notification checks.',
  },
  {
    id: 'google-pay',
    name: 'Google Pay',
    category: 'Finance',
    brandColor: '#1A73E8',
    icon: 'SiGooglepay',
    letterFallback: 'GP',
    deepLink: 'tez://upi/pay',
    webUrl: 'https://pay.google.com',
    connectionType: 'launch-only',
    description: 'Open Google Pay on supported devices or test simulated transaction alerts.',
  },
  {
    id: 'phonepe',
    name: 'PhonePe',
    category: 'Finance',
    brandColor: '#5F259F',
    icon: 'SiPhonepe',
    letterFallback: 'PP',
    deepLink: 'phonepe://',
    webUrl: 'https://www.phonepe.com',
    connectionType: 'launch-only',
    description: 'Launch PhonePe or run simulated UPI alert notifications.',
  },
  {
    id: 'amazon',
    name: 'Amazon',
    category: 'Shopping',
    brandColor: '#FF9900',
    icon: null,
    letterFallback: 'AZ',
    deepLink: 'com.amazon.mobile.shopping://',
    webUrl: 'https://www.amazon.in',
    connectionType: 'launch-only',
    description: 'Open Amazon shopping and simulate delivery status alerts.',
  },
  {
    id: 'flipkart',
    name: 'Flipkart',
    category: 'Shopping',
    brandColor: '#2874F0',
    icon: null,
    letterFallback: 'FK',
    deepLink: 'flipkart://',
    webUrl: 'https://www.flipkart.com',
    connectionType: 'launch-only',
    description: 'Open Flipkart or run simulated order dispatch notifications.',
  },
  {
    id: 'swiggy',
    name: 'Swiggy',
    category: 'Shopping',
    brandColor: '#FC8019',
    icon: 'SiSwiggy',
    letterFallback: 'SW',
    deepLink: 'swiggy://',
    webUrl: 'https://www.swiggy.com',
    connectionType: 'launch-only',
    description: 'Launch Swiggy or simulate live delivery alert routing.',
  },
  {
    id: 'zomato',
    name: 'Zomato',
    category: 'Shopping',
    brandColor: '#E23744',
    icon: 'SiZomato',
    letterFallback: 'ZM',
    deepLink: 'zomato://',
    webUrl: 'https://www.zomato.com',
    connectionType: 'launch-only',
    description: 'Launch Zomato or simulate order alert notifications.',
  },
  {
    id: 'uber',
    name: 'Uber',
    category: 'Shopping',
    brandColor: '#16161D',
    icon: 'SiUber',
    letterFallback: 'UB',
    deepLink: 'uber://',
    webUrl: 'https://m.uber.com',
    connectionType: 'launch-only',
    description: 'Launch Uber directly or run simulated ride-arrival alerts.',
  },
  {
    id: 'ola',
    name: 'Ola',
    category: 'Shopping',
    brandColor: '#6D8B00',
    icon: null,
    letterFallback: 'OL',
    deepLink: 'olacabs://',
    webUrl: 'https://www.olacabs.com',
    connectionType: 'launch-only',
    description: 'Launch Ola Cabs or test simulated pickup alert notifications.',
  },
  {
    id: 'spotify',
    name: 'Spotify',
    category: 'Entertainment',
    brandColor: '#1DB954',
    icon: 'SiSpotify',
    letterFallback: 'SP',
    deepLink: 'spotify://',
    webUrl: 'https://open.spotify.com',
    connectionType: 'launch-only',
    description: 'Launch Spotify player or send a simulated media release alert.',
  },
  {
    id: 'youtube',
    name: 'YouTube',
    category: 'Entertainment',
    brandColor: '#FF0000',
    icon: 'SiYoutube',
    letterFallback: 'YT',
    deepLink: 'vnd.youtube://',
    webUrl: 'https://www.youtube.com',
    connectionType: 'launch-only',
    description: 'Launch YouTube or simulate creator upload notifications.',
  },
  {
    id: 'netflix',
    name: 'Netflix',
    category: 'Entertainment',
    brandColor: '#E50914',
    icon: 'SiNetflix',
    letterFallback: 'NF',
    deepLink: 'nflx://',
    webUrl: 'https://www.netflix.com',
    connectionType: 'launch-only',
    description: 'Open Netflix app or run simulated account sign-in alert checks.',
  },
];

export const APP_CATALOG_BY_ID: Record<string, CatalogApp> = Object.fromEntries(
  APP_CATALOG.map((app) => [app.id, app])
);
