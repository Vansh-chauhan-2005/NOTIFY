'use client';

import React from 'react';
import {
  SiWhatsapp,
  SiTelegram,
  SiGmail,
  SiInstagram,
  SiX,
  SiDiscord,
  SiGithub,
  SiGitlab,
  SiJira,
  SiNotion,
  SiTrello,
  SiGooglecalendar,
  SiZoom,
  SiGooglemeet,
  SiPaytm,
  SiGooglepay,
  SiPhonepe,
  SiSwiggy,
  SiZomato,
  SiSpotify,
  SiYoutube,
  SiNetflix,
  SiUber,
} from 'react-icons/si';
import { APP_CATALOG_BY_ID, SiIconKey } from '../data/appCatalog';

const SI_ICON_MAP: Record<SiIconKey, React.ComponentType<{ className?: string; style?: React.CSSProperties }>> = {
  SiWhatsapp,
  SiTelegram,
  SiGmail,
  SiInstagram,
  SiX,
  SiDiscord,
  SiGithub,
  SiGitlab,
  SiJira,
  SiNotion,
  SiTrello,
  SiGooglecalendar,
  SiZoom,
  SiGooglemeet,
  SiPaytm,
  SiGooglepay,
  SiPhonepe,
  SiSwiggy,
  SiZomato,
  SiSpotify,
  SiYoutube,
  SiNetflix,
  SiUber,
};

interface AppIconBadgeProps {
  appId?: string;
  size?: 'sm' | 'md' | 'lg';
}

export default function AppIconBadge({ appId, size = 'md' }: AppIconBadgeProps) {
  const app = appId ? APP_CATALOG_BY_ID[appId] : undefined;
  const brandColor = app?.brandColor || '#D9468F';
  const IconComp = app?.icon ? SI_ICON_MAP[app.icon] : undefined;
  const fallbackText =
    app?.letterFallback || (appId ? appId.slice(0, 2).toUpperCase() : 'AG');

  const boxClass =
    size === 'sm'
      ? 'w-7 h-7 rounded-lg text-[10px]'
      : size === 'lg'
      ? 'w-11 h-11 rounded-2xl text-sm'
      : 'w-9 h-9 rounded-xl text-xs';

  const iconClass =
    size === 'sm' ? 'w-3.5 h-3.5' : size === 'lg' ? 'w-5 h-5' : 'w-4 h-4';

  return (
    <div
      className={`${boxClass} flex items-center justify-center shrink-0 font-bold border shadow-xs`}
      style={{
        backgroundColor: `${brandColor}16`,
        borderColor: `${brandColor}38`,
        color: brandColor,
      }}
      title={app?.name || appId || 'App'}
    >
      {IconComp ? (
        <IconComp className={iconClass} />
      ) : (
        <span className="font-mono-tech tracking-tight leading-none">{fallbackText}</span>
      )}
    </div>
  );
}
