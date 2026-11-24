import React from 'react';

// Aegis Brand Logo - Cream, Ink & Orchid Pink Shield
export const AegisGlyphLogo: React.FC<{ className?: string; size?: number }> = ({
  className = '',
  size = 38,
}) => {
  return (
    <div
      className={`relative rounded-xl bg-gradient-to-br from-[#16161D] via-[#4A1C38] to-[#D9468F] p-[1.5px] shadow-sm select-none ${className}`}
      style={{ width: size, height: size }}
      title="AegisNotify Hub"
    >
      <div className="w-full h-full rounded-[10px] bg-[#16161D] flex items-center justify-center">
        <svg
          width={size * 0.58}
          height={size * 0.58}
          viewBox="0 0 24 24"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M12 2L4 5.5V11.5C4 16.5 7.4 21.2 12 22.5C16.6 21.2 20 16.5 20 11.5V5.5L12 2Z"
            fill="url(#aegis-grad-shield)"
            fillOpacity="0.22"
            stroke="url(#aegis-grad-shield)"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <path
            d="M9 12L11 14L15 10"
            stroke="#FAF6F0"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          <defs>
            <linearGradient id="aegis-grad-shield" x1="4" y1="2" x2="20" y2="22.5" gradientUnits="userSpaceOnUse">
              <stop stopColor="#FAF6F0" />
              <stop offset="0.55" stopColor="#F472B6" />
              <stop offset="1" stopColor="#D9468F" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
};

// Connected App Logos tuned for Cream & Ink surfaces
export const NothingAppLogo: React.FC<{
  name: string;
  className?: string;
  size?: number;
}> = ({ name, className = '', size = 22 }) => {
  const normalized = name.toLowerCase();

  if (normalized.includes('slack') || normalized === 'messagesquare') {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className}>
        <rect x="3" y="9" width="4" height="4" rx="2" fill="#D9468F" />
        <rect x="8.5" y="4" width="4" height="9" rx="2" fill="#16161D" />
        <rect x="8.5" y="14.5" width="4" height="5.5" rx="2" fill="#B52A70" />
        <rect x="14" y="9" width="7" height="4" rx="2" fill="#464451" />
        <circle cx="10.5" cy="16.5" r="2" fill="#D9468F" />
        <circle cx="16" cy="16.5" r="2" fill="#16161D" />
      </svg>
    );
  }

  if (normalized.includes('github') || normalized === 'gitbranch') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={`text-[#16161D] ${className}`}
      >
        <circle cx="6" cy="18" r="3" fill="#FCECF4" stroke="#D9468F" />
        <circle cx="6" cy="6" r="3" fill="#FCECF4" stroke="#16161D" />
        <circle cx="18" cy="6" r="3" fill="#FCECF4" stroke="#D9468F" />
        <path d="M6 9v6" stroke="#16161D" />
        <path d="M18 9a9 9 0 0 1-9 9" stroke="#D9468F" />
      </svg>
    );
  }

  if (
    normalized.includes('stripe') ||
    normalized.includes('payment') ||
    normalized === 'creditcard'
  ) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="none"
        className={className}
      >
        <rect x="2" y="5" width="20" height="14" rx="3.5" fill="#16161D" />
        <rect x="2" y="9" width="20" height="3" fill="#D9468F" />
        <circle cx="6" cy="15" r="1.5" fill="#FAF6F0" />
        <circle cx="10" cy="15" r="1.5" fill="#F472B6" />
      </svg>
    );
  }

  if (
    normalized.includes('jira') ||
    normalized.includes('linear') ||
    normalized === 'checksquare'
  ) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        className={className}
      >
        <rect x="3" y="3" width="18" height="18" rx="5" fill="#D9468F" />
        <path
          d="M8 12.5L11 15.5L16.5 9"
          stroke="#FAF6F0"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  }

  if (
    normalized.includes('postmark') ||
    normalized.includes('mail') ||
    normalized === 'mail'
  ) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        className={className}
      >
        <rect x="2" y="4.5" width="20" height="15" rx="3" fill="#16161D" />
        <path
          d="M2 6.5L12 13.5L22 6.5"
          stroke="#D9468F"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
      </svg>
    );
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={className}
    >
      <circle cx="12" cy="12" r="9" fill="#FCECF4" stroke="#D9468F" strokeWidth="2" />
      <circle cx="12" cy="12" r="3.5" fill="#16161D" />
    </svg>
  );
};
