import { useId, type SVGProps } from 'react';

type P = SVGProps<SVGSVGElement> & { size?: number };

const base = (size = 18): SVGProps<SVGSVGElement> => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.8,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
  focusable: false,
});

export const SHIELD_PATH = 'M50 4 L92 18 V54 C92 82 74 102 50 112 C26 102 8 82 8 54 V18 Z';

/** Brand mark: a violet-to-magenta shield with a keyhole-shaped "local" dot. */
export function ShieldMark({ size = 28, ...rest }: P) {
  const id = `ss-mark-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  return (
    <svg width={size} height={(size * 116) / 100} viewBox="0 0 100 116" aria-hidden focusable={false} {...rest}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#8a5cf0" />
          <stop offset="1" stopColor="#d35cff" />
        </linearGradient>
      </defs>
      <path d={SHIELD_PATH} fill={`url(#${id})`} />
      <path d="M50 16 L80 26 V54 C80 75 67 90 50 98 Z" fill="#fcfaff" opacity="0.16" />
      <circle cx="50" cy="50" r="11" fill="#fcfaff" />
      <path d="M45 58 h10 l3 20 h-16 z" fill="#fcfaff" />
    </svg>
  );
}

export const IconChip = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <rect x="6" y="6" width="12" height="12" rx="2.5" />
    <path d="M9.5 9.5h5v5h-5z" />
    <path d="M9 2.5v3M15 2.5v3M9 18.5v3M15 18.5v3M2.5 9h3M2.5 15h3M18.5 9h3M18.5 15h3" />
  </svg>
);

export const IconCloud = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.75 4.75 0 0 0 7 18.5z" />
  </svg>
);

export const IconList = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M9 6h11M9 12h11M9 18h11" />
    <path d="M4 6h.01M4 12h.01M4 18h.01" strokeWidth={2.6} />
  </svg>
);

export const IconLock = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
    <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
  </svg>
);

export const IconSpark = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M12 3c.6 4.2 2.8 6.4 7 7-4.2.6-6.4 2.8-7 7-.6-4.2-2.8-6.4-7-7 4.2-.6 6.4-2.8 7-7z" />
  </svg>
);

export const IconDownload = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M12 4v11M7.5 10.5 12 15l4.5-4.5M5 19.5h14" />
  </svg>
);

export const IconCheck = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="m5 12.5 4.2 4.2L19 7" />
  </svg>
);

export const IconAlert = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M12 4 2.8 19.5h18.4z" />
    <path d="M12 10v4.2M12 17h.01" />
  </svg>
);

export const IconPage = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <rect x="4" y="4" width="16" height="16" rx="2.5" />
    <path d="M4 8.5h16M8 12.5h8M8 16h5" />
  </svg>
);

export const IconArrow = ({ size, ...p }: P) => (
  <svg {...base(size)} {...p}>
    <path d="M5 12h14M13.5 6.5 19 12l-5.5 5.5" />
  </svg>
);
