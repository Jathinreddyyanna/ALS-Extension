import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ['./src/**/*.{ts,tsx,html}'],
  theme: {
    extend: {
      colors: {
        safe: {
          50: '#F0FDF7',
          100: '#DCFCE9',
          200: '#BBF7D4',
          400: '#34D399',
          600: '#0D9B6A',
          700: '#0A7A54',
          dark: '#10C97D'
        },
        caution: {
          50: '#FFFBEB',
          100: '#FEF3C7',
          400: '#FBBF24',
          600: '#D97706',
          700: '#B45309'
        },
        danger: {
          50: '#FEF2F2',
          100: '#FEE2E2',
          400: '#F87171',
          600: '#DC2626',
          700: '#B91C1C'
        },
        critical: {
          600: '#991B1B',
          900: '#450A0A'
        },
        scan: {
          400: '#60A5FA',
          600: '#3B82F6'
        },
        neutral: {
          'bg-light': '#FAFAF8',
          'surface-light': '#FFFFFF',
          'border-light': '#E5E4E0',
          'text-primary-light': '#111110',
          'text-secondary-light': '#605F5A',
          'bg-dark': '#0F1117',
          'surface-dark': '#171B26',
          'surface-alt-dark': '#1E2330',
          'border-dark': '#2A2F40',
          'text-primary-dark': '#F4F4F2',
          'text-secondary-dark': '#9CA3AF'
        }
      },
      fontFamily: {
        display: ['"DM Sans"', 'sans-serif'],
        body: ['Lato', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace']
      },
      fontSize: {
        display: ['22px', { lineHeight: '1.15', letterSpacing: '-0.5px', fontWeight: '700' }],
        heading: ['18px', { lineHeight: '1.3', fontWeight: '600' }],
        subheading: ['15px', { lineHeight: '1.4', fontWeight: '500' }],
        body: ['14px', { lineHeight: '1.6', fontWeight: '400' }],
        caption: ['12px', { lineHeight: '1.5', fontWeight: '400' }],
        data: ['13px', { lineHeight: '1.45', fontWeight: '500' }],
        score: ['36px', { lineHeight: '1', fontWeight: '700' }]
      },
      borderRadius: {
        sm: '6px',
        md: '10px',
        lg: '14px',
        xl: '20px'
      },
      boxShadow: {
        card: '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
        elevated: '0 4px 12px rgba(0,0,0,0.08)',
        focus: '0 0 0 3px rgba(13,155,106,0.25)',
        'card-dark': '0 1px 3px rgba(0,0,0,0.3)',
        'elevated-dark': '0 4px 16px rgba(0,0,0,0.5)',
        'safe-glow': '0 0 12px rgba(16,201,125,0.15)',
        'danger-glow': '0 0 12px rgba(220,38,38,0.15)'
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' }
        },
        gentlePulse: {
          '0%, 100%': { transform: 'scale(1)', opacity: '0.9' },
          '50%': { transform: 'scale(1.02)', opacity: '1' }
        }
      },
      animation: {
        shimmer: 'shimmer 1.6s linear infinite',
        'gentle-pulse': 'gentlePulse 4s ease-in-out infinite'
      }
    }
  },
  plugins: []
};

export default config;
