import { motion, useReducedMotion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, ShieldEllipsis, ShieldQuestion } from 'lucide-react';
import clsx from 'clsx';

type ShieldStatus = 'idle' | 'scanning' | 'safe' | 'caution' | 'danger' | 'critical';

interface ShieldIconProps {
  status: ShieldStatus;
  size?: number;
}

const palette: Record<ShieldStatus, { ring: string; fill: string; glow: string; icon: JSX.Element }> = {
  idle: {
    ring: 'text-[var(--text-secondary)]',
    fill: 'bg-transparent',
    glow: '',
    icon: <ShieldQuestion className="h-10 w-10" aria-hidden="true" />
  },
  scanning: {
    ring: 'text-scan-600 dark:text-scan-400',
    fill: 'bg-scan-600/10',
    glow: 'shadow-[0_0_16px_rgba(59,130,246,0.18)]',
    icon: <ShieldEllipsis className="h-10 w-10" aria-hidden="true" />
  },
  safe: {
    ring: 'text-safe-600 dark:text-safe-dark',
    fill: 'bg-safe-600/12 dark:bg-safe-dark/12',
    glow: 'shadow-safe-glow',
    icon: <ShieldCheck className="h-10 w-10" aria-hidden="true" />
  },
  caution: {
    ring: 'text-caution-600',
    fill: 'bg-caution-600/12',
    glow: '',
    icon: <ShieldAlert className="h-10 w-10" aria-hidden="true" />
  },
  danger: {
    ring: 'text-danger-600',
    fill: 'bg-danger-600/12',
    glow: 'shadow-danger-glow',
    icon: <ShieldAlert className="h-10 w-10" aria-hidden="true" />
  },
  critical: {
    ring: 'text-critical-600',
    fill: 'bg-critical-600/15',
    glow: 'shadow-[0_0_22px_rgba(153,27,27,0.24)]',
    icon: <ShieldAlert className="h-10 w-10" aria-hidden="true" />
  }
};

export const ShieldIcon = ({ status, size = 120 }: ShieldIconProps) => {
  const reduceMotion = useReducedMotion();
  const tones = palette[status];

  return (
    <div
      className="relative flex items-center justify-center"
      style={{ width: size, height: size }}
      aria-label={`Shield status: ${status}`}
      role="img"
    >
      {status === 'scanning' && (
        <motion.div
          className="absolute inset-0 rounded-full border-2 border-dashed border-scan-600/40 dark:border-scan-400/40"
          animate={reduceMotion ? undefined : { rotate: 360 }}
          transition={{ repeat: Infinity, duration: 4, ease: 'linear' }}
        />
      )}
      {(status === 'safe' || status === 'danger' || status === 'critical') && (
        <motion.div
          className={clsx('absolute inset-2 rounded-full', tones.fill, tones.glow)}
          animate={reduceMotion ? undefined : status === 'safe' ? { scale: [1, 1.03, 1] } : { scale: [0.96, 1.04, 1] }}
          transition={status === 'safe' ? { repeat: Infinity, duration: 4, ease: 'easeInOut' } : { duration: 0.7, ease: 'easeOut' }}
        />
      )}
      <motion.div
        initial={reduceMotion ? false : { scale: 0.9, opacity: 0.6 }}
        animate={reduceMotion ? undefined : { scale: 1, opacity: 1 }}
        transition={{ duration: 0.24, ease: 'easeOut' }}
        className={clsx(
          'relative flex items-center justify-center rounded-full border',
          tones.ring,
          tones.fill,
          status === 'critical' ? 'border-critical-600/40' : 'border-current/20'
        )}
        style={{ width: size * 0.82, height: size * 0.82 }}
      >
        {tones.icon}
      </motion.div>
    </div>
  );
};
