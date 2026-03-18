import { AlertTriangle, Ban, CheckCircle2 } from 'lucide-react';
import clsx from 'clsx';
import type { RiskLevel } from '@/types/index';
import { riskLabels } from '@/lib/riskLabels';

const sizes = {
  sm: 'px-2.5 py-1 text-[11px]',
  md: 'px-3 py-1.5 text-caption',
  lg: 'px-4 py-2 text-body'
};

export const RiskBadge = ({ riskLevel, size = 'md' }: { riskLevel: RiskLevel; size?: 'sm' | 'md' | 'lg' }) => {
  const label = riskLabels[riskLevel];
  const icon = riskLevel === 'LOW'
    ? <CheckCircle2 className="h-3.5 w-3.5" />
    : riskLevel === 'CRITICAL'
      ? <Ban className="h-3.5 w-3.5" />
      : <AlertTriangle className="h-3.5 w-3.5" />;

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-2 rounded-full font-semibold',
        sizes[size],
        riskLevel === 'LOW' && 'soft-safe',
        riskLevel === 'MEDIUM' && 'soft-caution',
        riskLevel === 'HIGH' && 'soft-danger',
        riskLevel === 'CRITICAL' && 'soft-critical'
      )}
      aria-label={label.label}
    >
      {icon}
      {label.label}
    </span>
  );
};
