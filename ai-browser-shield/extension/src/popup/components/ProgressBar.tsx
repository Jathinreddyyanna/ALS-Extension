import { motion } from 'framer-motion';

type ProgressTone = 'safe' | 'caution' | 'danger' | 'critical' | 'scan';

const toneClassMap: Record<ProgressTone, string> = {
  safe: 'bg-[var(--safe)]',
  caution: 'bg-[var(--caution)]',
  danger: 'bg-[var(--danger)]',
  critical: 'bg-[var(--critical)]',
  scan: 'bg-[var(--scan)]',
};

export const ProgressBar = ({
  label,
  value,
  tone = 'scan',
  caption,
}: {
  label: string;
  value: number;
  tone?: ProgressTone;
  caption?: string;
}) => {
  const normalized = Math.max(0, Math.min(100, Math.round(value)));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[13px] font-semibold text-[var(--text-primary)]">{label}</p>
          {caption ? <p className="caption mt-1">{caption}</p> : null}
        </div>
        <span className="data-text text-[12px]">{normalized}%</span>
      </div>
      <div className="h-2.5 overflow-hidden rounded-full bg-[var(--surface-alt)]">
        <motion.div
          className={`h-full rounded-full ${toneClassMap[tone]}`}
          initial={{ width: 0 }}
          animate={{ width: `${normalized}%` }}
          transition={{ duration: 0.45, ease: 'easeOut' }}
        />
      </div>
    </div>
  );
};
