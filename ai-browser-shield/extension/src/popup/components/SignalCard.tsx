import type { LucideIcon } from 'lucide-react';

type SignalTone = 'safe' | 'caution' | 'danger' | 'critical';

const toneStyles: Record<SignalTone, string> = {
  safe: 'border-l-[var(--safe)] bg-[rgba(16,201,125,0.08)]',
  caution: 'border-l-[var(--caution)] bg-[rgba(217,119,6,0.1)]',
  danger: 'border-l-[var(--danger)] bg-[rgba(220,38,38,0.1)]',
  critical: 'border-l-[var(--critical)] bg-[rgba(153,27,27,0.2)]',
};

export const SignalCard = ({
  title,
  value,
  detail,
  icon: Icon,
  tone,
}: {
  title: string;
  value: number | string;
  detail: string;
  icon: LucideIcon;
  tone: SignalTone;
}) => (
  <div className={`rounded-2xl border border-[var(--border)] border-l-4 p-3 transition-all duration-200 hover:-translate-y-[1px] hover:shadow-[var(--shadow-elevated)] ${toneStyles[tone]}`}>
    <div className="flex items-start justify-between gap-3">
      <div className="rounded-xl bg-black/10 p-2 text-[var(--text-primary)] dark:bg-white/5">
        <Icon className="h-4 w-4" />
      </div>
      <span className="data-text text-lg text-[var(--text-primary)]">{value}</span>
    </div>
    <div className="mt-3">
      <p className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</p>
      <p className="caption mt-1">{detail}</p>
    </div>
  </div>
);
