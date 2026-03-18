import { ArrowRight, ArrowDown, ArrowUp } from 'lucide-react';

export const StatCard = ({
  value,
  label,
  trend = 'flat',
  tone = 'neutral'
}: {
  value: string | number;
  label: string;
  trend?: 'up' | 'down' | 'flat';
  tone?: 'neutral' | 'safe' | 'caution' | 'danger';
}) => {
  const Icon = trend === 'up' ? ArrowUp : trend === 'down' ? ArrowDown : ArrowRight;
  const toneClass = tone === 'safe' ? 'shadow-safe-glow' : tone === 'danger' ? 'shadow-danger-glow' : '';

  return (
    <div className={`surface-card p-4 ${toneClass}`}>
      <div className="flex items-center justify-between">
        <span className="data-text text-xl">{value}</span>
        <Icon className="h-4 w-4 text-[var(--text-secondary)]" />
      </div>
      <p className="mt-2 text-caption text-[var(--text-secondary)]">{label}</p>
    </div>
  );
};
