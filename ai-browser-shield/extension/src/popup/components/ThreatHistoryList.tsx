import { Clock3, Globe } from 'lucide-react';
import { useState } from 'react';
import { formatDomainDisplay, formatRelativeTime } from '@/lib/formatters';
import type { ThreatEvent } from '@/types/index';
import { ExplanationCard } from './ExplanationCard';
import { RiskBadge } from './RiskBadge';
import { ShieldIcon } from './ShieldIcon';

export const ThreatHistoryList = ({ history }: { history: ThreatEvent[] }) => {
  const [openId, setOpenId] = useState<string | null>(null);

  if (history.length === 0) {
    return (
      <div className="surface-card flex flex-col items-center gap-4 px-6 py-8 text-center">
        <ShieldIcon status="safe" size={80} />
        <div>
          <p className="heading">No threats detected today. Browsing safely!</p>
          <p className="caption mt-2">All clear - you've had a safe browsing session. Tip: hovering over links can show a quick risk preview before you click.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {history.map((item) => (
        <div key={item.id} className="surface-card overflow-hidden">
          <button
            type="button"
            onClick={() => setOpenId((current) => current === item.id ? null : item.id)}
            className="flex w-full items-center gap-3 px-4 py-3 text-left"
          >
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--surface-alt)]">
              <Globe className="h-4 w-4 text-[var(--text-secondary)]" />
            </div>
            <div className="min-w-0 flex-1">
              <p className="truncate text-body font-semibold">{formatDomainDisplay(item.domain)}</p>
              <p className="caption inline-flex items-center gap-1">
                <Clock3 className="h-3.5 w-3.5" />
                {formatRelativeTime(item.timestamp)}
              </p>
            </div>
            <RiskBadge riskLevel={item.riskLevel} size="sm" />
          </button>
          {openId === item.id && (
            <div className="border-t border-[var(--border)] px-4 py-4">
              <ExplanationCard explanation={item.aiExplanation ?? 'This scan was saved from an earlier browsing session.'} signals={[]} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
};
