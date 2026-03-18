import { Eye } from 'lucide-react';
import { formatDomainDisplay, formatRelativeTime } from '@/lib/formatters';
import type { ThreatEvent } from '@/types/index';
import { RiskBadge } from '@/popup/components/RiskBadge';

export const LiveFeed = ({ events }: { events: ThreatEvent[] }) => (
  <div className="surface-card p-5">
    <div className="mb-4 flex items-center justify-between">
      <div>
        <p className="heading">Live feed</p>
        <p className="caption">Recent protection activity</p>
      </div>
      <span className="caption">Updates every 30 seconds</span>
    </div>
    <div className="space-y-3">
      {events.map((event) => (
        <div key={event.id} className="flex items-center gap-3 rounded-lg bg-[var(--surface-alt)] px-4 py-3">
          <div className="min-w-0 flex-1">
            <p className="truncate text-body font-semibold">{formatDomainDisplay(event.domain)}</p>
            <p className="caption">{formatRelativeTime(event.timestamp)}</p>
          </div>
          <RiskBadge riskLevel={event.riskLevel} size="sm" />
          <button type="button" className="inline-flex min-h-11 items-center gap-2 text-caption text-safe-600 dark:text-safe-dark">
            <Eye className="h-4 w-4" />
            View details
          </button>
        </div>
      ))}
    </div>
  </div>
);
