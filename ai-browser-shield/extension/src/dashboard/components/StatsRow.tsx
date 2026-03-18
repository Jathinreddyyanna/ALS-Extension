import type { AppStatsResponse } from '@/lib/api';
import { StatCard } from '@/popup/components/StatCard';

export const StatsRow = ({ stats }: { stats: AppStatsResponse }) => (
  <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
    <StatCard value={stats.totalScans} label="Total Sites Scanned" tone="safe" />
    <StatCard value={stats.totalThreats} label="Threats Blocked Today" tone={stats.totalThreats > 0 ? 'danger' : 'safe'} />
    <StatCard value={stats.totalReports} label="Community Reports" tone="caution" />
    <StatCard value={stats.totalFileScans} label="Files Scanned" tone="neutral" />
  </div>
);
