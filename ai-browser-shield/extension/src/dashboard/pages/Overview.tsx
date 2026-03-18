import { useMemo } from 'react';
import type { AppStatsResponse, RecentReportResponse } from '@/lib/api';
import type { ThreatEvent } from '@/types/index';
import { DownloadHistory } from '../components/DownloadHistory';
import { LiveFeed } from '../components/LiveFeed';
import { RecentReports } from '../components/RecentReports';
import { SettingsPanel } from '../components/SettingsPanel';
import { StatsRow } from '../components/StatsRow';
import { ThreatChart } from '../components/ThreatChart';

export const OverviewPage = ({
  stats,
  reports,
  history
}: {
  stats: AppStatsResponse;
  reports: RecentReportResponse[];
  history: ThreatEvent[];
}) => {
  const downloadHistory = useMemo(() => history.slice(0, 4).map((item) => ({
    filename: `${item.domain.replace(/\./g, '-')}.download`,
    sourceDomain: item.domain,
    verdict: item.riskLevel === 'LOW' ? 'SAFE' as const : item.riskLevel === 'MEDIUM' ? 'SUSPICIOUS' as const : 'MALICIOUS' as const,
    confidence: 0.8,
    explanation: item.aiExplanation ?? 'Checked recently by Browser Shield.',
    indicators: [],
    recommended_action: 'warn',
    processedMs: 0
  })), [history]);

  return (
    <div className="space-y-6">
      <StatsRow stats={stats} />
      <div className="grid gap-6 xl:grid-cols-[1.3fr_0.9fr]">
        <LiveFeed events={history.slice(0, 6)} />
        <ThreatChart reports={reports} />
      </div>
      <RecentReports reports={reports.slice(0, 6)} />
      <DownloadHistory items={downloadHistory} />
      <SettingsPanel />
    </div>
  );
};
