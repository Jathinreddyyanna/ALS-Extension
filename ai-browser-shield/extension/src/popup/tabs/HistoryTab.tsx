import { useThreatHistory } from '@/hooks/useThreatHistory';
import { ThreatHistoryList } from '../components/ThreatHistoryList';
import { StatCard } from '../components/StatCard';

export const HistoryTab = () => {
  const { history } = useThreatHistory();
  const todayCount = history.filter((item) => Date.now() - item.timestamp < 24 * 60 * 60 * 1000).length;
  const blocked = history.filter((item) => ['HIGH', 'CRITICAL'].includes(item.riskLevel)).length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <StatCard value={todayCount} label="Scans today" tone="safe" />
        <StatCard value={blocked} label="Threats blocked" tone={blocked > 0 ? 'danger' : 'safe'} />
        <StatCard value={history.length} label="Sites reported" tone="caution" />
      </div>
      <ThreatHistoryList history={history} />
    </div>
  );
};
