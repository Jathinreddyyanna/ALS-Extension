import type { ThreatEvent } from '@/types/index';
import { ThreatHistoryList } from '@/popup/components/ThreatHistoryList';

export const HistoryPage = ({ history }: { history: ThreatEvent[] }) => (
  <div className="space-y-4">
    <div>
      <p className="heading">Browsing history</p>
      <p className="caption">Recent scans saved on this device.</p>
    </div>
    <ThreatHistoryList history={history} />
  </div>
);
