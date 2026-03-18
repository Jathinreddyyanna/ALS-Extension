import type { RecentReportResponse } from '@/lib/api';
import { RecentReports } from '../components/RecentReports';

export const ReportsPage = ({ reports }: { reports: RecentReportResponse[] }) => (
  <div className="space-y-4">
    <div>
      <p className="heading">Community reports</p>
      <p className="caption">Reports from people helping keep the web safer.</p>
    </div>
    <RecentReports reports={reports} />
  </div>
);
