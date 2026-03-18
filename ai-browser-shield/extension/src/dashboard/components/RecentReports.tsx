import { categoryLabels } from '@/lib/riskLabels';
import type { RecentReportResponse } from '@/lib/api';
import { formatRelativeTime } from '@/lib/formatters';

export const RecentReports = ({ reports }: { reports: RecentReportResponse[] }) => (
  <div className="surface-card overflow-hidden p-5">
    <div className="mb-4">
      <p className="heading">Recent community reports</p>
      <p className="caption">Fresh reports from people using Browser Shield</p>
    </div>
    <div className="overflow-x-auto">
      <table className="min-w-full text-left">
        <thead className="caption">
          <tr>
            <th className="pb-3 font-normal">Site</th>
            <th className="pb-3 font-normal">Category</th>
            <th className="pb-3 font-normal">When</th>
            <th className="pb-3 font-normal">Status</th>
          </tr>
        </thead>
        <tbody>
          {reports.map((report) => (
            <tr key={report.id} className="border-t border-[var(--border)]">
              <td className="py-3 text-body">{report.domain}</td>
              <td className="py-3 text-body">{categoryLabels[report.category] ?? report.category}</td>
              <td className="py-3 text-body">{formatRelativeTime(report.createdAt)}</td>
              <td className="py-3 text-body capitalize">{report.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);
