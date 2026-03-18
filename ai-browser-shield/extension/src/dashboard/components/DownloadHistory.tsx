import type { FileScanResult } from '@/types/index';
import { RiskBadge } from '@/popup/components/RiskBadge';

const verdictRisk = (verdict: FileScanResult['verdict']) => verdict === 'SAFE' ? 'LOW' : verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'HIGH';

export const DownloadHistory = ({ items }: { items: Array<FileScanResult & { filename: string; sourceDomain: string }> }) => (
  <div className="surface-card p-5">
    <div className="mb-4">
      <p className="heading">Download history</p>
      <p className="caption">Recent files checked before download</p>
    </div>
    <div className="grid gap-3 md:grid-cols-2">
      {items.map((item) => (
        <div key={`${item.filename}-${item.fileScanId ?? 'local'}`} className="rounded-lg bg-[var(--surface-alt)] p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-body font-semibold">{item.filename}</p>
              <p className="caption mt-1">{item.sourceDomain}</p>
            </div>
            <RiskBadge riskLevel={verdictRisk(item.verdict)} size="sm" />
          </div>
          <p className="caption mt-3">{item.explanation}</p>
          <button type="button" className="mt-4 text-caption font-semibold text-safe-600 dark:text-safe-dark">View scan details</button>
        </div>
      ))}
    </div>
  </div>
);
