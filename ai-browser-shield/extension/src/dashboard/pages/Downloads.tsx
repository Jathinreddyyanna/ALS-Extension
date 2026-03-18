import type { ThreatEvent } from '@/types/index';
import { DownloadHistory } from '../components/DownloadHistory';

export const DownloadsPage = ({ history }: { history: ThreatEvent[] }) => (
  <div className="space-y-4">
    <div>
      <p className="heading">Download checks</p>
      <p className="caption">Files recently reviewed before opening or saving.</p>
    </div>
    <DownloadHistory
      items={history.slice(0, 8).map((item) => ({
        filename: `${item.domain.replace(/\./g, '-')}.file`,
        sourceDomain: item.domain,
        verdict: item.riskLevel === 'LOW' ? 'SAFE' as const : item.riskLevel === 'MEDIUM' ? 'SUSPICIOUS' as const : 'MALICIOUS' as const,
        confidence: 0.78,
        explanation: item.aiExplanation ?? 'Checked recently by Browser Shield.',
        indicators: [],
        recommended_action: 'warn',
        processedMs: 0
      }))}
    />
  </div>
);
