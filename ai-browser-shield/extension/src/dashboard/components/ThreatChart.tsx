const categories = [
  { label: 'Phishing', key: 'phishing', color: 'bg-danger-600' },
  { label: 'Scam', key: 'scam', color: 'bg-caution-600' },
  { label: 'Malware', key: 'malware', color: 'bg-critical-600' },
  { label: 'Redirect', key: 'redirect', color: 'bg-scan-600' },
  { label: 'Popup Abuse', key: 'popup_abuse', color: 'bg-safe-600' }
] as const;

export const ThreatChart = ({ reports }: { reports: Array<{ category: string }> }) => {
  const counts = categories.map((category) => ({
    ...category,
    value: reports.filter((report) => report.category === category.key).length
  }));
  const max = Math.max(1, ...counts.map((item) => item.value));

  return (
    <div className="surface-card p-5">
      <p className="heading">Threat map</p>
      <p className="caption mb-5">What kinds of risks people are reporting most often</p>
      <div className="space-y-4">
        {counts.map((item) => (
          <div key={item.key}>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-body">{item.label}</span>
              <span className="data-text">{item.value}</span>
            </div>
            <div className="h-3 overflow-hidden rounded-full bg-[var(--surface-alt)]">
              <div className={`${item.color} h-full rounded-full`} style={{ width: `${(item.value / max) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
