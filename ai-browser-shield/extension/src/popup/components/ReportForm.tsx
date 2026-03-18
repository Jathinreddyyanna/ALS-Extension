import { CheckCircle2, Flag } from 'lucide-react';
import { useState } from 'react';
import { api } from '@/lib/api';
import { categoryLabels } from '@/lib/riskLabels';
import { useExtensionStore } from '@/store/useExtensionStore';
import { ErrorBanner } from './ErrorBanner';

const options = [
  { value: 'phishing', label: 'Fake login page' },
  { value: 'scam', label: 'Scam' },
  { value: 'malware', label: 'Malware' },
  { value: 'ad_abuse', label: 'Unwanted ads' },
  { value: 'redirect', label: 'Redirect tricks' },
  { value: 'other', label: 'Other' }
] as const;

export const ReportForm = ({ compact = false, url }: { compact?: boolean; url: string }) => {
  const { reportStatus, setReportStatus } = useExtensionStore();
  const [category, setCategory] = useState<typeof options[number]['value']>('phishing');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setReportStatus('submitting');
    setError(null);
    try {
      await api.reportSite({ url, category, description });
      setReportStatus('success');
    } catch (submissionError) {
      setReportStatus('error');
      setError((submissionError as { message?: string }).message ?? 'Could not submit your report right now.');
    }
  };

  if (reportStatus === 'success') {
    return (
      <div className="surface-card flex flex-col items-center gap-3 p-6 text-center">
        <CheckCircle2 className="h-10 w-10 text-safe-600 dark:text-safe-dark" />
        <p className="heading">Thank you - your report helps protect everyone</p>
        <p className="caption">We use reports like this to improve future warnings for the whole community.</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="surface-card space-y-4 p-4">
      <div>
        <label className="caption block">Site address</label>
        <input value={url} readOnly className="mt-2 min-h-11 w-full rounded-md border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2 text-body" />
      </div>
      <div>
        <label htmlFor="category" className="caption block">What looks wrong?</label>
        <select id="category" value={category} onChange={(event) => setCategory(event.target.value as typeof category)} className="mt-2 min-h-11 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-body">
          {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </div>
      <div>
        <label htmlFor="description" className="caption block">Describe what you noticed</label>
        <textarea
          id="description"
          value={description}
          onChange={(event) => setDescription(event.target.value)}
          placeholder={`Example: ${categoryLabels[category] ?? 'This page'} asked for my password unexpectedly.`}
          className={`mt-2 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-body ${compact ? 'min-h-[96px]' : 'min-h-[120px]'}`}
        />
      </div>
      {error && <ErrorBanner message={error} />}
      <button type="submit" className="flex min-h-11 w-full items-center justify-center gap-2 rounded-md bg-safe-600 px-4 py-3 font-semibold text-white dark:bg-safe-dark">
        <Flag className="h-4 w-4" />
        {reportStatus === 'submitting' ? 'Sending report...' : 'Submit report'}
      </button>
    </form>
  );
};
