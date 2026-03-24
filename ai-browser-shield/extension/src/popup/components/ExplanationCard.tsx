import { AnimatePresence, motion } from 'framer-motion';
import { CheckCircle2, ChevronDown, Sparkles, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { plainSignalLabels } from '@/lib/riskLabels';

export const ExplanationCard = ({
  title = 'AI Analysis',
  explanation,
  signals,
  positives,
  warnings,
  confidence,
  reports,
  aiUsed,
  technicalDetails = []
}: {
  title?: string;
  explanation: string;
  signals: string[];
  positives?: string[];
  warnings?: string[];
  confidence?: number;
  reports?: number;
  aiUsed?: boolean;
  technicalDetails?: Array<{ label: string; value: string }>;
}) => {
  const [open, setOpen] = useState(false);
  const displaySignals = signals.slice(0, 3).map((signal) => plainSignalLabels[signal] ?? signal.replace(/_/g, ' '));
  const displayPositives = (positives ?? []).slice(0, 3);
  const displayWarnings = (warnings ?? []).slice(0, 3);

  return (
    <div className="surface-card space-y-4 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="caption mb-2 uppercase tracking-[0.12em]">{title}</p>
          <p className="text-body text-[var(--text-primary)]">{explanation}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {displayPositives.map((signal) => (
              <span key={signal} className="inline-flex items-center gap-2 rounded-full bg-[#163126] px-3 py-1 text-caption text-[#9ae6b4]">
                <CheckCircle2 className="h-3.5 w-3.5" />
                {signal}
              </span>
            ))}
            {displayWarnings.map((signal) => (
              <span key={signal} className="inline-flex items-center gap-2 rounded-full bg-[var(--surface-alt)] px-3 py-1 text-caption text-[var(--text-secondary)]">
                <TriangleAlert className="h-3.5 w-3.5" />
                {signal}
              </span>
            ))}
            {displaySignals.map((signal) => (
              <span key={signal} className="inline-flex items-center gap-2 rounded-full bg-[var(--surface-alt)] px-3 py-1 text-caption text-[var(--text-secondary)]">
                <TriangleAlert className="h-3.5 w-3.5" />
                {signal}
              </span>
            ))}
            {reports && reports > 0 && (
              <span className="inline-flex items-center gap-2 rounded-full bg-[var(--surface-alt)] px-3 py-1 text-caption text-[var(--text-secondary)]">
                <Sparkles className="h-3.5 w-3.5" />
                {reports} community report{reports === 1 ? '' : 's'}
              </span>
            )}
          </div>
        </div>
        <span className="caption inline-flex items-center gap-1 whitespace-nowrap">
          <Sparkles className="h-3.5 w-3.5" />
          {aiUsed ? 'AI explanation' : 'Rule-based explanation'}
        </span>
      </div>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex items-center gap-2 text-caption text-safe-600 dark:text-safe-dark"
        aria-expanded={open}
      >
        Technical details
        <ChevronDown className={`h-4 w-4 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden rounded-md bg-[var(--surface-alt)] p-3 text-caption text-[var(--text-secondary)]"
          >
            We compare the domain structure, trust signals, and reputation first. AI only explains the verdict after the decision has already been made.
            {typeof confidence === 'number' && <div className="mt-2">Detection confidence: {Math.round(confidence * 100)}%</div>}
            {technicalDetails.length > 0 && (
              <div className="mt-3 space-y-2">
                {technicalDetails.map((item) => (
                  <div key={`${item.label}-${item.value}`}>
                    <span className="font-semibold text-[var(--text-primary)]">{item.label}:</span> {item.value}
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
