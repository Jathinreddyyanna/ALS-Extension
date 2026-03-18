import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown, Sparkles, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { plainSignalLabels } from '@/lib/riskLabels';

export const ExplanationCard = ({
  explanation,
  signals,
  confidence,
  reports
}: {
  explanation: string;
  signals: string[];
  confidence?: number;
  reports?: number;
}) => {
  const [open, setOpen] = useState(false);
  const displaySignals = signals.slice(0, 3).map((signal) => plainSignalLabels[signal] ?? signal.replace(/_/g, ' '));

  return (
    <div className="surface-card space-y-4 p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-body text-[var(--text-primary)]">{explanation}</p>
          <div className="mt-3 flex flex-wrap gap-2">
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
          Powered by AI
        </span>
      </div>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex items-center gap-2 text-caption text-safe-600 dark:text-safe-dark"
        aria-expanded={open}
      >
        What does this mean?
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
            We compare the web address, look for known deception patterns, ask the AI to explain what it sees, and check whether other people reported the same site.
            {typeof confidence === 'number' && <div className="mt-2">AI analysis confidence: {Math.round(confidence * 100)}%</div>}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
