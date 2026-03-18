import { Flag } from 'lucide-react';
import { motion } from 'framer-motion';

interface ActionBarProps {
  onBack: () => void;
  onProceed: () => void;
  onReport: () => void;
}

export const ActionBar = ({ onBack, onProceed, onReport }: ActionBarProps) => (
  <div className="flex flex-col gap-3">
    <div className="grid grid-cols-[1.4fr_1fr] gap-3">
      <motion.button
        whileTap={{ scale: 0.98 }}
        type="button"
        onClick={onBack}
        className="min-h-11 rounded-md bg-safe-600 px-4 py-3 text-body font-semibold text-white dark:bg-safe-dark"
      >
        Go Back
      </motion.button>
      <motion.button
        whileTap={{ scale: 0.98 }}
        type="button"
        onClick={onProceed}
        className="min-h-11 rounded-md border border-[var(--border)] bg-transparent px-4 py-3 text-body font-semibold text-[var(--text-primary)]"
      >
        Proceed Anyway
      </motion.button>
    </div>
    <button
      type="button"
      onClick={onReport}
      className="inline-flex min-h-11 items-center justify-center gap-2 text-caption font-semibold text-[var(--text-secondary)]"
    >
      <Flag className="h-4 w-4" />
      Report This Site
    </button>
  </div>
);
