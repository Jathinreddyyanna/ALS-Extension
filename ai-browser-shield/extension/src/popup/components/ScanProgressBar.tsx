import { motion } from 'framer-motion';
import { CheckCircle2, LoaderCircle, Search, Sparkles, Users } from 'lucide-react';

const steps = [
  { label: 'Checking structure', icon: Search },
  { label: 'AI analysis', icon: Sparkles },
  { label: 'Community data', icon: Users }
];

export const ScanProgressBar = ({ stage }: { stage: number }) => (
  <div className="surface-card flex flex-col gap-3 p-4" aria-label="Scan progress">
    {steps.map((step, index) => {
      const done = stage > index;
      const active = stage === index;
      const Icon = done ? CheckCircle2 : active ? LoaderCircle : step.icon;
      return (
        <motion.div
          key={step.label}
          initial={{ opacity: 0, x: -6 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.1 }}
          className="flex items-center gap-3"
        >
          <Icon className={`h-4 w-4 ${done ? 'text-safe-600 dark:text-safe-dark' : active ? 'animate-spin text-scan-600' : 'text-[var(--text-secondary)]'}`} />
          <span className={`text-body ${done || active ? 'text-[var(--text-primary)]' : 'text-[var(--text-secondary)]'}`}>{step.label}</span>
        </motion.div>
      );
    })}
  </div>
);
