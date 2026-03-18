import { Shield } from 'lucide-react';
import { ThemeToggle } from '@/popup/components/ThemeToggle';
import { formatProtectedSince } from '@/lib/formatters';

export const HeroBar = ({ since }: { since: number }) => (
  <header className="surface-card flex flex-wrap items-center justify-between gap-4 p-6">
    <div className="flex items-center gap-4">
      <div className="rounded-xl bg-safe-600/12 p-3 text-safe-600 dark:bg-safe-dark/12 dark:text-safe-dark">
        <Shield className="h-6 w-6" />
      </div>
      <div>
        <h1 className="headline">AI Browser Shield</h1>
        <p className="caption mt-1">Protected since {formatProtectedSince(since)}</p>
      </div>
    </div>
    <ThemeToggle />
  </header>
);
