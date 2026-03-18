import { motion } from 'framer-motion';
import { Moon, Sun } from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';

export const ThemeToggle = () => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      className="relative flex min-h-11 min-w-[92px] items-center rounded-full border border-[var(--border)] bg-[var(--surface)] p-1"
    >
      <motion.span
        layout
        className="absolute left-1 top-1 bottom-1 w-[42px] rounded-full bg-[var(--surface-alt)]"
        animate={{ x: isDark ? 42 : 0 }}
        transition={{ type: 'spring', stiffness: 300, damping: 28 }}
      />
      <span className="relative z-10 flex flex-1 items-center justify-center gap-1 text-caption">
        <Sun className="h-3.5 w-3.5" />
        Light
      </span>
      <span className="relative z-10 flex flex-1 items-center justify-center gap-1 text-caption">
        <Moon className="h-3.5 w-3.5" />
        Dark
      </span>
    </button>
  );
};
