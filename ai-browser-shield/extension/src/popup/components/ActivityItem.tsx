import { motion } from 'framer-motion';
import type { ActivityFeedItem } from '@/types/index';

const dotClassMap: Record<string, string> = {
  popup_intercepted: 'bg-[var(--caution)]',
  redirect_detected: 'bg-[#fb923c]',
  iframe_hidden: 'bg-[var(--danger)]',
  overlay_detected: 'bg-[var(--danger)]',
  script_injected: 'bg-[#fb923c]',
  form_suspicious: 'bg-[var(--danger)]',
  scan_completed: 'bg-[var(--scan)]',
  ai_used: 'bg-[var(--scan)]',
  heuristic_fallback: 'bg-[var(--text-secondary)]',
  blocked: 'bg-[var(--critical)]',
  safe: 'bg-[var(--safe)]',
  allowlisted: 'bg-[var(--safe)]',
  bypass_enabled: 'bg-[var(--caution)]',
  rescan_requested: 'bg-[var(--scan)]',
  sensitive_data_risk: 'bg-[var(--critical)]',
  report_submitted: 'bg-[var(--scan)]',
};

const formatTime = (timestamp: number) => {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

export const ActivityItem = ({ item }: { item: ActivityFeedItem }) => (
  <motion.div
    initial={{ opacity: 0, x: -10 }}
    animate={{ opacity: 1, x: 0 }}
    className="flex gap-3 rounded-2xl border border-[var(--border)] bg-[var(--surface)] px-3 py-3"
  >
    <div className="flex flex-col items-center pt-1">
      <span className={`h-2.5 w-2.5 rounded-full ${dotClassMap[item.type] ?? 'bg-[var(--scan)]'}`} />
      <span className="mt-2 h-full w-px bg-[var(--border)]" />
    </div>
    <div className="min-w-0 flex-1">
      <div className="flex items-center justify-between gap-3">
        <p className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{item.detail}</p>
        <span className="data-text shrink-0 text-[11px] text-[var(--text-secondary)]">{formatTime(item.timestamp)}</span>
      </div>
      <p className="caption mt-1 capitalize">{item.type.replace(/_/g, ' ')}</p>
    </div>
  </motion.div>
);
