import { AnimatePresence, motion } from 'framer-motion';
import { Flag, LockKeyhole, Settings, Shield } from 'lucide-react';
import { useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useCurrentTab } from '@/hooks/useCurrentTab';
import { useScanResult } from '@/hooks/useScanResult';
import { ThemeProvider } from '@/hooks/useTheme';
import { formatDomainDisplay } from '@/lib/formatters';
import { useExtensionStore } from '@/store/useExtensionStore';
import { DownloadWarningOverlay } from './components/DownloadWarningOverlay';
import { ThemeToggle } from './components/ThemeToggle';
import { ReportTab } from './tabs/ReportTab';
import { SettingsTab } from './tabs/SettingsTab';
import { ShieldTab } from './tabs/ShieldTab';
import { UnlockTab } from './tabs/UnlockTab';
import { VaultTab } from './tabs/VaultTab';
import { useVaultStore } from '../store/useVaultStore';
import '@/styles/globals.css';

const queryClient = new QueryClient();

const tabs = [
  { id: 'shield', label: 'Shield', icon: Shield },
  { id: 'report', label: 'Report', icon: Flag },
  { id: 'vault', label: 'Vault', icon: LockKeyhole },
  { id: 'settings', label: 'Settings', icon: Settings }
] as const;

const PopupShell = () => {
  const { data: tab } = useCurrentTab();
  const {
    currentTab,
    direction,
    setCurrentTab,
    setCurrentLocation,
    currentDomain,
    downloadOverlay,
    setDownloadOverlay
  } = useExtensionStore();
  const { unlocked, syncState } = useVaultStore();

  useEffect(() => {
    if (!tab?.url) return;
    setCurrentLocation(tab.url, formatDomainDisplay(tab.url), tab.id ?? null);
  }, [setCurrentLocation, tab]);

  useEffect(() => {
    void syncState();
    const timer = window.setInterval(() => void syncState(), 30_000);
    return () => window.clearInterval(timer);
  }, [syncState]);

  useScanResult();

  return (
    <div className="app-shell flex min-h-[520px] w-[380px] flex-col bg-[radial-gradient(circle_at_top,rgba(13,155,106,0.12),transparent_38%)] p-4 dark:bg-[radial-gradient(circle_at_top,rgba(16,201,125,0.12),transparent_32%)]">
      <header className="mb-5 flex items-center justify-between">
        <div>
          <p className="headline text-lg">AI Browser Shield</p>
          <p className="caption">Calm protection for everyday browsing</p>
        </div>
        <ThemeToggle />
      </header>

      <main className="min-h-0 flex-1 overflow-y-auto pb-4">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={currentTab}
            initial={{ x: direction > 0 ? 18 : -18, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: direction > 0 ? -18 : 18, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
          >
            {currentTab === 'shield' && <ShieldTab />}
            {currentTab === 'report' && <ReportTab />}
            {currentTab === 'vault' && (unlocked ? <VaultTab /> : <UnlockTab />)}
            {currentTab === 'settings' && <SettingsTab />}
          </motion.div>
        </AnimatePresence>
      </main>

      <nav className="mt-auto grid grid-cols-4 gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-2">
        {tabs.map((item) => {
          const Icon = item.icon;
          const active = currentTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setCurrentTab(item.id)}
              className={`flex min-h-11 flex-col items-center justify-center rounded-lg px-2 py-2 text-caption transition-colors ${active ? 'bg-[var(--surface-alt)] text-safe-600 dark:text-safe-dark' : 'text-[var(--text-secondary)]'}`}
              aria-current={active ? 'page' : undefined}
            >
              <Icon className="mb-1 h-4 w-4" />
              {item.label}
            </button>
          );
        })}
      </nav>

      <DownloadWarningOverlay
        open={downloadOverlay.open}
        result={downloadOverlay.result}
        fileName={downloadOverlay.fileName}
        fileSize={downloadOverlay.fileSize}
        onClose={() => setDownloadOverlay({ open: false, result: null })}
      />

      <div className="pointer-events-none absolute inset-0 rounded-[22px] ring-1 ring-black/5 dark:ring-white/5" />
      <div className="sr-only">{currentDomain}</div>
    </div>
  );
};

export default function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <PopupShell />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
