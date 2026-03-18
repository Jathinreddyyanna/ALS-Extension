import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BarChart3, Clock3, Download, Settings2, Shield } from 'lucide-react';
import { useEffect } from 'react';
import { ThemeProvider } from '@/hooks/useTheme';
import { useApiRequest } from '@/hooks/useApiRequest';
import { useThreatHistory } from '@/hooks/useThreatHistory';
import { api } from '@/lib/api';
import { useExtensionStore } from '@/store/useExtensionStore';
import { HeroBar } from './components/HeroBar';
import { DownloadsPage } from './pages/Downloads';
import { HistoryPage } from './pages/History';
import { OverviewPage } from './pages/Overview';
import { ReportsPage } from './pages/Reports';
import { SettingsPage } from './pages/Settings';
import '@/styles/globals.css';

const queryClient = new QueryClient();

const navItems = [
  { id: 'overview', label: 'Overview', icon: Shield },
  { id: 'history', label: 'History', icon: Clock3 },
  { id: 'reports', label: 'Reports', icon: BarChart3 },
  { id: 'downloads', label: 'Downloads', icon: Download },
  { id: 'settings', label: 'Settings', icon: Settings2 }
] as const;

const DashboardShell = () => {
  const { dashboardPage, setDashboardPage } = useExtensionStore();
  const { history } = useThreatHistory();

  const statsQuery = useApiRequest({
    queryKey: ['dashboard-stats'],
    queryFn: api.getStats,
    refetchInterval: 30_000
  });
  const reportsQuery = useApiRequest({
    queryKey: ['dashboard-reports'],
    queryFn: api.getRecentReports,
    refetchInterval: 30_000
  });

  useEffect(() => {
    if (localStorage.getItem('shield-api-base-url')) return;
    api.setBaseUrl(import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:3001/api/v1');
  }, []);

  const stats = statsQuery.data ?? { totalScans: 0, totalThreats: 0, totalReports: 0, totalFileScans: 0, lastUpdated: new Date().toISOString() };
  const reports = reportsQuery.data ?? [];

  return (
    <div className="min-h-screen bg-[var(--bg)] px-4 py-6 text-[var(--text-primary)] md:px-8">
      <div className="mx-auto max-w-7xl space-y-6">
        <HeroBar since={Date.now() - 12 * 24 * 60 * 60 * 1000} />
        <div className="grid gap-6 lg:grid-cols-[240px_1fr]">
          <aside className="surface-card h-fit p-3">
            <nav className="space-y-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = dashboardPage === item.id;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setDashboardPage(item.id)}
                    className={`flex min-h-11 w-full items-center gap-3 rounded-lg px-4 py-3 text-left ${active ? 'bg-[var(--surface-alt)] text-safe-600 dark:text-safe-dark' : 'text-[var(--text-secondary)]'}`}
                  >
                    <Icon className="h-4 w-4" />
                    {item.label}
                  </button>
                );
              })}
            </nav>
          </aside>
          <section className="space-y-6">
            {dashboardPage === 'overview' && <OverviewPage stats={stats} reports={reports} history={history} />}
            {dashboardPage === 'history' && <HistoryPage history={history} />}
            {dashboardPage === 'reports' && <ReportsPage reports={reports} />}
            {dashboardPage === 'downloads' && <DownloadsPage history={history} />}
            {dashboardPage === 'settings' && <SettingsPage />}
          </section>
        </div>
      </div>
    </div>
  );
};

export default function DashboardApp() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <DashboardShell />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
