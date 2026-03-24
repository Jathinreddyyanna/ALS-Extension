import { AnimatePresence, motion } from 'framer-motion';
import {
  Activity,
  Brain,
  CreditCard,
  ExternalLink,
  EyeOff,
  FormInput,
  LineChart,
  Radar,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Sparkles,
  Waves,
  Zap,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { riskLabels } from '@/lib/riskLabels';
import { useExtensionStore } from '@/store/useExtensionStore';
import type { ActivityFeedItem, RiskLevel } from '@/types/index';
import { ActivityItem } from '../components/ActivityItem';
import { ErrorBanner } from '../components/ErrorBanner';
import { ExplanationCard } from '../components/ExplanationCard';
import { ProgressBar } from '../components/ProgressBar';
import { RiskBadge } from '../components/RiskBadge';
import { RiskMeter } from '../components/RiskMeter';
import { ScanProgressBar } from '../components/ScanProgressBar';
import { ShieldIcon } from '../components/ShieldIcon';
import { SignalCard } from '../components/SignalCard';

const formatPercentage = (value?: number) => `${Math.round((value ?? 0) * 100)}%`;

const getSignalTone = (value: number, metric: 'popup' | 'redirect' | 'iframe' | 'form'): 'safe' | 'caution' | 'danger' | 'critical' => {
  if (metric === 'iframe' || metric === 'form') return value > 0 ? 'danger' : 'safe';
  if (metric === 'popup') return value >= 3 ? 'danger' : value >= 1 ? 'caution' : 'safe';
  if (metric === 'redirect') return value >= 3 ? 'danger' : value >= 1 ? 'caution' : 'safe';
  return 'safe';
};

const getRiskTone = (riskLevel: RiskLevel): 'safe' | 'caution' | 'danger' | 'critical' => {
  if (riskLevel === 'LOW') return 'safe';
  if (riskLevel === 'MEDIUM') return 'caution';
  if (riskLevel === 'HIGH') return 'danger';
  return 'critical';
};

const toneButtonMap = {
  primary: 'bg-[#2563EB] text-white hover:bg-[#1e40af]',
  secondary: 'border border-[var(--border)] bg-[var(--surface)] text-[var(--text-primary)] hover:bg-[var(--surface-alt)]',
  ghost: 'border border-[var(--border)] bg-transparent text-[var(--text-secondary)] hover:bg-[var(--surface-alt)] hover:text-[var(--text-primary)]',
  danger: 'border border-[rgba(220,38,38,0.35)] bg-[rgba(220,38,38,0.1)] text-[#fca5a5] hover:bg-[rgba(220,38,38,0.16)]',
} as const;

export const ShieldTab = () => {
  const {
    currentDomain,
    currentTabId,
    currentUrl,
    isScanning,
    scanStage,
    scanResult,
    scanError,
    setCurrentTab,
  } = useExtensionStore();
  const [activity, setActivity] = useState<ActivityFeedItem[]>([]);
  const [toast, setToast] = useState<{ tone: 'safe' | 'caution' | 'danger'; message: string } | null>(null);
  const [isRescanning, setIsRescanning] = useState(false);
  const [isBypassing, setIsBypassing] = useState(false);
  const [isAllowlisting, setIsAllowlisting] = useState(false);
  const toastTimer = useRef<number | null>(null);

  useEffect(() => {
    setActivity(scanResult?.activityLog?.slice(0, 8) ?? []);
  }, [scanResult?.activityLog]);

  useEffect(() => () => {
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
  }, []);

  const showToast = (message: string, tone: 'safe' | 'caution' | 'danger') => {
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    setToast({ message, tone });
    toastTimer.current = window.setTimeout(() => setToast(null), 2600);
  };

  const runtimeSignals = scanResult?.signals ?? {
    popupCount: 0,
    redirectCount: 0,
    hiddenIframeCount: 0,
    overlayCount: 0,
    scriptInjectionCount: 0,
    suspiciousFormCount: 0,
    domMutationCount: 0,
  };

  const detailRows = useMemo(
    () =>
      [
        scanResult?.signalsUsed?.length ? { label: 'Signals used', value: scanResult.signalsUsed.join(', ') } : null,
        scanResult?.decisionBasis ? { label: 'Decision basis', value: scanResult.decisionBasis } : null,
        scanResult?.source ? { label: 'Source', value: scanResult.source } : null,
        scanResult?.modelUsed ? { label: 'Model', value: scanResult.modelUsed } : null,
      ].filter((item): item is { label: string; value: string } => !!item),
    [scanResult?.decisionBasis, scanResult?.modelUsed, scanResult?.signalsUsed, scanResult?.source]
  );

  const riskTone = getRiskTone(scanResult?.riskLevel ?? 'LOW');
  const modelLabel =
    scanResult?.modelStatus === 'active'
      ? `AI active${scanResult.modelUsed ? ` · ${scanResult.modelUsed}` : ''}`
      : scanResult?.modelStatus === 'degraded'
        ? 'AI degraded'
        : 'Heuristic mode';

  const sendMessage = <T,>(payload: Record<string, unknown>) =>
    new Promise<T>((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(payload, (response: T) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(response);
        });
      } catch (error) {
        reject(error);
      }
    });

  const withAction = async (
    setter: (value: boolean) => void,
    action: () => Promise<void>,
    successMessage: string,
    tone: 'safe' | 'caution' | 'danger' = 'safe'
  ) => {
    setter(true);
    try {
      await action();
      showToast(successMessage, tone);
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Action failed', 'danger');
    } finally {
      setter(false);
    }
  };

  const openDashboard = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  };

  if (scanError && !scanResult) {
    return (
      <div className="flex flex-col gap-5">
        <div className="surface-card flex flex-col items-center gap-4 p-6 text-center">
          <ShieldIcon status="idle" />
          <p className="heading">Protection engine temporarily limited</p>
          <p className="caption max-w-[280px]">
            Live browser heuristics are still active, but the richer security snapshot could not be loaded right now.
          </p>
        </div>
        <ErrorBanner message={scanError} />
      </div>
    );
  }

  if (isScanning || !scanResult) {
    return (
      <div className="flex flex-col gap-4">
        <div className="rounded-[20px] border border-[var(--border)] bg-[#0B1220] p-5 text-white shadow-[var(--shadow-elevated)]">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Security command center</p>
              <p className="mt-2 text-lg font-semibold">{currentDomain || 'Current page'}</p>
              <p className="mt-1 text-sm text-slate-400">Preparing live threat analysis and runtime telemetry…</p>
            </div>
            <ShieldIcon status="scanning" size={96} />
          </div>
          <div className="mt-4">
            <ScanProgressBar stage={scanStage} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          {Array.from({ length: 4 }).map((_, index) => (
            <div key={index} className="surface-card shimmer h-[106px] rounded-2xl p-4" />
          ))}
        </div>
        <div className="surface-card shimmer h-[152px] rounded-2xl p-4" />
        <div className="surface-card shimmer h-[168px] rounded-2xl p-4" />
      </div>
    );
  }

  const activeResult = scanResult;
  const trend = activeResult.history && activeResult.history.length >= 3
    ? activeResult.history[0].riskScore > activeResult.history[1].riskScore && activeResult.history[1].riskScore > activeResult.history[2].riskScore
      ? 'rising'
      : activeResult.history[0].riskScore < activeResult.history[1].riskScore && activeResult.history[1].riskScore < activeResult.history[2].riskScore
        ? 'falling'
        : 'steady'
    : 'steady';

  return (
    <div className="space-y-4">
      <motion.div
        initial={{ opacity: 0.8, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-[20px] border border-[rgba(37,99,235,0.24)] bg-[#0B1220] p-5 text-white shadow-[0_12px_36px_rgba(0,0,0,0.35)]"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-[0.14em] text-slate-400">Real-time security command center</p>
            <p className="mt-2 truncate text-lg font-semibold">{currentDomain || activeResult.domain}</p>
            <p className="mt-1 truncate font-mono text-[12px] text-slate-400">{currentUrl || activeResult.url}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-medium text-slate-200">{modelLabel}</span>
              <span className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-medium text-slate-200">
                Confidence {formatPercentage(activeResult.confidence)}
              </span>
            </div>
          </div>
          <div className={activeResult.riskLevel === 'CRITICAL' ? 'rounded-full shadow-[0_0_30px_rgba(220,38,38,0.35)]' : ''}>
            <RiskMeter score={activeResult.riskScore} riskLevel={activeResult.riskLevel} animated />
          </div>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="rounded-2xl bg-white/5 p-3">
            <p className="text-[11px] uppercase tracking-[0.12em] text-slate-400">Risk level</p>
            <div className="mt-2">
              <RiskBadge riskLevel={activeResult.riskLevel} />
            </div>
          </div>
          <div className="rounded-2xl bg-white/5 p-3">
            <p className="text-[11px] uppercase tracking-[0.12em] text-slate-400">Threat category</p>
            <p className="mt-2 text-sm font-semibold capitalize text-slate-100">{activeResult.category || 'unknown'}</p>
          </div>
          <div className="rounded-2xl bg-white/5 p-3">
            <p className="text-[11px] uppercase tracking-[0.12em] text-slate-400">Scan time</p>
            <p className="mt-2 data-text text-sm text-slate-100">{activeResult.processedMs || 0}ms</p>
          </div>
        </div>
      </motion.div>

      {scanError ? <ErrorBanner message={scanError} /> : null}

      {activeResult.sensitiveDataRisk?.detected ? (
        <div className={`rounded-[18px] border px-4 py-4 ${
          activeResult.sensitiveDataRisk.level === 'high'
            ? 'border-[rgba(220,38,38,0.35)] bg-[rgba(220,38,38,0.12)]'
            : 'border-[rgba(217,119,6,0.35)] bg-[rgba(217,119,6,0.12)]'
        }`}>
          <div className="flex items-start gap-3">
            <div className="rounded-xl bg-black/10 p-2 text-[#fca5a5] dark:bg-white/5">
              <CreditCard className="h-4 w-4" />
            </div>
            <div>
              <p className="text-[13px] font-semibold text-[var(--text-primary)]">Sensitive data warning</p>
              <p className="caption mt-1">{activeResult.sensitiveDataRisk.message}</p>
              <p className="caption mt-2">
                Password fields: {activeResult.sensitiveDataRisk.passwordFields} · Card fields: {activeResult.sensitiveDataRisk.creditCardFields}
              </p>
            </div>
          </div>
        </div>
      ) : null}

      <div className="grid grid-cols-3 gap-3">
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <ShieldAlert className="h-4 w-4" />
            <span className="text-[12px] font-medium">Patterns</span>
          </div>
          <p className="mt-2 text-[13px] font-semibold text-[var(--text-primary)]">
            {activeResult.patternFlags?.phishingPattern ? 'Phishing pattern' : activeResult.patternFlags?.redirectTrap ? 'Redirect trap' : 'No major pattern'}
          </p>
        </div>
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Brain className="h-4 w-4" />
            <span className="text-[12px] font-medium">Reputation</span>
          </div>
          <p className="mt-2 text-[13px] font-semibold text-[var(--text-primary)]">
            {activeResult.reputation?.reportCount ?? 0} report{(activeResult.reputation?.reportCount ?? 0) === 1 ? '' : 's'}
          </p>
        </div>
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <LineChart className="h-4 w-4" />
            <span className="text-[12px] font-medium">Trend</span>
          </div>
          <p className="mt-2 text-[13px] font-semibold capitalize text-[var(--text-primary)]">{trend}</p>
        </div>
      </div>

      <div className="surface-card rounded-[20px] p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <p className="heading text-[16px]">Runtime signals</p>
            <p className="caption">Live page behaviors collected from the current tab</p>
          </div>
          <div className="inline-flex items-center gap-2 rounded-full bg-[var(--surface-alt)] px-3 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            <span className="h-2 w-2 rounded-full bg-[var(--safe)]" />
            Monitoring live
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <SignalCard
            title="Popups"
            value={runtimeSignals.popupCount}
            detail={runtimeSignals.popupCount > 0 ? 'Intercepted before opening' : 'No popup behavior seen'}
            icon={ShieldAlert}
            tone={getSignalTone(runtimeSignals.popupCount, 'popup')}
          />
          <SignalCard
            title="Redirect chains"
            value={runtimeSignals.redirectCount}
            detail={runtimeSignals.redirectCount > 1 ? 'Multi-hop redirect detected' : 'Stable navigation flow'}
            icon={Waves}
            tone={getSignalTone(runtimeSignals.redirectCount, 'redirect')}
          />
          <SignalCard
            title="Hidden iframes"
            value={runtimeSignals.hiddenIframeCount}
            detail={runtimeSignals.hiddenIframeCount > 0 ? 'Possible click hijacking surface' : 'No hidden iframe activity'}
            icon={EyeOff}
            tone={getSignalTone(runtimeSignals.hiddenIframeCount, 'iframe')}
          />
          <SignalCard
            title="Suspicious forms"
            value={runtimeSignals.suspiciousFormCount}
            detail={runtimeSignals.suspiciousFormCount > 0 ? 'Credential collection risk' : 'No risky forms detected'}
            icon={FormInput}
            tone={getSignalTone(runtimeSignals.suspiciousFormCount, 'form')}
          />
        </div>
      </div>

      <div className="surface-card rounded-[20px] p-4">
        <div className="mb-4">
          <p className="heading text-[16px]">Risk breakdown</p>
          <p className="caption">How the score is being composed right now</p>
        </div>
        <div className="space-y-4">
          <ProgressBar label="Overall risk score" value={activeResult.riskScore} tone={riskTone} caption={riskLabels[activeResult.riskLevel].description} />
          <ProgressBar label="Runtime behavior risk" value={activeResult.runtimeRisk ?? 0} tone={(activeResult.runtimeRisk ?? 0) >= 70 ? 'critical' : (activeResult.runtimeRisk ?? 0) >= 50 ? 'danger' : (activeResult.runtimeRisk ?? 0) >= 25 ? 'caution' : 'safe'} />
          <ProgressBar label="DOM mutation risk" value={activeResult.domRisk ?? 0} tone={(activeResult.domRisk ?? 0) >= 60 ? 'danger' : (activeResult.domRisk ?? 0) >= 25 ? 'caution' : 'safe'} />
          <ProgressBar label="Interaction risk" value={activeResult.interactionRisk ?? 0} tone={(activeResult.interactionRisk ?? 0) >= 60 ? 'danger' : (activeResult.interactionRisk ?? 0) >= 25 ? 'caution' : 'safe'} />
          {activeResult.reputation ? (
            <ProgressBar
              label="Community reputation pressure"
              value={Math.min(100, activeResult.reputation.averageRisk)}
              tone={activeResult.reputation.averageRisk >= 70 ? 'danger' : activeResult.reputation.averageRisk >= 35 ? 'caution' : 'safe'}
              caption={`Domain reported ${activeResult.reputation.reportCount} time${activeResult.reputation.reportCount === 1 ? '' : 's'}`}
            />
          ) : null}
        </div>
      </div>

      <ExplanationCard
        title="AI explanation"
        explanation={activeResult.aiExplanation || activeResult.explanation}
        signals={activeResult.keyIndicators}
        positives={activeResult.positives}
        warnings={activeResult.warnings}
        confidence={activeResult.confidence}
        reports={activeResult.dbReportCount}
        aiUsed={activeResult.aiUsed}
        technicalDetails={detailRows}
      />

      <div className="surface-card rounded-[20px] p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <p className="heading text-[16px]">Activity feed</p>
            <p className="caption">Latest security events from this tab</p>
          </div>
          <div className="rounded-full bg-[var(--surface-alt)] px-3 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            {activity.length} event{activity.length === 1 ? '' : 's'}
          </div>
        </div>
        <div className="max-h-[220px] space-y-3 overflow-y-auto pr-1">
          {activity.length > 0 ? (
            activity.map((item) => <ActivityItem key={`${item.type}-${item.timestamp}-${item.detail}`} item={item} />)
          ) : (
            <div className="rounded-2xl border border-dashed border-[var(--border)] bg-[var(--surface-alt)] px-4 py-5 text-center">
              <ShieldCheck className="mx-auto h-5 w-5 text-[var(--safe)]" />
              <p className="mt-2 text-[13px] font-semibold text-[var(--text-primary)]">No suspicious activity detected</p>
              <p className="caption mt-1">We’re still watching this page in real time.</p>
            </div>
          )}
        </div>
      </div>

      <div className="surface-card rounded-[20px] p-4">
        <div className="mb-3">
          <p className="heading text-[16px]">Controls</p>
          <p className="caption">Session-level actions for this site and tab</p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            disabled={isBypassing || !currentTabId || !!scanResult.bypassed}
            onClick={() =>
              withAction(
                setIsBypassing,
                async () => {
                  await sendMessage({ type: 'BYPASS_FOR_TAB', tabId: currentTabId });
                },
                'Protection paused for this tab',
                'caution'
              )
            }
            className={`min-h-11 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-60 ${activeResult.bypassed ? toneButtonMap.secondary : toneButtonMap.ghost}`}
          >
            {activeResult.bypassed ? 'Bypass Enabled' : isBypassing ? 'Pausing…' : 'Bypass This Tab'}
          </button>
          <button
            type="button"
            disabled={isAllowlisting || !!activeResult.allowlisted}
            onClick={() =>
              withAction(
                setIsAllowlisting,
                async () => {
                  await sendMessage({
                    type: 'ALLOWLIST_DOMAIN',
                    tabId: currentTabId,
                    domain: activeResult.domain,
                    url: activeResult.url,
                  });
                },
                'Domain added to allowlist'
              )
            }
            className={`min-h-11 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-60 ${activeResult.allowlisted ? toneButtonMap.secondary : toneButtonMap.danger}`}
          >
            {activeResult.allowlisted ? 'Allowlisted' : isAllowlisting ? 'Saving…' : 'Allowlist Domain'}
          </button>
          <button
            type="button"
            disabled={isRescanning || !currentTabId}
            onClick={() =>
              withAction(
                setIsRescanning,
                async () => {
                  await sendMessage({ type: 'RESCAN_TAB', tabId: currentTabId });
                },
                'Scan refreshed'
              )
            }
            className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-60 ${toneButtonMap.primary}`}
          >
            <RefreshCw className={`h-4 w-4 ${isRescanning ? 'animate-spin' : ''}`} />
            {isRescanning ? 'Rescanning…' : 'Rescan'}
          </button>
          <button
            type="button"
            onClick={openDashboard}
            className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 ${toneButtonMap.secondary}`}
          >
            <ExternalLink className="h-4 w-4" />
            Open Dashboard
          </button>
          <button
            type="button"
            onClick={() => setCurrentTab('report')}
            className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 ${toneButtonMap.ghost}`}
          >
            <Sparkles className="h-4 w-4" />
            Report Site
          </button>
          <button
            type="button"
            onClick={() => window.history.back()}
            className={`inline-flex min-h-11 items-center justify-center gap-2 rounded-xl px-4 py-3 text-[13px] font-semibold transition-all duration-200 ${toneButtonMap.ghost}`}
          >
            <ShieldOff className="h-4 w-4" />
            Go Back
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Brain className="h-4 w-4" />
            <span className="text-[12px] font-medium">AI status</span>
          </div>
          <p className="mt-2 text-[14px] font-semibold text-[var(--text-primary)] capitalize">{scanResult.modelStatus || 'offline'}</p>
        </div>
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Radar className="h-4 w-4" />
            <span className="text-[12px] font-medium">DOM changes</span>
          </div>
          <p className="mt-2 data-text text-[14px] text-[var(--text-primary)]">{runtimeSignals.domMutationCount}</p>
        </div>
        <div className="surface-card rounded-[18px] p-3">
          <div className="flex items-center gap-2 text-[var(--text-secondary)]">
            <Zap className="h-4 w-4" />
            <span className="text-[12px] font-medium">Scripts</span>
          </div>
          <p className="mt-2 data-text text-[14px] text-[var(--text-primary)]">{runtimeSignals.scriptInjectionCount}</p>
        </div>
      </div>

      <AnimatePresence>
        {toast ? (
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 8 }}
            className={`fixed bottom-4 right-4 z-50 max-w-[280px] rounded-2xl border px-4 py-3 text-[13px] font-medium shadow-[var(--shadow-elevated)] ${
              toast.tone === 'safe'
                ? 'border-[rgba(16,201,125,0.3)] bg-[#133324] text-[#b8f5d1]'
                : toast.tone === 'caution'
                  ? 'border-[rgba(217,119,6,0.3)] bg-[#362613] text-[#fbd38d]'
                  : 'border-[rgba(220,38,38,0.3)] bg-[#3b1717] text-[#fecaca]'
            }`}
          >
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              {toast.message}
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
};
