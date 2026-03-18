import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { riskLabels, plainSignalLabels } from '@/lib/riskLabels';
import { useExtensionStore } from '@/store/useExtensionStore';
import type { UrlScanResult } from '@/types/index';
import { ActionBar } from '../components/ActionBar';
import { ErrorBanner } from '../components/ErrorBanner';
import { ExplanationCard } from '../components/ExplanationCard';
import { RiskBadge } from '../components/RiskBadge';
import { RiskMeter } from '../components/RiskMeter';
import { ScanProgressBar } from '../components/ScanProgressBar';
import { ShieldIcon } from '../components/ShieldIcon';
import { SiteTrustPanel } from '../components/SiteTrustPanel';

const AiSourceBadge = ({ result }: { result: UrlScanResult }) => (
  <div className="ai-source-row mt-2 flex justify-center">
    {result.aiSource === 'gemini' ? (
      <div className="ai-badge gemini flex items-center gap-1 rounded-lg border border-[#7c3aed33] bg-[linear-gradient(135deg,#1a1a2e_0%,#16213e_100%)] px-3 py-2 text-[12px] font-medium text-[#a78bfa]">
        <span className="ai-icon">✦</span>
        <span className="ai-label">Powered by Gemini AI</span>
        {result.modelUsed && <span className="ai-model text-[10px] text-[#94a3b8]">· {result.modelUsed}</span>}
      </div>
    ) : result.aiSource === 'heuristic' ? (
      <div className="ai-badge heuristic flex items-center gap-1 rounded-lg border border-[#f59e0b33] bg-[#1c1a14] px-3 py-2 text-[12px] font-medium text-[#fbbf24]">
        <span className="ai-icon">!</span>
        <span className="ai-label">Heuristic analysis used</span>
        <span className="ai-sub text-[10px] text-[#d97706]">AI temporarily unavailable</span>
      </div>
    ) : (
      <div className="ai-badge unknown flex items-center gap-1 rounded-lg border border-[#374151] bg-[#141414] px-3 py-2 text-[12px] font-medium text-[#6b7280]">
        <span className="ai-icon">o</span>
        <span className="ai-label">Analysis in progress...</span>
      </div>
    )}
  </div>
);

export const ShieldTab = () => {
  const { currentDomain, isScanning, scanStage, scanResult, scanError, setCurrentTab } = useExtensionStore();
  const [detailsOpen, setDetailsOpen] = useState(false);

  if (scanError) {
    return (
      <div className="flex flex-col gap-5">
        <div className="surface-card flex flex-col items-center gap-4 p-6 text-center">
          <ShieldIcon status="idle" />
          <p className="heading">Protection is temporarily limited</p>
          <p className="caption">We could not reach full analysis just now. Local checks are still watching quietly.</p>
        </div>
        <ErrorBanner message={scanError} />
      </div>
    );
  }

  if (isScanning || !scanResult) {
    return (
      <div className="flex flex-col items-center gap-6 px-1 py-2 text-center">
        <ShieldIcon status="scanning" size={130} />
        <div>
          <p className="heading">Analysing {currentDomain || 'this site'}...</p>
          <p className="caption mt-2">We are checking the web address, asking the AI for a second opinion, and reading community reports.</p>
        </div>
        <ScanProgressBar stage={scanStage} />
      </div>
    );
  }

  if (scanResult.skip || scanResult.riskLevel === 'LOW') {
    return (
      <div className="flex flex-col items-center gap-5 text-center">
        <div className="flex flex-col items-center gap-4">
          <ShieldIcon status="safe" size={138} />
          <div>
            <p className="heading">{currentDomain || scanResult.domain}</p>
            <div className="mt-3 flex justify-center">
              <RiskBadge riskLevel="LOW" />
            </div>
          </div>
          <p className="max-w-[280px] text-body">{riskLabels.LOW.description}</p>
          <AiSourceBadge result={scanResult} />
        </div>
        <SiteTrustPanel domain={scanResult.domain || currentDomain} />
      </div>
    );
  }

  const shieldStatus = scanResult.riskLevel === 'CRITICAL' ? 'critical' : scanResult.riskLevel === 'HIGH' ? 'danger' : 'caution';

  return (
    <div className="space-y-4">
      <motion.div initial={{ opacity: 0.6 }} animate={{ opacity: 1 }} className="flex flex-col items-center gap-4 text-center">
        <ShieldIcon status={shieldStatus} size={120} />
        <RiskMeter score={scanResult.riskScore} riskLevel={scanResult.riskLevel} animated />
        <RiskBadge riskLevel={scanResult.riskLevel} size="lg" />
        <AiSourceBadge result={scanResult} />
      </motion.div>
      <ExplanationCard
        explanation={scanResult.aiExplanation || scanResult.explanation}
        signals={scanResult.keyIndicators}
        confidence={scanResult.confidence}
        reports={scanResult.dbReportCount}
      />
      <ActionBar onBack={() => window.history.back()} onProceed={() => window.close()} onReport={() => setCurrentTab('report')} />
      <button type="button" onClick={() => setDetailsOpen((value) => !value)} className="flex w-full items-center justify-center gap-2 text-caption text-[var(--text-secondary)]">
        Show full analysis
        <ChevronDown className={`h-4 w-4 transition-transform ${detailsOpen ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence>
        {detailsOpen && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="surface-card space-y-3 p-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="caption">AI analysis confidence</p>
                  <p className="data-text mt-1">{Math.round(scanResult.confidence * 100)}%</p>
                </div>
                <div>
                  <p className="caption">Community reports</p>
                  <p className="data-text mt-1">{scanResult.dbReportCount}</p>
                </div>
              </div>
              <div>
                <p className="caption">What we noticed</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {scanResult.keyIndicators.map((indicator) => (
                    <span key={indicator} className="rounded-full bg-[var(--surface-alt)] px-3 py-1 text-caption">
                      {plainSignalLabels[indicator] ?? indicator}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <p className="caption">First seen by the system</p>
                <p className="text-body">Today</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
