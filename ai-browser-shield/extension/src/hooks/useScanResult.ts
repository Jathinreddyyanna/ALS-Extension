import { useEffect } from 'react';
import { api } from '@/lib/api';
import { appendThreatHistory } from '@/lib/chrome';
import { useExtensionStore } from '@/store/useExtensionStore';
import type { ThreatEvent } from '@/types/index';

export const useScanResult = () => {
  const {
    currentUrl,
    currentTabId,
    sessionId,
    setScanStage,
    setScanResult,
    setScanError,
    setIsScanning
  } = useExtensionStore();

  useEffect(() => {
    if (!currentUrl) return;
    let mounted = true;
    setIsScanning(true);
    setScanError(null);
    setScanStage(0);

    const timerA = window.setTimeout(() => mounted && setScanStage(1), 400);
    const timerB = window.setTimeout(() => mounted && setScanStage(2), 800);

    void api.scanUrl({ url: currentUrl, tabId: currentTabId ?? undefined, sessionId }).then(async (result) => {
      if (!mounted) return;
      setScanResult(result);
      setIsScanning(false);
      if (!result.skip) {
        const event: ThreatEvent = {
          id: `${result.domain}-${Date.now()}`,
          eventType: 'url_threat',
          domain: result.domain,
          url: result.url,
          riskScore: result.riskScore,
          riskLevel: result.riskLevel,
          aiExplanation: result.explanation,
          timestamp: Date.now()
        };
        await appendThreatHistory(event);
      }
    }).catch((error: { message?: string }) => {
      if (!mounted) return;
      setIsScanning(false);
      setScanError(error.message ?? 'Protection system temporarily offline - heuristic analysis only');
    });

    return () => {
      mounted = false;
      window.clearTimeout(timerA);
      window.clearTimeout(timerB);
    };
  }, [currentTabId, currentUrl, sessionId, setIsScanning, setScanError, setScanResult, setScanStage]);
};
