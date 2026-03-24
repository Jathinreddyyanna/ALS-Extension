import { useEffect } from 'react';
import { appendThreatHistory } from '@/lib/chrome';
import { useExtensionStore } from '@/store/useExtensionStore';
import { scoreUrl } from '@/detection/urlScorer';
import type { ThreatEvent, UrlScanResult } from '@/types/index';

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
    if (
      currentUrl.startsWith('chrome://') ||
      currentUrl.startsWith('about:') ||
      currentUrl.startsWith('chrome-extension://') ||
      currentUrl.startsWith('devtools://')
    ) {
      return;
    }
    let mounted = true;
    setIsScanning(true);
    setScanError(null);
    setScanResult(null);
    setScanStage(0);

    const timerA = window.setTimeout(() => mounted && setScanStage(1), 400);
    const timerB = window.setTimeout(() => mounted && setScanStage(2), 800);

    const local = scoreUrl(currentUrl);
    const fallbackResult: UrlScanResult = {
      url: currentUrl,
      domain: (() => {
        try {
          return new URL(currentUrl).hostname;
        } catch {
          return '';
        }
      })(),
      riskScore: local.score,
      riskLevel: local.riskLevel,
      explanation: 'Heuristic analysis - AI unavailable',
      aiExplanation: '',
      keyIndicators: [],
      positives: [],
      warnings: ['Protection system is in fallback mode'],
      recommendedAction: 'warn',
      confidence: 0,
      category: 'unknown',
      categories: [],
      heuristic: local.score,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: false,
      aiDegraded: true,
      aiSource: 'heuristic',
      processedMs: 0,
      urlType: 'website',
      source: 'heuristic'
    };

    const persistThreatEvent = async (result: UrlScanResult) => {
      if (result.skip) return;
      const event: ThreatEvent = {
        id: `${result.domain}-${Date.now()}`,
        eventType: 'url_threat',
        domain: result.domain,
        url: result.url,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        aiExplanation: result.explanation,
        source: result.aiSource || result.source,
        timestamp: Date.now()
      };
      await appendThreatHistory(event);
    };

    const applyResult = async (result: UrlScanResult | null) => {
      const finalResult = result ?? fallbackResult;
      setScanResult(finalResult);
      setIsScanning(false);
      setScanError(result ? null : 'Protection system temporarily offline - heuristic analysis only');
      await persistThreatEvent(finalResult);
    };

    const messageListener = (message: { type?: string; tabId?: number; payload?: any }) => {
      if (!mounted) return;
      if (typeof currentTabId === 'number' && message.tabId !== currentTabId) return;

      if (message.type === 'SCAN_UPDATED' && message.payload) {
        setScanResult(message.payload);
        setIsScanning(false);
        setScanError(null);
        return;
      }

      if (message.type === 'SENSITIVE_DATA_RISK' && message.payload) {
        setScanResult((prev) => prev ? { ...prev, sensitiveDataRisk: message.payload } : prev);
      }
    };

    chrome.runtime.onMessage.addListener(messageListener);

    try {
      chrome.runtime.sendMessage(
        {
          type: 'GET_SCAN_DATA',
          tabId: currentTabId ?? undefined,
          url: currentUrl,
          sessionId
        },
        (result: UrlScanResult | null) => {
          if (!mounted) return;
          if (chrome.runtime.lastError) {
            void applyResult(null);
            return;
          }
          void applyResult(result);
        }
      );
    } catch {
      void applyResult(null);
    }

    return () => {
      mounted = false;
      window.clearTimeout(timerA);
      window.clearTimeout(timerB);
      chrome.runtime.onMessage.removeListener(messageListener);
    };
  }, [currentTabId, currentUrl, sessionId, setIsScanning, setScanError, setScanResult, setScanStage]);
};
