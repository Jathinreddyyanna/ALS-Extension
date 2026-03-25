import { useEffect, useRef, useCallback } from 'react';
import { appendThreatHistory } from '@/lib/chrome';
import { useExtensionStore } from '@/store/useExtensionStore';
import { scoreUrl } from '@/detection/urlScorer';
import type { ThreatEvent, UrlScanResult } from '@/types/index';

// Debounce time to prevent rapid state updates causing UI flicker
const SCAN_UPDATE_DEBOUNCE_MS = 100;

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

  // Track last update time to debounce rapid updates
  const lastUpdateRef = useRef(0);
  const pendingUpdateRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const previousUrlRef = useRef<string>('');

  // Debounced scan result update to prevent flicker
  const debouncedSetScanResult = useCallback((result: UrlScanResult) => {
    const now = Date.now();
    const timeSinceLastUpdate = now - lastUpdateRef.current;

    if (pendingUpdateRef.current) {
      clearTimeout(pendingUpdateRef.current);
    }

    if (timeSinceLastUpdate < SCAN_UPDATE_DEBOUNCE_MS) {
      // Debounce: wait before updating
      pendingUpdateRef.current = setTimeout(() => {
        lastUpdateRef.current = Date.now();
        setScanResult(result);
        setIsScanning(false);
        setScanError(null);
      }, SCAN_UPDATE_DEBOUNCE_MS - timeSinceLastUpdate);
    } else {
      // Enough time has passed, update immediately
      lastUpdateRef.current = now;
      setScanResult(result);
      setIsScanning(false);
      setScanError(null);
    }
  }, [setScanResult, setIsScanning, setScanError]);

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

    // Check if URL actually changed
    const urlChanged = currentUrl !== previousUrlRef.current;
    previousUrlRef.current = currentUrl;

    let mounted = true;

    // Only show loading state if URL actually changed
    if (urlChanged) {
      setIsScanning(true);
      setScanError(null);
      // Don't reset scanResult to null - keep previous result visible
      // This prevents the "flash" to empty state
      setScanStage(0);
    }

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
      debouncedSetScanResult(finalResult);
      await persistThreatEvent(finalResult);
    };

    const messageListener = (message: { type?: string; tabId?: number; payload?: any }) => {
      if (!mounted) return;
      if (typeof currentTabId === 'number' && message.tabId !== currentTabId) return;

      if (message.type === 'SCAN_UPDATED' && message.payload) {
        // Use debounced update to prevent flicker from rapid messages
        debouncedSetScanResult(message.payload);
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
      if (pendingUpdateRef.current) {
        clearTimeout(pendingUpdateRef.current);
      }
      chrome.runtime.onMessage.removeListener(messageListener);
    };
  }, [currentTabId, currentUrl, sessionId, setIsScanning, setScanError, setScanResult, setScanStage, debouncedSetScanResult]);
};
