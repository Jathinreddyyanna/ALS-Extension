import type { ContentCategory } from '../types/scan.types';

export interface BehaviorClassificationResult {
  contentCategory: ContentCategory;
  behaviorRisk: number;
  warnings: string[];
}

export interface RuntimeRiskResult {
  runtimeRisk: number;
  warnings: string[];
  signalsUsed: string[];
}

const STREAMING_HINTS = ['stream', 'watch', 'movie', 'series', 'episode', 'ott', 'live-tv', 'sports'];
const DOWNLOAD_HINTS = ['download', 'setup', 'installer', 'apk', 'crack', 'zip', 'exe', 'torrent'];
const ADULT_HINTS = ['adult', 'xxx', 'sex', 'porn', 'cam', 'escort'];
const FINANCIAL_HINTS = ['bank', 'wallet', 'upi', 'payment', 'card', 'loan', 'netbanking'];
const LOGIN_HINTS = ['login', 'signin', 'verify', 'password', 'otp', 'account', 'auth'];

const includesAny = (value: string, patterns: string[]): boolean => patterns.some((item) => value.includes(item));

export function classifyContentCategory(rawUrl: string, hostname: string): ContentCategory {
  const combined = `${hostname}${rawUrl}`.toLowerCase();
  if (includesAny(combined, LOGIN_HINTS)) return 'login';
  if (includesAny(combined, FINANCIAL_HINTS)) return 'financial';
  if (includesAny(combined, DOWNLOAD_HINTS)) return 'download';
  if (includesAny(combined, STREAMING_HINTS)) return 'streaming';
  if (includesAny(combined, ADULT_HINTS)) return 'adult';
  return 'unknown';
}

export function computeBehaviorRisk(input: {
  contentCategory: ContentCategory;
  domainAgeDays: number | null;
  cheapHosting: boolean;
  suspiciousKeywordScore: number;
}): BehaviorClassificationResult {
  let behaviorRisk = 0;
  const warnings: string[] = [];

  if (input.contentCategory === 'streaming') {
    behaviorRisk += 30;
    warnings.push('This site may contain intrusive ads and redirects');
  }
  if (input.contentCategory === 'download') {
    behaviorRisk += 35;
    warnings.push('This site may expose you to unsafe downloads');
  }
  if (input.contentCategory === 'adult') {
    behaviorRisk += 25;
  }
  if (input.contentCategory === 'login') {
    behaviorRisk += 40;
  }
  if (input.contentCategory === 'financial') {
    behaviorRisk += 25;
  }

  if (input.domainAgeDays !== null && input.domainAgeDays < 30 && input.contentCategory === 'login') {
    behaviorRisk += 30;
  }
  if (input.cheapHosting && input.contentCategory === 'streaming') {
    behaviorRisk += 20;
  }
  if (input.suspiciousKeywordScore > 0) {
    behaviorRisk += 10;
  }
  if (input.contentCategory === 'unknown') {
    warnings.push('Limited data available - proceed with caution');
  }

  return {
    contentCategory: input.contentCategory,
    behaviorRisk: Math.min(100, behaviorRisk),
    warnings
  };
}

export function computeRuntimeRisk(input: {
  signals?: Record<string, number>;
  requestContext?: { tabCount?: number; timeOnPage?: number; referrer?: string };
}): RuntimeRiskResult {
  const signals = input.signals ?? {};
  let runtimeRisk = 0;
  const warnings: string[] = [];
  const signalsUsed: string[] = [];

  const popupScore = Math.min(30, Number(signals.popupFrequency ?? signals.popupCount ?? 0) * 10);
  if (popupScore > 0) {
    runtimeRisk += popupScore;
    warnings.push('This page is generating excessive popups');
    signalsUsed.push('popup_abuse');
  }

  const redirectScore = Math.min(30, Number(signals.redirectChains ?? signals.redirectCount ?? 0) * 8);
  if (redirectScore > 0) {
    runtimeRisk += redirectScore;
    warnings.push('This page is chaining redirects after interaction');
    signalsUsed.push('redirect_chain');
  }

  const downloadScore = Math.min(30, Number(signals.downloadTriggers ?? signals.downloadCount ?? 0) * 10);
  if (downloadScore > 0) {
    runtimeRisk += downloadScore;
    warnings.push('This page is triggering downloads aggressively');
    signalsUsed.push('download_trigger');
  }

  const permissionScore = Math.min(20, Number(signals.permissionAbuse ?? 0) * 10);
  if (permissionScore > 0) {
    runtimeRisk += permissionScore;
    warnings.push('This page is requesting risky browser permissions');
    signalsUsed.push('permission_abuse');
  }

  const navigationHijackScore = Math.min(20, Number(signals.navigationHijacks ?? signals.historyManipulation ?? 0) * 10);
  if (navigationHijackScore > 0) {
    runtimeRisk += navigationHijackScore;
    warnings.push('This page is manipulating navigation flow');
    signalsUsed.push('navigation_hijack');
  }

  if ((input.requestContext?.tabCount ?? 0) > 6) {
    runtimeRisk += 10;
    warnings.push('This page is causing tab explosions');
    signalsUsed.push('tab_explosion');
  }
  if ((input.requestContext?.timeOnPage ?? 60) < 5) {
    runtimeRisk += 5;
    signalsUsed.push('session_duration_anomaly');
  }

  return {
    runtimeRisk: Math.min(100, runtimeRisk),
    warnings: Array.from(new Set(warnings)),
    signalsUsed: Array.from(new Set(signalsUsed))
  };
}
