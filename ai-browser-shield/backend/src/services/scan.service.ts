import { prisma } from '../db/client';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { resolveAllowlist } from './allowlist.service';
import { cacheGetJSON, cacheKeys, cacheService, cacheSetJSON } from './cache.service';
import { analyzeDomain } from './domainIntelligence.service';
import { enrichDomainSignals } from './domainEnrichment.service';
import { computeHeuristics, type HeuristicResult } from './scoring.service';
import { getReputation, type ReputationResult } from './reputation.service';
import { makeDecision } from './decision.service';
import { generateExplanation } from './explanation.service';
import { localPersistence } from './localPersistence.service';
import { aggregateThreatIntel } from './threatIntel.service';
import type { ThreatIntelAggregateResult } from './threatIntel.service';
import { classifyContentCategory, computeBehaviorRisk, computeRuntimeRisk } from './behaviorRisk.service';
import { computeDomRisk, computeInteractionRisk } from './pageInteraction.service';
import { hashIp } from '../utils/ip';
import { logger } from '../utils/logger';
import type { Category, RiskLevel, UrlScanResult } from '../types/scan.types';

const VERIFIED_SAFE_DOMAINS = new Set([
  'google.com', 'github.com', 'stackoverflow.com', 'youtube.com',
  'microsoft.com', 'apple.com', 'amazon.com', 'linkedin.com', 'wikipedia.org'
]);

const PIRACY_KEYWORDS = [
  'filmyzilla', 'movierulz', 'tamilrockers', 'torrent', 'piracy',
  'moviescounter', '1337x', 'yts', 'rarbg', 'katcr', 'fmovies',
  'gomovies', 'putlocker', '123movies', 'solarmovie', 'dramacool',
  'kissasian', 'anime', 'hdmovie', 'fullmovie', 'downloadhub',
  'filmywap', 'jiorockers', 'isaimini', 'kuttymovies', 'cinemavilla',
  'warez', 'filmyzap', 'bolly4u', 'vegamovies', 'moviesflix'
];

const PIRACY_TLDS = new Set([
  'rest', 'codes', 'florist', 'cyou', 'icu', 'sbs', 'top',
  'click', 'loan', 'cam', 'tk', 'ml', 'ga', 'cf', 'gq',
  'xyz', 'zip', 'mov', 'monster', 'fin', 'phd'
]);

const PHISHING_BRANDS = [
  'paypal', 'sbi', 'hdfc', 'icici', 'axisbank', 'amazon',
  'google', 'microsoft', 'apple', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'paytm', 'phonepe', 'gpay',
  'binance', 'coinbase', 'metamask', 'blockchain'
];

const PHISHING_ACTIONS = [
  'verify', 'login', 'signin', 'secure', 'update',
  'confirm', 'account', 'banking', 'netbanking', 'wallet',
  'suspended', 'unusual', 'activity', 'limited', 'restore', 'unlock'
];

const SIGNAL_WEIGHTS: Record<string, number> = {
  brand_impersonation_phishing: 1.0,
  piracy_with_abuse: 1.0,
  malicious_script_injection: 1.0,
  overlay_trap: 0.9,
  click_interception: 0.9,
  hidden_iframes: 0.8,
  piracy_site: 0.8,
  redirect_chain: 0.8,
  popup_abuse: 0.8,
  typosquat_suspicious_tld: 0.8,
  ip_hostname: 0.75,
  suspicious_form_count: 0.75,
  piracy_keyword: 0.5,
  suspicious_tld_with_keywords: 0.5,
  brand_impersonation: 0.5,
  unknown_domain: 0.4,
  cheap_hosting: 0.4,
  minor_keyword_flag: 0.3,
  suspicious_tld: 0.3
};

const verdictFromRiskLevel = (riskLevel: RiskLevel): 'safe' | 'suspicious' | 'malicious' => (
  riskLevel === 'CRITICAL' || riskLevel === 'HIGH'
    ? 'malicious'
    : riskLevel === 'MEDIUM'
      ? 'suspicious'
      : 'safe'
);

const isVerifiedSafeDomain = (hostname: string): boolean => {
  const clean = hostname.replace(/^www\./, '').toLowerCase();
  return VERIFIED_SAFE_DOMAINS.has(clean);
};

const getCacheTtl = (riskLevel: RiskLevel): number => (
  riskLevel === 'LOW' ? 60 * 60 * 24
    : riskLevel === 'MEDIUM' ? 60 * 30
      : riskLevel === 'HIGH' ? 60 * 15
        : 60 * 5
);

const buildHeuristicExplanationFallback = () => ({
  explanation: 'AI analysis temporarily unavailable. Risk assessed using pattern matching and domain intelligence.',
  aiExplanation: 'Heuristic fallback — Gemini quota reached or all models exhausted.',
  riskLevel: 'LOW' as const,
  recommendedAction: 'allow' as const,
  confidence: 0.6,
  keyIndicators: [] as string[],
  aiSource: 'heuristic' as const,
  riskScore: 10,
  threatCategory: 'unknown' as const
});

const applyThreatBoosters = (
  url: string,
  hostname: string,
  heuristic: HeuristicResult
): HeuristicResult => {
  const boostedSignals = { ...heuristic.signals };
  const boostedSignalsUsed = [...heuristic.signalsUsed];
  const boostedWarnings = [...heuristic.warnings];
  let boostedScore = heuristic.score;

  const urlLower = url.toLowerCase();
  const tld = hostname.split('.').pop()?.toLowerCase() ?? '';
  const hasPiracyKeyword = PIRACY_KEYWORDS.some((keyword) => urlLower.includes(keyword));
  const hasPiracyTld = PIRACY_TLDS.has(tld);

  if (hasPiracyKeyword && hasPiracyTld) {
    boostedScore += 40;
    boostedSignals.piracyPattern = 1;
    boostedSignalsUsed.push('piracy_keyword_and_tld');
    boostedWarnings.push('Piracy-style domain pattern');
  } else if (hasPiracyKeyword) {
    boostedScore += 20;
    boostedSignals.piracyKeyword = 1;
    boostedSignalsUsed.push('piracy_keyword');
    boostedWarnings.push('Piracy-style keyword');
  } else if (hasPiracyTld && boostedScore >= 15) {
    boostedScore += 15;
    boostedSignals.suspiciousTLD = Math.max(boostedSignals.suspiciousTLD ?? 0, 1);
    boostedSignalsUsed.push('suspicious_tld_boost');
    boostedWarnings.push('Suspicious top-level domain');
  }

  const hasBrandImpersonation = PHISHING_BRANDS.some((brand) => hostname.includes(brand)) &&
    PHISHING_ACTIONS.some((action) => urlLower.includes(action));

  if (hasBrandImpersonation && !isVerifiedSafeDomain(hostname)) {
    boostedScore += 50;
    boostedSignals.brandImpersonation = Math.max(boostedSignals.brandImpersonation ?? 0, 50);
    boostedSignalsUsed.push('brand_impersonation_pattern');
    boostedWarnings.push('Brand impersonation pattern');
  }

  return {
    ...heuristic,
    score: Math.min(100, boostedScore),
    signals: boostedSignals,
    signalsUsed: Array.from(new Set(boostedSignalsUsed)),
    warnings: Array.from(new Set(boostedWarnings))
  };
};

const computeSignalConfidenceMultiplier = (detectedPatterns: string[]): number => {
  if (detectedPatterns.length === 0) return 0.7;

  const totalWeight = detectedPatterns.reduce((sum, pattern) => sum + (SIGNAL_WEIGHTS[pattern] ?? 0.4), 0);
  const avgWeight = totalWeight / detectedPatterns.length;
  return Math.min(1.15, Math.max(0.75, 0.75 + (avgWeight * 0.4)));
};

const computeThreatSignals = (
  url: string,
  hostname: string,
  signals: Record<string, number>
): { boost: number; detectedPatterns: string[] } => {
  const urlLower = url.toLowerCase();
  const hostLower = hostname.toLowerCase();
  const tld = hostname.split('.').pop()?.toLowerCase() ?? '';
  let boost = 0;
  const detectedPatterns: string[] = [];

  const hasPiracyKeyword = PIRACY_KEYWORDS.some((keyword) => urlLower.includes(keyword));
  const hasPiracyTld = PIRACY_TLDS.has(tld);
  const hasRuntimeAbuse = (signals.popupFrequency ?? 0) > 0 || (signals.redirectChains ?? 0) > 0;

  if (hasPiracyKeyword && hasPiracyTld && hasRuntimeAbuse) {
    boost += 55;
    detectedPatterns.push('piracy_with_abuse');
  } else if (hasPiracyKeyword && hasPiracyTld) {
    boost += 40;
    detectedPatterns.push('piracy_site');
  } else if (hasPiracyKeyword) {
    boost += 20;
    detectedPatterns.push('piracy_keyword');
  } else if (hasPiracyTld && (signals.suspiciousKeywords ?? 0) > 0) {
    boost += 15;
    detectedPatterns.push('suspicious_tld_with_keywords');
  }

  const hasBrandName = PHISHING_BRANDS.some((brand) => hostLower.includes(brand));
  const hasActionWord = PHISHING_ACTIONS.some((action) => urlLower.includes(action));
  if (hasBrandName && hasActionWord && !isVerifiedSafeDomain(hostname)) {
    boost += 55;
    detectedPatterns.push('brand_impersonation_phishing');
  }

  if ((signals.typosquatScore ?? 0) > 0 && hasPiracyTld) {
    boost += 20;
    detectedPatterns.push('typosquat_suspicious_tld');
  }

  if ((signals.ipAsHostname ?? 0) > 0) {
    boost += 20;
    detectedPatterns.push('ip_hostname');
  }

  if ((signals.overlayTrap ?? 0) > 0) detectedPatterns.push('overlay_trap');
  if ((signals.hiddenIframes ?? 0) > 0) detectedPatterns.push('hidden_iframes');
  if ((signals.clickInterception ?? 0) > 0) detectedPatterns.push('click_interception');
  if ((signals.suspiciousFormCount ?? 0) > 0) detectedPatterns.push('suspicious_form_count');
  if ((signals.popupFrequency ?? 0) > 0) detectedPatterns.push('popup_abuse');
  if ((signals.redirectChains ?? 0) > 0) detectedPatterns.push('redirect_chain');
  if ((signals.domRisk ?? 0) >= 60) detectedPatterns.push('malicious_script_injection');

  return { boost, detectedPatterns: Array.from(new Set(detectedPatterns)) };
};

const deriveCategory = (
  riskLevel: RiskLevel,
  heuristic: HeuristicResult,
  reputation: ReputationResult
): Category => {
  if (riskLevel === 'LOW') return 'clean';
  if (reputation.categories.length > 0) {
    return (reputation.categories[0] as Category) ?? 'unknown';
  }
  if (heuristic.signals.typosquatScore || heuristic.signals.suspiciousKeywords || heuristic.signals.brandImpersonation || heuristic.signals.subdomainSpoofing || heuristic.signals.homoglyphRisk) return 'phishing';
  if (heuristic.signals.suspiciousTLD || heuristic.signals.ipAsHostname) return 'scam';
  return 'unknown';
};

const buildLocalResult = (
  inputUrl: string,
  domain: string,
  urlType: UrlScanResult['urlType'],
  explanation: string,
  started: number
): UrlScanResult => ({
  url: inputUrl,
  domain,
  riskScore: 0,
  riskLevel: 'LOW',
  explanation,
  aiExplanation: explanation,
  keyIndicators: [],
  positives: [],
  warnings: [],
  recommendedAction: 'allow',
  confidence: 0.95,
  category: 'clean',
  categories: [],
  verdict: 'safe',
  heuristic: 0,
  dbRiskScore: 0,
  dbReportCount: 0,
  cached: false,
  aiDegraded: true,
  aiSource: 'heuristic',
  aiUsed: false,
  processedMs: Date.now() - started,
  urlType,
  source: 'local_context',
  threatSource: 'internal',
  sources: [],
  confidenceLevel: 'high',
  analysisDepth: 'fast',
  safeBrowsingMatched: false,
  safeBrowsingThreatTypes: [],
  signalsUsed: [],
  trustSignals: [],
  contentCategory: 'unknown',
  behaviorRisk: 0,
  runtimeRisk: 0,
  domRisk: 0,
  interactionRisk: 0,
  warningsEnhanced: [],
  allowlisted: false,
  reputationStatus: 'unknown',
  decisionBasis: 'local_context'
});

export const performUrlScan = async (input: {
  url: string;
  signals?: Record<string, number>;
  sessionId?: string;
  tabId?: number;
  requestContext?: { referrer?: string; tabCount?: number; timeOnPage?: number };
  ip?: string;
  userAgent?: string;
  forceAi?: boolean;
  requestId?: string;
  userGeminiKey?: string;
}): Promise<UrlScanResult> => {
  const started = Date.now();
  const parsed = parseAndNormalizeUrl(input.url);

  if (parsed.skip) {
    return {
      url: input.url,
      domain: parsed.domain,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: 'Skipped browser internal URL.',
      aiExplanation: 'Skipped browser internal URL.',
      keyIndicators: [],
      positives: [],
      warnings: [],
      recommendedAction: 'allow',
      confidence: 1,
      category: 'clean',
      heuristic: 0,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: false,
      aiDegraded: true,
      aiSource: 'heuristic',
      aiUsed: false,
      processedMs: Date.now() - started,
      urlType: parsed.urlType,
      skip: true,
      reason: parsed.skipReason,
      source: 'browser_internal',
      threatSource: 'internal',
      sources: [],
      confidenceLevel: 'high',
      analysisDepth: 'fast',
      safeBrowsingMatched: false,
      safeBrowsingThreatTypes: [],
      signalsUsed: [],
      trustSignals: [],
      contentCategory: 'unknown',
      behaviorRisk: 0,
      runtimeRisk: 0,
      domRisk: 0,
      interactionRisk: 0,
      warningsEnhanced: [],
      allowlisted: false,
      reputationStatus: 'unknown',
      decisionBasis: 'browser_internal'
    };
  }

  if (['localhost', 'private_ip', 'file', 'data', 'internal', 'blob'].includes(parsed.urlType)) {
    return buildLocalResult(
      input.url,
      parsed.domain,
      parsed.urlType,
      parsed.urlType === 'file'
        ? 'Local file URL detected.'
        : parsed.urlType === 'data'
          ? 'Data URL detected.'
          : 'Internal or local URL detected.',
      started
    );
  }

  const cacheKey = cacheKeys.urlScan(parsed.normalizedUrl);
  if (!input.forceAi) {
    const cached = await cacheGetJSON<UrlScanResult>(cacheKey);
    if (cached) {
      return { ...cached, cached: true, processedMs: Date.now() - started };
    }
  }

  const lockKey = `scan:${cacheKey}`;
  const lockAcquired = await cacheService.acquireLock(lockKey, 10_000);
  let canUseAi = true;

  try {
    if (!lockAcquired && !input.forceAi) {
      await new Promise((resolve) => setTimeout(resolve, 200));
      const afterWait = await cacheGetJSON<UrlScanResult>(cacheKey);
      if (afterWait) {
        return { ...afterWait, cached: true, processedMs: Date.now() - started };
      }
      canUseAi = false;
    }

    const intel = analyzeDomain(parsed.normalizedUrl);
    const allowlistPromise = resolveAllowlist(intel.registeredDomain);
    const reputationPromise = getReputation(intel.registeredDomain).catch(() => ({
      domainRiskScore: 0,
      reportCount: 0,
      categories: [],
      isConfirmed: false,
      reputationStatus: 'unknown' as const,
      confidenceLevel: 'unknown' as const
    }));
    const enrichmentPromise = enrichDomainSignals({
      hostname: intel.hostname,
      registeredDomain: intel.registeredDomain,
      isHTTPS: intel.isHTTPS,
      isOfficialTLD: intel.isOfficialTLD
    });
    const threatIntel = await aggregateThreatIntel(parsed.normalizedUrl).catch((error): ThreatIntelAggregateResult => {
      logger.warn({ err: error, url: parsed.normalizedUrl }, 'threat intel aggregation failed, falling back to internal engine');
      return {
        isMalicious: false,
        sources: [] as string[],
        threatTypes: [] as string[],
        threatSource: 'internal' as const,
        confidenceLevel: 'low' as const,
        matchedProviders: []
      };
    });
    if (threatIntel.isMalicious && threatIntel.threatSource === 'google') {
      const response: UrlScanResult = {
        url: input.url,
        domain: intel.registeredDomain,
        riskScore: 100,
        riskLevel: 'CRITICAL',
        explanation: 'Google Safe Browsing has identified this URL as malicious. This site should be blocked immediately.',
        aiExplanation: 'Google Safe Browsing has identified this URL as malicious. This site should be blocked immediately.',
        keyIndicators: ['Google Safe Browsing match', ...threatIntel.threatTypes],
        positives: [],
        warnings: ['Confirmed malicious by Google Safe Browsing'],
        recommendedAction: 'block',
        confidence: 0.99,
        confidenceLevel: 'high',
        category: 'phishing',
        categories: threatIntel.threatTypes,
        verdict: 'malicious',
        heuristic: 0,
        dbRiskScore: 0,
        dbReportCount: 0,
        cached: false,
        aiDegraded: true,
        aiSource: 'heuristic',
        aiUsed: false,
        processedMs: Date.now() - started,
        urlType: parsed.urlType,
        source: 'google_safe_browsing',
        threatSource: 'google',
        sources: threatIntel.sources,
        analysisDepth: 'fast',
        safeBrowsingMatched: true,
        safeBrowsingThreatTypes: threatIntel.threatTypes,
        signalsUsed: ['google_safe_browsing'],
        trustSignals: [],
        contentCategory: 'unknown',
        behaviorRisk: 0,
        runtimeRisk: 0,
        domRisk: 0,
        interactionRisk: 0,
        warningsEnhanced: ['Google Safe Browsing has confirmed this page as harmful'],
        allowlisted: false,
        reputationStatus: 'unknown',
        decisionBasis: 'google_safe_browsing'
      };

      await cacheSetJSON(cacheKey, response, 600);

      const ipHash = hashIp(input.ip ?? '0.0.0.0');
      void prisma.detectionEvent.create({
        data: {
          eventType: 'url_threat',
          domain: intel.registeredDomain,
          url: input.url,
          riskScore: response.riskScore,
          riskLevel: response.riskLevel,
          signals: {
            signalsUsed: ['google_safe_browsing'],
            safeBrowsingThreatTypes: threatIntel.threatTypes,
            decisionBasis: 'google_safe_browsing',
            requestSignals: input.signals ?? {},
            tabId: input.tabId
          },
          aiExplanation: response.explanation,
          ipHash,
          userAgent: input.userAgent,
          sessionId: input.sessionId
        }
      }).catch(() => localPersistence.createDetectionEvent({
        eventType: 'url_threat',
        domain: intel.registeredDomain,
        url: input.url,
        riskScore: response.riskScore,
        riskLevel: response.riskLevel,
        signals: {
          signalsUsed: ['google_safe_browsing'],
          safeBrowsingThreatTypes: threatIntel.threatTypes,
          decisionBasis: 'google_safe_browsing',
          requestSignals: input.signals ?? {},
          tabId: input.tabId
        },
        aiExplanation: response.explanation,
        ipHash,
        userAgent: input.userAgent,
        sessionId: input.sessionId,
        domainScoreId: undefined,
        fileScanId: undefined
      })).catch(() => undefined);

      return response;
    }

    const [allowlist, reputation, enrichment] = await Promise.all([allowlistPromise, reputationPromise, enrichmentPromise]);
    const trustSignals = Array.from(new Set([...intel.positives, ...enrichment.positives]));
    const runtime = computeRuntimeRisk({ signals: input.signals, requestContext: input.requestContext });
    const domInspection = computeDomRisk(input.signals);
    const interaction = computeInteractionRisk(input.signals);
    const contentCategory = classifyContentCategory(parsed.normalizedUrl, intel.hostname);
    const behavior = computeBehaviorRisk({
      contentCategory,
      domainAgeDays: enrichment.domainAgeDays,
      cheapHosting: enrichment.asnReputation === 'cheap_hosting',
      suspiciousKeywordScore: Number(input.signals?.suspiciousKeywords ?? 0)
    });
    const verifiedSafeDomain = isVerifiedSafeDomain(intel.hostname);

    if (allowlist.matched) {
      const explanation = 'This domain matches the verified trust registry and its structural trust signals are consistent with a legitimate service.';
      const response: UrlScanResult = {
        url: input.url,
        domain: intel.registeredDomain,
        riskScore: 0,
        riskLevel: 'LOW',
        explanation,
        aiExplanation: explanation,
        keyIndicators: ['Verified domain registry'],
        positives: Array.from(new Set([...trustSignals, 'Verified domain badge'])),
        warnings: [],
        recommendedAction: 'allow',
        confidence: 0.99,
        category: 'clean',
        categories: ['allowlisted'],
        verdict: 'safe',
        heuristic: 0,
        dbRiskScore: reputation.domainRiskScore,
        dbReportCount: reputation.reportCount,
        cached: false,
        aiDegraded: true,
        aiSource: 'heuristic',
        aiUsed: false,
        processedMs: Date.now() - started,
        urlType: parsed.urlType,
        source: 'allowlist',
        sources: threatIntel.sources,
        confidenceLevel: 'high',
        threatSource: threatIntel.isMalicious ? 'multi' : 'internal',
        analysisDepth: 'fast',
        safeBrowsingMatched: false,
        safeBrowsingThreatTypes: [],
        signalsUsed: ['verified_domain_registry'],
        trustSignals,
        contentCategory,
        behaviorRisk: 0,
        runtimeRisk: runtime.runtimeRisk,
        domRisk: 0,
        interactionRisk: 0,
        warningsEnhanced: [],
        allowlisted: true,
        reputationStatus: reputation.reputationStatus,
        decisionBasis: 'verified_allowlist'
      };

      await cacheSetJSON(cacheKey, response, getCacheTtl(response.riskLevel));
      return response;
    }

    const heuristic = applyThreatBoosters(
      parsed.normalizedUrl,
      intel.hostname,
      computeHeuristics(parsed.normalizedUrl, intel, enrichment)
    );
    const signalContext: Record<string, number> = {
      ...heuristic.signals,
      ...(input.signals ?? {}),
      runtimeRisk: runtime.runtimeRisk,
      domRisk: domInspection.domRisk,
      interactionRisk: interaction.interactionRisk,
      popupFrequency: Number(input.signals?.popupFrequency ?? input.signals?.popupCount ?? 0),
      redirectChains: Number(input.signals?.redirectChains ?? input.signals?.redirectCount ?? 0),
      overlayTrap: Number(input.signals?.overlayTrap ?? 0),
      hiddenIframes: Number(input.signals?.hiddenIframes ?? 0),
      suspiciousFormCount: Number(input.signals?.suspiciousFormCount ?? 0),
      clickInterception: Number(input.signals?.clickInterception ?? 0)
    };
    const { boost, detectedPatterns } = computeThreatSignals(parsed.normalizedUrl, intel.hostname, signalContext);
    const baseStructuralRisk = Math.min(100, heuristic.score + boost);
    const signalCount = Object.values(signalContext).filter((value) => value > 0).length;
    let structuralRisk = baseStructuralRisk;

    if (signalCount <= 1 && detectedPatterns.length === 0 && structuralRisk < 40) {
      structuralRisk = Math.max(0, structuralRisk - 10);
    }
    if (signalCount >= 4) {
      structuralRisk = Math.min(100, structuralRisk + 10);
    }
    if (runtime.runtimeRisk >= 80) {
      structuralRisk = Math.max(structuralRisk, 90);
    }
    if (domInspection.domRisk >= 60) {
      structuralRisk = Math.max(structuralRisk, 60);
    }

    const lowInteractionRisk = runtime.runtimeRisk < 20 && domInspection.domRisk < 20 && interaction.interactionRisk < 20;

    if (verifiedSafeDomain && structuralRisk < 25 && lowInteractionRisk) {
      const explanation = 'This page is on a verified, well-known domain with no significant risk signals detected in the current interaction.';
      const response: UrlScanResult = {
        url: input.url,
        domain: intel.registeredDomain,
        riskScore: 5,
        riskLevel: 'LOW',
        explanation,
        aiExplanation: 'Verified safe domain - no AI analysis required.',
        keyIndicators: ['Verified well-known domain', 'Low interaction risk'],
        positives: Array.from(new Set([...trustSignals, 'Verified safe domain'])),
        warnings: [],
        recommendedAction: 'allow',
        confidence: 0.99,
        category: 'clean',
        categories: ['verified_safe_domain'],
        verdict: 'safe',
        heuristic: structuralRisk,
        dbRiskScore: reputation.domainRiskScore,
        dbReportCount: reputation.reportCount,
        cached: false,
        aiDegraded: true,
        aiSource: 'heuristic',
        aiUsed: false,
        processedMs: Date.now() - started,
        urlType: parsed.urlType,
        source: 'heuristic',
        sources: threatIntel.sources,
        confidenceLevel: 'high',
        threatSource: threatIntel.isMalicious ? 'multi' : 'internal',
        analysisDepth: 'fast',
        safeBrowsingMatched: false,
        safeBrowsingThreatTypes: [],
        signalsUsed: ['verified_safe_domain'],
        trustSignals: Array.from(new Set([...trustSignals, 'Verified safe domain'])),
        contentCategory,
        behaviorRisk: 0,
        runtimeRisk: runtime.runtimeRisk,
        domRisk: domInspection.domRisk,
        interactionRisk: interaction.interactionRisk,
        warningsEnhanced: [],
        allowlisted: false,
        reputationStatus: reputation.reputationStatus,
        decisionBasis: 'verified_safe_domain'
      };

      await cacheSetJSON(cacheKey, response, getCacheTtl(response.riskLevel));
      return response;
    }

    const reputationRisk = threatIntel.isMalicious && threatIntel.threatSource === 'multi'
      ? Math.max(reputation.domainRiskScore, 70)
      : Math.max(reputation.domainRiskScore, reputation.reputationStatus === 'community_flagged' ? 45 : 20);
    const environmentRisk =
      (enrichment.dnsStatus === 'nxdomain' ? 35 : enrichment.dnsFastFluxRisk ? 25 : 0) +
      (enrichment.sslStatus === 'self_signed' ? 25 : enrichment.sslStatus === 'hostname_mismatch' ? 20 : enrichment.sslStatus === 'invalid' ? 12 : 0) +
      (enrichment.asnReputation === 'cheap_hosting' ? 15 : 0);
    const initialDecision = makeDecision(intel, heuristic, reputation, {
      structuralRisk,
      reputationRisk: Math.min(100, reputationRisk),
      environmentRisk: Math.min(100, environmentRisk),
      behaviorRisk: behavior.behaviorRisk,
      runtimeRisk: runtime.runtimeRisk,
      domRisk: domInspection.domRisk,
      interactionRisk: interaction.interactionRisk,
      signalsUsed: Array.from(new Set([
        ...heuristic.signalsUsed,
        ...detectedPatterns,
        ...runtime.signalsUsed,
        ...domInspection.signalsUsed,
        ...interaction.signalsUsed,
        ...behavior.warnings.map((warning) => warning.toLowerCase().replace(/[^a-z0-9]+/g, '_')).filter(Boolean)
      ])),
      hasMaliciousScriptInjection: domInspection.hasMaliciousScriptInjection,
      hasOverlayTrap: domInspection.hasOverlayTrap,
      hasClickInterception: interaction.hasClickInterception
    });
    const shouldCallGemini = canUseAi && !verifiedSafeDomain;
    if (!shouldCallGemini) {
      logger.debug({ hostname: intel.hostname, heuristicScore: structuralRisk }, 'Gemini skipped - using heuristic fallback');
    }
    const explanationResult = shouldCallGemini
      ? await generateExplanation({
        url: parsed.normalizedUrl,
        hostname: intel.hostname,
        tld: intel.hostname.split('.').pop() ?? 'unknown',
        domainAgeDays: enrichment.domainAgeDays,
        signals: signalContext,
        heuristicScore: structuralRisk,
        pageTitle: undefined,
        hasLoginForm: contentCategory === 'login' || (signalContext.suspiciousFormCount ?? 0) > 0,
        hasDownloadPrompt: contentCategory === 'download' || (signalContext.fakePlayButtons ?? 0) > 0
      })
      : buildHeuristicExplanationFallback();
    const decision = initialDecision;
    const confidenceMultiplier = computeSignalConfidenceMultiplier(detectedPatterns);
    let calibratedScore = decision.riskScore; // FIXED: RULE 4 - confidence must not alter riskScore

    const hardOverrideBasis = new Set([
      'homoglyph_or_punycode_detected',
      'subdomain_spoofing_detected',
      'brand_impersonation_detected',
      'strong_phishing_signals',
      'runtime_abuse_detected',
      'malicious_script_injection_detected',
      'click_interception_detected',
      'overlay_trap_detected'
    ]);

    if (runtime.runtimeRisk >= 80) {
      calibratedScore = Math.max(calibratedScore, 90);
    }
    if (domInspection.domRisk >= 60) {
      calibratedScore = Math.max(calibratedScore, 60);
    }
    if (hardOverrideBasis.has(decision.decisionBasis)) {
      calibratedScore = Math.max(calibratedScore, decision.riskScore);
    }
    // FIXED: RULE 1 & 2 - Removed the arbitrary Math.max(36) inflation block

    let calibratedRiskLevel: RiskLevel =
      calibratedScore >= 75 ? 'CRITICAL'
        : calibratedScore >= 55 ? 'HIGH'
          : calibratedScore >= 35 ? 'MEDIUM'
            : 'LOW';

    if (
      explanationResult.aiSource !== 'gemini' &&
      structuralRisk < 25 &&
      detectedPatterns.length === 0 &&
      signalCount === 0 &&
      heuristic.signalsUsed.length === 0
    ) {
      calibratedRiskLevel = 'LOW';
      calibratedScore = Math.min(calibratedScore, 20);
    }

    const calibratedRecommendedAction: UrlScanResult['recommendedAction'] =
      calibratedRiskLevel === 'CRITICAL' ? 'block'
        : calibratedRiskLevel === 'HIGH' ? 'block'
          : calibratedRiskLevel === 'MEDIUM' ? 'warn'
            : 'allow';

    const finalDecision = explanationResult.aiSource === 'gemini'
      ? {
        ...decision,
        riskScore: explanationResult.riskScore, // FIXED: RULE 6 - Use Gemini score directly
        riskLevel: explanationResult.riskLevel,
        recommendedAction: explanationResult.recommendedAction,
        confidence: explanationResult.confidence
      }
      : structuralRisk < 30 &&
        calibratedRiskLevel === 'MEDIUM' &&
        signalCount === 0 &&
        heuristic.signalsUsed.length === 0 &&
        detectedPatterns.length === 0 &&
        runtime.runtimeRisk < 20 &&
        domInspection.domRisk < 20 &&
        interaction.interactionRisk < 20
        ? {
          ...decision,
          riskScore: Math.min(calibratedScore, 20),
          riskLevel: 'LOW' as const,
          recommendedAction: 'allow' as const,
          decisionBasis: 'low_signal_heuristic_fallback',
          confidence: explanationResult.confidence
        }
        : {
          ...decision,
          riskScore: Math.min(100, Math.max(0, calibratedScore)),
          riskLevel: calibratedRiskLevel,
          recommendedAction: calibratedRecommendedAction,
          confidence: explanationResult.confidence
        };
    const finalExplanationContent = finalDecision.decisionBasis === 'low_signal_heuristic_fallback'
      ? {
        explanation: 'No significant threat signals were confirmed for this interaction, and the page remains in the low-risk range without AI analysis. Keep watching for redirects, downloads, or permission prompts.',
        aiExplanation: 'Heuristic fallback — low-signal interaction remained below the medium-risk threshold.',
        keyIndicators: ['Low-signal fallback', 'No strong threat indicators'],
        positives: [] as string[],
        warnings: [],
        recommendation: 'allow' as const
      }
      : {
        explanation: explanationResult.explanation,
        aiExplanation: explanationResult.aiExplanation,
        keyIndicators: explanationResult.keyIndicators,
        positives: [] as string[],
        warnings: [] as string[],
        recommendation: explanationResult.recommendedAction
      };

    const combinedWarnings = Array.from(new Set([
      ...(finalExplanationContent.warnings ?? []),
      ...behavior.warnings,
      ...runtime.warnings,
      ...domInspection.warnings,
      ...interaction.warnings,
      ...heuristic.warnings
    ]));

    const response: UrlScanResult = {
      url: input.url,
      domain: intel.registeredDomain,
      riskScore: finalDecision.riskScore,
      riskLevel: finalDecision.riskLevel,
      explanation: finalExplanationContent.explanation,
      aiExplanation: finalExplanationContent.aiExplanation,
      keyIndicators: Array.from(new Set([...(finalExplanationContent.keyIndicators ?? []), ...detectedPatterns])),
      positives: Array.from(new Set([...(finalExplanationContent.positives ?? []), ...trustSignals])),
      warnings: combinedWarnings,
      recommendedAction: finalDecision.recommendedAction,
      confidence: finalDecision.confidence,
      category: deriveCategory(finalDecision.riskLevel, heuristic, reputation),
      categories: reputation.categories,
      verdict: verdictFromRiskLevel(finalDecision.riskLevel),
      heuristic: heuristic.score,
      dbRiskScore: reputation.domainRiskScore,
      dbReportCount: reputation.reportCount,
      cached: false,
      aiDegraded: explanationResult.aiSource !== 'gemini',
      aiSource: explanationResult.aiSource === 'gemini' ? 'gemini' : 'heuristic',
      aiUsed: explanationResult.aiSource === 'gemini',
      processedMs: Date.now() - started,
      urlType: parsed.urlType,
      source: explanationResult.aiSource === 'gemini' ? 'gemini' : 'heuristic',
      sources: threatIntel.sources,
      confidenceLevel: finalDecision.confidence >= 0.8 ? 'high' : finalDecision.confidence >= 0.55 ? 'medium' : 'low',
      threatSource: threatIntel.isMalicious ? 'multi' : 'internal',
      analysisDepth: 'full',
      safeBrowsingMatched: threatIntel.sources.includes('google_safe_browsing'),
      safeBrowsingThreatTypes: threatIntel.sources.includes('google_safe_browsing') ? threatIntel.threatTypes : [],
      signalsUsed: finalDecision.signalsUsed,
      trustSignals,
      contentCategory,
      behaviorRisk: behavior.behaviorRisk,
      runtimeRisk: runtime.runtimeRisk,
      domRisk: domInspection.domRisk,
      interactionRisk: interaction.interactionRisk,
      warningsEnhanced: combinedWarnings,
      allowlisted: false,
      reputationStatus: reputation.reputationStatus,
      decisionBasis: finalDecision.decisionBasis
    };

    await cacheSetJSON(cacheKey, response, getCacheTtl(response.riskLevel));

    const ipHash = hashIp(input.ip ?? '0.0.0.0');
    void prisma.detectionEvent.create({
      data: {
        eventType: 'url_threat',
        domain: intel.registeredDomain,
        url: input.url,
        riskScore: finalDecision.riskScore,
        riskLevel: finalDecision.riskLevel,
        signals: {
          ...heuristic.signals,
          signalsUsed: heuristic.signalsUsed,
          decisionBasis: finalDecision.decisionBasis,
          reputationStatus: reputation.reputationStatus,
          requestSignals: input.signals ?? {},
          tabId: input.tabId
        },
        aiExplanation: finalExplanationContent.explanation,
        ipHash,
        userAgent: input.userAgent,
        sessionId: input.sessionId
      }
    }).catch(() => localPersistence.createDetectionEvent({
      eventType: 'url_threat',
      domain: intel.registeredDomain,
      url: input.url,
      riskScore: finalDecision.riskScore,
      riskLevel: finalDecision.riskLevel,
      signals: {
        ...heuristic.signals,
        signalsUsed: heuristic.signalsUsed,
        decisionBasis: finalDecision.decisionBasis,
        reputationStatus: reputation.reputationStatus,
        requestSignals: input.signals ?? {},
        tabId: input.tabId
      },
      aiExplanation: finalExplanationContent.explanation,
      ipHash,
      userAgent: input.userAgent,
      sessionId: input.sessionId,
      domainScoreId: undefined,
      fileScanId: undefined
    })).catch(() => undefined);

    return response;
  } finally {
    if (lockAcquired) {
      await cacheService.releaseLock(lockKey);
    }
  }
};

export const explainUrlWithAi = async (input: {
  url: string;
  signals?: Record<string, number>;
  popupRedirect?: { popupCount: number; redirectCount: number; riskLevel: RiskLevel; flags: string[] };
  force?: boolean;
  ip?: string;
  userAgent?: string;
  requestId?: string;
  userGeminiKey?: string;
}) => performUrlScan({
  url: input.url,
  signals: input.signals,
  forceAi: input.force ?? true,
  ip: input.ip,
  userAgent: input.userAgent,
  requestId: input.requestId,
  userGeminiKey: input.userGeminiKey
});

export const scoreExtractedEmailUrls = async (input: { emailBody: string; senderEmail: string; subject: string; requestId?: string }) => {
  const matches = Array.from(input.emailBody.matchAll(/https?:\/\/[^\s"'<>]+/g)).map((match) => match[0]);
  const urls = await Promise.all(matches.map((url) => performUrlScan({ url, forceAi: false, ip: '0.0.0.0', requestId: input.requestId })));
  const senderDomain = input.senderEmail.split('@')[1] ?? '';
  const senderRisk = /support|billing|security|admin|hr/i.test(input.subject) && ['gmail.com', 'yahoo.com', 'outlook.com'].includes(senderDomain)
    ? 'HIGH'
    : urls.some((item) => item.riskLevel === 'HIGH' || item.riskLevel === 'CRITICAL')
      ? 'MEDIUM'
      : 'LOW';
  const overallRisk = urls.some((item) => item.riskLevel === 'CRITICAL') || senderRisk === 'HIGH'
    ? 'HIGH'
    : urls.some((item) => item.riskLevel === 'HIGH' || item.riskLevel === 'MEDIUM')
      ? 'MEDIUM'
      : 'LOW';
  return { urls, senderRisk, overallRisk };
};
