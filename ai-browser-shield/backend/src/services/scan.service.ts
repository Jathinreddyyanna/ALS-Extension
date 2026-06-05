import { prisma } from '../db/client';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { resolveAllowlist } from './allowlist.service';
import { cacheGetJSON, cacheKeys, cacheService, cacheSetJSON } from './cache.service';
import { analyzeDomain } from './domainIntelligence.service';
import { enrichDomainSignals } from './domainEnrichment.service';
import type { DomainEnrichment } from './domainEnrichment.service';
import { computeHeuristics, type HeuristicResult } from './scoring.service';
import { getReputation, type ReputationResult } from './reputation.service';
import { makeDecision } from './decision.service';
import { generateExplanation } from './explanation.service';
import { localPersistence } from './localPersistence.service';
import { aggregateThreatIntel } from './threatIntel.service';
import type { ThreatIntelAggregateResult } from './threatIntel.service';
import { classifyContentCategory, computeBehaviorRisk, computeRuntimeRisk } from './behaviorRisk.service';
import { computeDomRisk, computeInteractionRisk } from './pageInteraction.service';
import { isTrustedDomain } from './trustEngine.service';
import { analyzeResolvedUrl, resolveUrlDeep, isUrlShortener, extractRootDomain } from './urlResolver.service';
import { hashIp } from '../utils/ip';
import { hashUrlForStorage } from '../utils/crypto';
import { logger } from '../utils/logger';
import type { Category, RiskLevel, UrlScanResult } from '../types/scan.types';

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

const HIGH_RISK_TLDS = new Set(['digital', 'trade', 'online', 'xyz', 'tk']);
const FREE_HOSTING_SUFFIXES = ['pages.dev', 'herokuapp.com', 'netlify.app', 'vercel.app'];
const OFFICIAL_CRYPTO_SUFFIXES = ['trezor.io', 'ledger.com', 'metamask.io', 'coinbase.com'];
const CRYPTO_BRANDS = ['trezor', 'ledger', 'metamask', 'coinbase'];

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

const getCacheTtl = (riskLevel: RiskLevel): number => (
  riskLevel === 'LOW' ? 60 * 60 * 24
    : riskLevel === 'MEDIUM' ? 60 * 30
      : riskLevel === 'HIGH' ? 60 * 15
        : 60 * 5
);

const buildHeuristicExplanationFallback = () => ({
  explanation: 'AI analysis is temporarily unavailable, so this page was assessed using domain trust and observed behavior signals.',
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
  heuristic: HeuristicResult,
  input?: {
    domainAgeDays: number | null;
    suspiciousKeywordScore: number;
  }
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

  if (hasBrandImpersonation && !isTrustedDomain(hostname)) {
    boostedScore += 50;
    boostedSignals.brandImpersonation = Math.max(boostedSignals.brandImpersonation ?? 0, 50);
    boostedSignalsUsed.push('brand_impersonation_pattern');
    boostedWarnings.push('Brand impersonation pattern');
  }

  const firstLabel = hostname.split('.')[0] ?? '';
  const hasGibberishSubdomain = firstLabel.length >= 8 &&
    (firstLabel.match(/[aeiou]/gi)?.length ?? 0) <= 2 &&
    /[a-z]/i.test(firstLabel) &&
    /\d/.test(firstLabel) === false;
  if (hasGibberishSubdomain) {
    boostedScore += 40;
    boostedSignalsUsed.push('gibberish_subdomain');
    boostedWarnings.push('Random-looking subdomain');
  }

  if (HIGH_RISK_TLDS.has(tld)) {
    boostedScore += 25;
    boostedSignalsUsed.push('high_risk_tld');
    boostedWarnings.push('Suspicious top-level domain');
  }

  if (/\/(?:login|class)\.php(?:[/?#]|$)/i.test(new URL(url).pathname)) {
    boostedScore += 35;
    boostedSignalsUsed.push('php_login_lure');
    boostedWarnings.push('Suspicious login endpoint');
  }

  const hasBase64RedirectParam = Array.from(new URL(url).searchParams.values()).some((value) => {
    const normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/=]+$/.test(normalized) || normalized.length < 8) return false;
    try {
      const decoded = Buffer.from(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='), 'base64').toString('utf8').trim();
      return /^https?:\/\//i.test(decoded);
    } catch {
      return false;
    }
  });
  if (hasBase64RedirectParam) {
    boostedScore += 40;
    boostedSignalsUsed.push('base64_redirect_param');
    boostedWarnings.push('Encoded redirect destination');
  }

  const isOfficialCryptoDomain = OFFICIAL_CRYPTO_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`));
  if (CRYPTO_BRANDS.some((brand) => urlLower.includes(brand)) && !isOfficialCryptoDomain) {
    boostedScore += 55;
    boostedSignalsUsed.push('crypto_brand_impersonation');
    boostedWarnings.push('Crypto brand referenced off official domain');
  }

  if (hostname.includes('xn--')) {
    boostedScore += 45;
    boostedSignalsUsed.push('punycode_domain');
    boostedWarnings.push('Punycode hostname');
  }

  if (
    FREE_HOSTING_SUFFIXES.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`)) &&
    ((input?.suspiciousKeywordScore ?? 0) > 0 || PHISHING_ACTIONS.some((action) => urlLower.includes(action)))
  ) {
    boostedScore += 35;
    boostedSignalsUsed.push('free_hosting_with_suspicious_content');
    boostedWarnings.push('Free hosting with suspicious content');
  }

  if ((heuristic.signals.typosquatScore ?? 0) > 0) {
    boostedScore = Math.max(boostedScore, heuristic.score + 50);
    boostedSignalsUsed.push('typosquatting');
    boostedWarnings.push('Typosquatting pattern');
  }

  if ((input?.domainAgeDays ?? null) !== null && (input?.domainAgeDays ?? 9999) < 30) {
    boostedScore += 35;
    boostedSignalsUsed.push('new_domain_registration');
    boostedWarnings.push('Recently registered domain');
  }

  if (!urlLower.startsWith('https://')) {
    boostedScore += 30;
    boostedSignalsUsed.push('no_https');
    boostedWarnings.push('Connection is not using HTTPS');
  }

  if (hostname.split('.').length >= 5) {
    boostedScore += 30;
    boostedSignalsUsed.push('excessive_subdomains');
    boostedWarnings.push('Excessive subdomains');
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    boostedScore += 50;
    boostedSignalsUsed.push('ip_hostname');
    boostedWarnings.push('IP address used as hostname');
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
  if (hasBrandName && hasActionWord && !isTrustedDomain(hostname)) {
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
  if ((signals.hiddenIframes ?? 0) > 5) detectedPatterns.push('hidden_iframes');
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

const filterTrustOverrideWarnings = (warnings: string[]): string[] =>
  warnings.filter((warning) => {
    const lower = warning.toLowerCase();
    return !(
      lower.includes('possible impersonation') ||
      lower.includes('proceed with caution') ||
      lower.includes('hidden iframe') ||
      lower.includes('limited page context')
    );
  });

const filterTrustOverrideIndicators = (indicators: string[]): string[] =>
  indicators.filter((indicator) => {
    const lower = indicator.toLowerCase();
    return !(
      lower.includes('impersonation') ||
      lower.includes('hidden_iframes') ||
      lower.includes('suspicious_form_count')
    );
  });

const shouldApplyTrustedDomainOverride = (input: {
  intel: ReturnType<typeof analyzeDomain>;
  enrichment: DomainEnrichment;
  reputation: ReputationResult;
  threatIntel: ThreatIntelAggregateResult;
  heuristic: HeuristicResult;
  runtimeRisk: number;
  domRisk: number;
  interactionRisk: number;
  detectedPatterns: string[];
  signalContext: Record<string, number>;
  response: UrlScanResult;
}): boolean => {
  const hasStrongRiskSignals =
    input.threatIntel.isMalicious ||
    input.response.riskLevel === 'HIGH' ||
    input.response.riskLevel === 'CRITICAL' ||
    input.runtimeRisk >= 25 ||
    input.domRisk >= 25 ||
    input.interactionRisk >= 25 ||
    Number(input.signalContext.overlayTrap ?? 0) > 0 ||
    Number(input.signalContext.clickInterception ?? 0) > 0 ||
    Number(input.signalContext.suspiciousFormCount ?? 0) > 0 ||
    Number(input.signalContext.hiddenIframes ?? 0) > 5 ||
    input.detectedPatterns.some((pattern) =>
      [
        'brand_impersonation_phishing',
        'malicious_script_injection',
        'overlay_trap',
        'click_interception',
        'suspicious_form_count',
        'redirect_chain'
      ].includes(pattern)
    );

  if (hasStrongRiskSignals) return false;

  const trustedReputation = input.reputation.reputationStatus === 'known_safe';
  const strongTrustSignals =
    input.intel.trustScore >= 55 &&
    input.enrichment.sslTrusted &&
    (input.enrichment.domainAgeDays === null || input.enrichment.domainAgeDays >= 365) &&
    !input.intel.hasSubdomainSpoofing &&
    !input.intel.impersonatedBrand &&
    !input.intel.homoglyph.hasHomoglyphRisk &&
    input.heuristic.score <= 18;

  return trustedReputation || strongTrustSignals;
};

const applyTrustedDomainOverride = (response: UrlScanResult): UrlScanResult => ({
  ...response,
  riskScore: Math.min(response.riskScore, 12),
  riskLevel: 'LOW',
  explanation: 'This domain shows strong trust signals and the current page behavior is consistent with normal operation.',
  aiExplanation: 'Trusted domain override applied. Reputation, TLS trust, and low-risk runtime behavior outweigh weak heuristic noise for this page.',
  keyIndicators: Array.from(new Set(['Trusted domain reputation', ...filterTrustOverrideIndicators(response.keyIndicators)])),
  positives: Array.from(new Set([...(response.positives ?? []), 'Domain matches official service', 'No malicious behavior detected'])),
  warnings: filterTrustOverrideWarnings(response.warnings ?? []),
  warningsEnhanced: filterTrustOverrideWarnings(response.warningsEnhanced ?? []),
  recommendedAction: 'allow',
  confidence: Math.max(response.confidence, 0.95),
  category: 'clean',
  trustedDomain: true,
  categories: response.categories?.includes('verified_safe_domain')
    ? response.categories
    : Array.from(new Set(['verified_safe_domain', ...(response.categories ?? [])])),
  verdict: 'safe',
  decisionBasis: 'trusted_domain_override'
});

const buildLocalResult = (
  inputUrl: string,
  finalUrl: string,
  redirectChain: string[],
  domain: string,
  urlType: UrlScanResult['urlType'],
  explanation: string,
  started: number
): UrlScanResult => ({
  url: inputUrl,
  finalUrl,
  redirectChain,
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
  trustedDomain: false,
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

  // Check if URL is a shortener - use deep HTTP resolution
  let resolved: { rawUrl: string; finalUrl: string; domain: string; redirectChain: string[]; redirector: boolean };
  try {
    const hostname = new URL(input.url).hostname.toLowerCase();
    if (isUrlShortener(hostname)) {
      // URL shortener detected - resolve via HTTP HEAD
      const deepResolved = await resolveUrlDeep(input.url);
      resolved = {
        rawUrl: input.url,
        finalUrl: deepResolved.finalUrl,
        domain: extractRootDomain(deepResolved.finalUrl),
        redirectChain: deepResolved.chain,
        redirector: true
      };
      logger.info({ shortUrl: input.url, finalUrl: deepResolved.finalUrl, chain: deepResolved.chain }, 'URL shortener resolved');
    } else {
      resolved = analyzeResolvedUrl(input.url);
    }
  } catch {
    // Invalid URL - use standard resolution
    resolved = analyzeResolvedUrl(input.url);
  }

  const parsed = parseAndNormalizeUrl(resolved.finalUrl);

  if (parsed.skip) {
    return {
      url: input.url,
      finalUrl: resolved.finalUrl,
      redirectChain: resolved.redirectChain,
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
      trustedDomain: false,
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
      resolved.finalUrl,
      resolved.redirectChain,
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
    if (threatIntel.isMalicious) {
      logger.warn({
        url: parsed.normalizedUrl,
        sources: threatIntel.sources,
        threatTypes: threatIntel.threatTypes,
        confidenceLevel: threatIntel.confidenceLevel
      }, '[THREAT_INTEL] THREAT DETECTED');
    }
    if (threatIntel.isMalicious && threatIntel.threatSource === 'google') {
      const response: UrlScanResult = {
        url: input.url,
        finalUrl: resolved.finalUrl,
        redirectChain: resolved.redirectChain,
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
        trustedDomain: false,
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
      const hashedUrl = hashUrlForStorage(resolved.finalUrl);
      void prisma.detectionEvent.create({
        data: {
          eventType: 'url_threat',
          domain: intel.registeredDomain,
          url: hashedUrl,
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
        url: hashedUrl,
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
    const verifiedSafeDomain = isTrustedDomain(intel.hostname);
    const trustSignals = Array.from(new Set([
      ...intel.positives,
      ...enrichment.positives,
      ...(enrichment.domainAgeDays !== null && enrichment.domainAgeDays >= 365 * 5 ? ['Registered 5+ years ago'] : []),
      ...(reputation.reportCount === 0 ? ['No reported phishing'] : []),
      ...(verifiedSafeDomain ? ['Official domain match'] : []),
      ...(resolved.redirectChain.length > 1 ? ['Final destination resolved through redirect chain'] : [])
    ]));

    if (allowlist.matched) {
      const explanation = 'This domain matches the verified trust registry and its structural trust signals are consistent with a legitimate service.';
      const response: UrlScanResult = {
        url: input.url,
        finalUrl: resolved.finalUrl,
        redirectChain: resolved.redirectChain,
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
        trustedDomain: true,
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
      computeHeuristics(parsed.normalizedUrl, intel, enrichment),
      {
        domainAgeDays: enrichment.domainAgeDays,
        suspiciousKeywordScore: Number(input.signals?.suspiciousKeywords ?? 0)
      }
    );

    // Log signal breakdown for debugging
    const signalBreakdown = Object.entries(heuristic.signals)
      .filter(([, value]) => value > 0)
      .sort(([, a], [, b]) => b - a);
    if (signalBreakdown.length > 0) {
      logger.debug({
        url: parsed.normalizedUrl,
        hostname: intel.hostname,
        heuristicScore: heuristic.score,
        signalBreakdown: Object.fromEntries(signalBreakdown),
        signalsUsed: heuristic.signalsUsed,
        positives: heuristic.positives,
        warnings: heuristic.warnings
      }, '[SCORING] Heuristic signal breakdown');
    }
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
        finalUrl: resolved.finalUrl,
        redirectChain: resolved.redirectChain,
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
        trustedDomain: true,
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
        : calibratedScore >= 50 ? 'HIGH'
          : calibratedScore >= 30 ? 'MEDIUM'
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
      finalUrl: resolved.finalUrl,
      redirectChain: resolved.redirectChain,
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
      trustedDomain: verifiedSafeDomain,
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

    const finalResponse = shouldApplyTrustedDomainOverride({
      intel,
      enrichment,
      reputation,
      threatIntel,
      heuristic,
      runtimeRisk: runtime.runtimeRisk,
      domRisk: domInspection.domRisk,
      interactionRisk: interaction.interactionRisk,
      detectedPatterns,
      signalContext,
      response
    })
      ? applyTrustedDomainOverride(response)
      : response;

    await cacheSetJSON(cacheKey, finalResponse, getCacheTtl(finalResponse.riskLevel));

    const ipHash = hashIp(input.ip ?? '0.0.0.0');
    const hashedUrl = hashUrlForStorage(resolved.finalUrl);
    void prisma.detectionEvent.create({
      data: {
        eventType: 'url_threat',
        domain: intel.registeredDomain,
        url: hashedUrl,
        riskScore: finalResponse.riskScore,
        riskLevel: finalResponse.riskLevel,
        signals: {
          ...heuristic.signals,
          signalsUsed: heuristic.signalsUsed,
          decisionBasis: finalResponse.decisionBasis,
          reputationStatus: reputation.reputationStatus,
          requestSignals: input.signals ?? {},
          tabId: input.tabId
        },
        aiExplanation: finalResponse.explanation,
        ipHash,
        userAgent: input.userAgent,
        sessionId: input.sessionId
      }
    }).catch(() => localPersistence.createDetectionEvent({
      eventType: 'url_threat',
      domain: intel.registeredDomain,
      url: hashedUrl,
      riskScore: finalResponse.riskScore,
      riskLevel: finalResponse.riskLevel,
      signals: {
        ...heuristic.signals,
        signalsUsed: heuristic.signalsUsed,
        decisionBasis: finalResponse.decisionBasis,
        reputationStatus: reputation.reputationStatus,
        requestSignals: input.signals ?? {},
        tabId: input.tabId
      },
      aiExplanation: finalResponse.explanation,
      ipHash,
      userAgent: input.userAgent,
      sessionId: input.sessionId,
      domainScoreId: undefined,
      fileScanId: undefined
    })).catch(() => undefined);

    return finalResponse;
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
