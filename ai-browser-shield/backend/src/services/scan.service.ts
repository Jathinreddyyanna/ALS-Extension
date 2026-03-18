import { prisma } from '../db/client';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { scoreUrl } from '../detection/urlScorer';
import { analyzeWithGemini } from './ai.service';
import { cacheKeys, cacheService, getScanTtlSeconds } from './cache.service';
import { detectAndFlagSpike, getDomainScoreRecord, getOrCreateDomainScore, updateDomainFromScan } from './domain.service';
import { localPersistence } from './localPersistence.service';
import { hashIp } from '../utils/ip';
import { logger } from '../utils/logger';
import type { Category, RiskLevel, UrlScanResult } from '../types/scan.types';

const toRiskLevel = (score: number): RiskLevel => score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
const aiRiskNumeric = (riskLevel: RiskLevel): number => riskLevel === 'CRITICAL' ? 95 : riskLevel === 'HIGH' ? 80 : riskLevel === 'MEDIUM' ? 50 : 15;
const categoriesFromAssessment = (category: Category): Category[] => category === 'clean' || category === 'unknown' ? [] : [category];

const clampScore = (value: number, requestId?: string, url?: string): number => {
  if (Number.isNaN(value)) {
    logger.warn({ requestId, url }, 'NaN detected in score calculation, defaulting to 0');
    return 0;
  }
  if (!Number.isFinite(value)) {
    return 100;
  }
  return Math.max(0, Math.min(100, Math.round(value)));
};

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
      keyIndicators: [],
      recommendedAction: 'allow',
      confidence: 1,
      category: 'clean',
      heuristic: 0,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: false,
      processedMs: Date.now() - started,
      urlType: parsed.urlType,
      skip: true,
      reason: parsed.skipReason,
      source: 'browser_internal'
    };
  }

  const cacheKey = cacheKeys.urlScan(parsed.normalizedUrl);
  if (!input.forceAi) {
    const cached = await cacheService.get<UrlScanResult>(cacheKey);
    if (cached) {
      return { ...cached, cached: true, processedMs: Date.now() - started };
    }
  }

  const urlHashLockKey = `scan:${cacheKey}`;
  let canCallAi = true;
  const lockAcquired = await cacheService.acquireLock(urlHashLockKey, 10_000);
  if (!lockAcquired && !input.forceAi) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    const afterWait = await cacheService.get<UrlScanResult>(cacheKey);
    if (afterWait) {
      return { ...afterWait, cached: true, processedMs: Date.now() - started };
    }
    canCallAi = false;
  }

  const heuristic = scoreUrl(parsed);
  const shouldSkipAi = ['localhost', 'private_ip', 'file', 'data', 'internal'].includes(parsed.urlType) || !canCallAi;

  let domainScore: Awaited<ReturnType<typeof getDomainScoreRecord>> | null = null;
  let dbRiskScore = 0;
  let dbReportCount = 0;
  try {
    domainScore = await getDomainScoreRecord(parsed.domain);
    if (!domainScore && parsed.domain) {
      domainScore = await getOrCreateDomainScore(parsed.domain);
    }
    dbRiskScore = domainScore?.riskScore ?? 0;
    dbReportCount = domainScore?.reportCount ?? 0;
  } catch (error) {
    logger.warn({ err: error, requestId: input.requestId, domain: parsed.domain }, 'domain score lookup failed, continuing degraded');
  }

  const aiAssessment = shouldSkipAi
    ? {
      riskLevel: 'LOW' as const,
      riskScore: parsed.urlType === 'data' ? 10 : 5,
      confidence: 0.95,
      recommendedAction: 'allow' as const,
      explanation: parsed.urlType === 'file'
        ? 'Local file URL detected.'
        : parsed.urlType === 'data'
          ? 'Data URL detected.'
          : parsed.urlType === 'localhost' || parsed.urlType === 'private_ip' || parsed.urlType === 'internal'
            ? 'Internal URL detected.'
            : 'Concurrent scan in progress, heuristic result returned.',
      keyIndicators: parsed.notes,
      category: 'clean' as const,
      categories: [] as string[],
      verdict: 'safe' as const,
      threatVector: 'unknown' as const,
      isFalsePositiveRisk: false,
      suggestedWhitelist: false,
      source: 'heuristic' as const,
      aiDegraded: !canCallAi,
      cached: false
    }
    : await analyzeWithGemini({
      url: parsed.aiSafeUrl,
      hostname: parsed.hostnameUnicode,
      path: parsed.path,
      queryParams: parsed.queryParams,
      heuristicScore: heuristic.score,
      heuristicSignals: heuristic.signals,
      domainReputation: {
        riskScore: dbRiskScore,
        reportCount: dbReportCount,
        trustScore: domainScore?.trustScore ?? 50,
        is_whitelisted: domainScore?.isWhitelisted ?? false
      },
      urlType: parsed.urlType,
      requestContext: input.requestContext,
      requestId: input.requestId,
      cacheKey,
      domain: parsed.domain,
      userGeminiKey: input.userGeminiKey
    });

  const base = (heuristic.score * 0.20) + (aiRiskNumeric(aiAssessment.riskLevel) * aiAssessment.confidence * 0.50) + (dbRiskScore * 0.30);
  let bonuses = 0;
  if (aiAssessment.recommendedAction === 'block') {
    bonuses += 12;
  } else if (aiAssessment.recommendedAction === 'warn') {
    bonuses += 6;
  }
  if (heuristic.signals.typosquat > 0) {
    bonuses += 8;
  }
  if (heuristic.signals.ipAsHostname > 0) {
    bonuses += 15;
  }
  if (heuristic.signals.suspiciousTLD > 0 && heuristic.signals.suspiciousKeywords > 0) {
    bonuses += 7;
  }
  if (dbReportCount >= 3) {
    bonuses += 10;
  }
  if (dbReportCount >= 5) {
    bonuses += 10;
  }
  if (heuristic.signals.credentialInUrl > 0) {
    bonuses += 25;
  }
  if (heuristic.signals.idnHomoglyph > 0) {
    bonuses += 20;
  }
  if ((domainScore?.isWhitelisted ?? false) && heuristic.score < 40) {
    bonuses -= 15;
  }
  if (parsed.urlType === 'localhost' || parsed.urlType === 'private_ip') {
    bonuses -= 10;
  }

  let finalScore = clampScore(base + bonuses, input.requestId, input.url);
  if (dbRiskScore > 0) {
    finalScore = Math.max(finalScore, dbRiskScore);
  }
  if (parsed.urlType === 'localhost' || parsed.urlType === 'private_ip') {
    finalScore = Math.min(10, Math.max(5, finalScore));
  }
  if (parsed.urlType === 'file') {
    finalScore = 10;
  }
  if (parsed.urlType === 'data' || parsed.urlType === 'internal') {
    finalScore = 5;
  }

  const finalRiskLevel = parsed.urlType === 'localhost' || parsed.urlType === 'private_ip' || parsed.urlType === 'file' || parsed.urlType === 'data' || parsed.urlType === 'internal'
    ? 'LOW'
    : toRiskLevel(finalScore);

  const response: UrlScanResult = {
    url: input.url,
    domain: parsed.domain,
    riskScore: finalScore,
    riskLevel: heuristic.signals.credentialInUrl > 0 || heuristic.signals.idnHomoglyph > 0
      ? (['LOW', 'MEDIUM'].includes(finalRiskLevel) ? 'HIGH' : finalRiskLevel)
      : finalRiskLevel,
    explanation: aiAssessment.explanation,
    keyIndicators: Array.from(new Set([...heuristic.indicators, ...aiAssessment.keyIndicators, ...parsed.notes])).slice(0, 5),
    recommendedAction: parsed.urlType === 'localhost' || parsed.urlType === 'private_ip' ? 'allow' : aiAssessment.recommendedAction,
    confidence: aiAssessment.confidence,
    category: aiAssessment.category,
    categories: aiAssessment.categories,
    verdict: aiAssessment.verdict,
    heuristic: heuristic.score,
    dbRiskScore,
    dbReportCount,
    cached: false,
    aiDegraded: aiAssessment.source !== 'gemini',
    aiSource: aiAssessment.source,
    aiExplanation: aiAssessment.explanation,
    modelUsed: aiAssessment.modelUsed,
    processedMs: Date.now() - started,
    urlType: parsed.urlType,
    source: aiAssessment.source,
    ...(parsed.urlType === 'browser_internal' ? { skip: true, reason: parsed.skipReason } : {})
  };

  const ttl = getScanTtlSeconds(response.riskScore, domainScore?.isWhitelisted ?? false, parsed.urlType);
  if (ttl > 0) {
    await cacheService.set(cacheKey, response, ttl);
  }

  const ipHash = hashIp(input.ip ?? '0.0.0.0');
  void prisma.detectionEvent.create({
    data: {
      eventType: 'url_threat',
      domain: parsed.domain,
      url: input.url,
      riskScore: response.riskScore,
      riskLevel: response.riskLevel,
      signals: {
        ...heuristic.signals,
        category: aiAssessment.category,
        requestSignals: input.signals ?? {},
        tabId: input.tabId
      },
      aiExplanation: aiAssessment.explanation,
      ipHash,
      userAgent: input.userAgent,
      sessionId: input.sessionId,
      domainScoreId: domainScore?.id
    }
  }).catch((error) => {
    logger.warn({ err: error, requestId: input.requestId }, 'detection event write failed');
    return localPersistence.createDetectionEvent({
      eventType: 'url_threat',
      domain: parsed.domain,
      url: input.url,
      riskScore: response.riskScore,
      riskLevel: response.riskLevel,
      signals: {
        ...heuristic.signals,
        category: aiAssessment.category,
        requestSignals: input.signals ?? {},
        tabId: input.tabId
      },
      aiExplanation: aiAssessment.explanation,
      ipHash,
      userAgent: input.userAgent,
      sessionId: input.sessionId,
      domainScoreId: domainScore?.id,
      fileScanId: undefined
    });
  }).finally(() => {
    void detectAndFlagSpike(parsed.domain).catch(() => undefined);
  });

  if (parsed.domain) {
    void updateDomainFromScan({
      domain: parsed.domain,
      riskScore: response.riskScore,
      categories: categoriesFromAssessment(aiAssessment.category),
      eventRiskLevel: response.riskLevel
    }).catch((error) => {
      logger.warn({ err: error, requestId: input.requestId }, 'domain update failed');
    });
  }

  if (lockAcquired) {
    await cacheService.releaseLock(urlHashLockKey);
  }
  return response;
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
