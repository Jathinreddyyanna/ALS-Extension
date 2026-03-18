import { prisma } from '../db/client';
import { TRUSTED_DOMAIN_WHITELIST } from '../config/constants';
import { cacheKeys, cacheService } from './cache.service';
import { localPersistence } from './localPersistence.service';
import { DatabaseError, NotFoundError } from '../errors';
import { logger } from '../utils/logger';
import type { Category, RiskLevel } from '../types/scan.types';
import type { CategoryCounts, DomainTrend } from '../types/domain.types';

const isWhitelistedDomain = (domain: string): boolean =>
  TRUSTED_DOMAIN_WHITELIST.some((item) => domain === item || domain.endsWith(`.${item}`));

const decayIfStale = <T extends { riskScore: number; lastUpdated: Date }>(record: T): T => {
  const isStale = record.lastUpdated.getTime() < Date.now() - 30 * 24 * 60 * 60 * 1000;
  if (!isStale) {
    return record;
  }
  return { ...record, riskScore: Math.round(record.riskScore * 0.8) };
};

export const invalidateDomainCaches = async (domain: string): Promise<void> => {
  await cacheService.del(cacheKeys.domain(domain));
  try {
    const urls = await prisma.detectionEvent.findMany({
      where: { domain },
      select: { url: true },
      distinct: ['url'],
      take: 250
    });
    await Promise.all(urls.map((item) => cacheService.del(cacheKeys.urlScan(item.url))));
  } catch {
    // Degraded mode may not have a live database; the domain cache entry above is enough.
  }
};

export const getDomainScoreRecord = async (domain: string) => {
  const cached = await cacheService.get<Awaited<ReturnType<typeof prisma.domainScore.findUnique>>>(cacheKeys.domain(domain));
  if (cached) {
    return decayIfStale(cached);
  }
  try {
    const result = await prisma.domainScore.findUnique({ where: { domain } });
    if (!result) {
      return null;
    }
    await cacheService.set(cacheKeys.domain(domain), result, 600);
    return decayIfStale(result);
  } catch (error) {
    const fallback = await localPersistence.getDomainScore(domain);
    if (!fallback) {
      throw new DatabaseError('Database temporarily unavailable', error);
    }
    return decayIfStale(fallback);
  }
};

export const getOrCreateDomainScore = async (domain: string) => {
  try {
    return await prisma.domainScore.upsert({
      where: { domain },
      update: {},
      create: {
        domain,
        isWhitelisted: isWhitelistedDomain(domain),
        trustScore: isWhitelistedDomain(domain) ? 90 : 50
      }
    });
  } catch (error) {
    return localPersistence.upsertDomainScore({
      domain,
      isWhitelisted: isWhitelistedDomain(domain),
      trustScore: isWhitelistedDomain(domain) ? 90 : 50
    });
  }
};

export const updateDomainFromScan = async (input: {
  domain: string;
  riskScore: number;
  categories: Category[];
  eventRiskLevel: RiskLevel;
}): Promise<void> => {
  try {
    const existing = await getOrCreateDomainScore(input.domain);
    const categoryCounts = (existing.categoryCounts as CategoryCounts | null) ?? {};
    for (const category of input.categories) {
      categoryCounts[category] = (categoryCounts[category] ?? 0) + 1;
    }
    await prisma.domainScore.update({
      where: { id: existing.id },
      data: {
        riskScore: Math.max(existing.riskScore, input.riskScore),
        scanCount: { increment: 1 },
        categories: Array.from(new Set([...(existing.categories as string[]), ...input.categories])),
        categoryCounts,
        lastReportAt: ['HIGH', 'CRITICAL'].includes(input.eventRiskLevel) ? new Date() : existing.lastReportAt
      }
    });
    await invalidateDomainCaches(input.domain);
  } catch (error) {
    await localPersistence.applyScanToDomain(input);
    await invalidateDomainCaches(input.domain);
  }
};

export const recalculateDomainScore = async (domain: string): Promise<void> => {
  let existing;
  try {
    existing = await getOrCreateDomainScore(domain);
  } catch (error) {
    logger.warn({ err: error, domain }, 'failed to get domain during recalc');
    return;
  }

  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  let events: Awaited<ReturnType<typeof prisma.detectionEvent.findMany>> = [];
  let reports: Awaited<ReturnType<typeof prisma.threatReport.findMany>> = [];
  try {
    events = await prisma.detectionEvent.findMany({ where: { domain, createdAt: { gte: since } }, orderBy: { createdAt: 'desc' } });
  } catch (error) {
    logger.warn({ err: error, domain }, 'failed reading detection events during recalc');
  }
  try {
    reports = await prisma.threatReport.findMany({ where: { domain }, orderBy: { createdAt: 'desc' } });
  } catch (error) {
    logger.warn({ err: error, domain }, 'failed reading threat reports during recalc');
  }

  const categoryCounts: CategoryCounts = {};
  let weighted = 0;
  let weightTotal = 0;
  for (const event of events) {
    const ageDays = Math.max(1, (Date.now() - event.createdAt.getTime()) / (24 * 60 * 60 * 1000));
    const decay = 1 / ageDays;
    weighted += event.riskScore * decay;
    weightTotal += decay;
    const signals = typeof event.signals === 'object' && event.signals ? event.signals as Record<string, unknown> : {};
    const category = typeof signals.category === 'string' ? signals.category : 'unknown';
    categoryCounts[category] = (categoryCounts[category] ?? 0) + 1;
  }
  for (const report of reports) {
    categoryCounts[report.category] = (categoryCounts[report.category] ?? 0) + 1;
  }

  const derivedRisk = weightTotal > 0 ? Math.round(weighted / weightTotal) : existing.riskScore;
  const stale = existing.lastUpdated.getTime() < Date.now() - 30 * 24 * 60 * 60 * 1000;
  const nextRiskScore = stale ? Math.round(derivedRisk * 0.8) : derivedRisk;
  const reportCount = reports.filter((report) => report.status === 'confirmed').length;
  const distinctReporterCount = new Set(reports.map((report) => report.ipHash)).size;

  try {
    await prisma.domainScore.update({
      where: { id: existing.id },
      data: {
        riskScore: Math.min(100, nextRiskScore),
        reportCount,
        categories: Object.keys(categoryCounts),
        categoryCounts,
        isConfirmed: distinctReporterCount >= 3 ? true : existing.isConfirmed,
        trustScore: Math.max(0, Math.min(100, existing.isWhitelisted ? 95 : 100 - Math.round(nextRiskScore * 0.7)))
      }
    });
  } catch (error) {
    logger.warn({ err: error, domain }, 'failed writing recalculated domain score');
  }
  await invalidateDomainCaches(domain);
};

export const detectAndFlagSpike = async (domain: string): Promise<void> => {
  try {
    const score = await prisma.domainScore.findUnique({ where: { domain } });
    if (!score || score.isConfirmed) {
      return;
    }
    const since = new Date(Date.now() - 60 * 60 * 1000);
    const events = await prisma.detectionEvent.findMany({
      where: { domain, createdAt: { gte: since }, ipHash: { not: null } },
      select: { ipHash: true }
    });
    const uniqueIpCount = new Set(events.map((event) => event.ipHash).filter((value): value is string => typeof value === 'string')).size;
    if (uniqueIpCount <= 20) {
      return;
    }
    await prisma.domainScore.update({
      where: { domain },
      data: {
        isConfirmed: true,
        riskScore: Math.max(score.riskScore, 75)
      }
    });
    await prisma.adminLog.create({
      data: {
        action: 'auto_flag_spike',
        targetType: 'domain',
        targetId: domain,
        adminId: 'system',
        notes: `Spike: ${uniqueIpCount} unique IPs in 60min`
      }
    });
    await invalidateDomainCaches(domain);
    logger.warn({ domain, uniqueIpCount }, `Spike auto-flag triggered for domain: ${domain}, unique IPs: ${uniqueIpCount}`);
  } catch (error) {
    const score = await localPersistence.getDomainScore(domain);
    if (!score || score.isConfirmed) {
      return;
    }
    const since = Date.now() - 60 * 60 * 1000;
    const events = await localPersistence.listDetectionEvents({ domain, limit: 500 });
    const uniqueIpCount = new Set(events.filter((event) => event.createdAt.getTime() >= since).map((event) => event.ipHash).filter((value): value is string => typeof value === 'string')).size;
    if (uniqueIpCount <= 20) {
      return;
    }
    await localPersistence.updateDomainScore(domain, (current) => ({
      ...current,
      isConfirmed: true,
      riskScore: Math.max(current.riskScore, 75),
      lastUpdated: new Date()
    }));
  }
};

export const getDomainTrend = async (domain: string): Promise<DomainTrend> => {
  try {
    const now = Date.now();
    const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const fourteenDaysAgo = new Date(now - 14 * 24 * 60 * 60 * 1000);
    const [currentEvents, previousEvents] = await Promise.all([
      prisma.detectionEvent.findMany({ where: { domain, createdAt: { gte: sevenDaysAgo } }, orderBy: { createdAt: 'asc' } }),
      prisma.detectionEvent.findMany({ where: { domain, createdAt: { gte: fourteenDaysAgo, lt: sevenDaysAgo } } })
    ]);
    const average = (events: typeof currentEvents): number => events.length === 0 ? 0 : Math.round(events.reduce((sum, item) => sum + item.riskScore, 0) / events.length);
    return {
      current: average(currentEvents),
      previous: average(previousEvents),
      change: average(currentEvents) - average(previousEvents),
      points: currentEvents.map((event) => ({
        date: event.createdAt.toISOString().slice(0, 10),
        riskScore: event.riskScore
      }))
    };
  } catch (error) {
    return localPersistence.getDomainTrend(domain);
  }
};

export const getDomainInsight = async (domain: string) => {
  try {
    const score = await getDomainScoreRecord(domain);
    if (!score) {
      return null;
    }
    const [detectionEvents, reports, trend] = await Promise.all([
      prisma.detectionEvent.findMany({ where: { domain }, orderBy: { createdAt: 'desc' }, take: 10 }),
      prisma.threatReport.findMany({ where: { domain }, orderBy: { createdAt: 'desc' }, take: 5 }),
      getDomainTrend(domain)
    ]);
    return { score, detectionEvents, reports, trend };
  } catch (error) {
    const score = await localPersistence.getDomainScore(domain);
    if (!score) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      throw new DatabaseError('Database temporarily unavailable', error);
    }
    const detectionEvents = await localPersistence.listDetectionEvents({ domain, limit: 10 });
    const trend = await localPersistence.getDomainTrend(domain);
    return { score, detectionEvents, reports: [], trend };
  }
};

export const confirmDomainVerdict = async (input: {
  domain: string;
  verdict: 'confirmed' | 'rejected';
  notes?: string;
  overrideRiskScore?: number;
}) => {
  try {
    const domainScore = await prisma.domainScore.findUnique({ where: { domain: input.domain } });
    if (!domainScore) {
      throw new NotFoundError('domain not found');
    }
    const riskScore = input.verdict === 'confirmed'
      ? (typeof input.overrideRiskScore === 'number' ? input.overrideRiskScore : Math.max(domainScore.riskScore, 75))
      : Math.max(0, domainScore.riskScore - 20);
    const reportUpdate = await prisma.threatReport.updateMany({
      where: { domain: input.domain, status: 'pending' },
      data: { status: input.verdict === 'confirmed' ? 'confirmed' : 'rejected' }
    });
    await prisma.domainScore.update({
      where: { domain: input.domain },
      data: {
        isConfirmed: input.verdict === 'confirmed',
        riskScore
      }
    });
    await prisma.adminLog.create({
      data: {
        action: `admin_${input.verdict}_domain`,
        targetType: 'domain',
        targetId: input.domain,
        adminId: 'admin',
        notes: input.notes
      }
    });
    await invalidateDomainCaches(input.domain);
    return {
      domain: input.domain,
      verdict: input.verdict,
      riskScore,
      affectedReports: reportUpdate.count
    };
  } catch (error) {
    if (error instanceof NotFoundError) {
      throw error;
    }
    throw new DatabaseError('Database temporarily unavailable', error);
  }
};

export const getFlaggedDomains = async () => {
  try {
    return await prisma.domainScore.findMany({
      where: { isConfirmed: false, riskScore: { gte: 50 } },
      orderBy: { riskScore: 'desc' },
      take: 50
    });
  } catch (error) {
    throw new DatabaseError('Database temporarily unavailable', error);
  }
};
