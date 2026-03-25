import crypto from 'node:crypto';
import { prisma } from '../db/client';
import { DatabaseError } from '../errors';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { cacheGetJSON, cacheKeys, cacheService, cacheSetJSON } from './cache.service';
import { hashIp } from '../utils/ip';
import { invalidateDomainCaches, recalculateDomainScore } from './domain.service';

const isNoDb = () => process.env.NO_DB === 'true';

type InMemoryReport = {
  id: string;
  url: string;
  domain: string;
  category: string;
  description: string;
  createdAt: Date;
  status: 'pending' | 'confirmed';
};

const inMemoryReports: InMemoryReport[] = [];

export const createThreatReport = async (input: {
  url: string;
  category: 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'ad_abuse' | 'data_exfil' | 'crypto_mining' | 'piracy' | 'other';
  description: string;
  signals?: Record<string, number>;
  sessionId?: string;
  ip: string;
  userAgent?: string;
}) => {
  const parsed = parseAndNormalizeUrl(input.url);
  const ipHash = hashIp(input.ip);
  const persistedCategory = input.category === 'piracy' ? 'other' : input.category;

  if (isNoDb()) {
    const existing = inMemoryReports.find((report) =>
      report.url === input.url &&
      report.domain === parsed.domain &&
      report.createdAt.getTime() >= Date.now() - (24 * 60 * 60 * 1000)
    );

    if (existing) {
      return {
        id: existing.id,
        status: 'already_reported' as const,
        message: 'Report already submitted in the last 24 hours.'
      };
    }

    const report: InMemoryReport = {
      id: crypto.randomUUID(),
      url: input.url,
      domain: parsed.domain,
      category: persistedCategory,
      description: input.description,
      createdAt: new Date(),
      status: 'pending'
    };
    inMemoryReports.unshift(report);

    await Promise.all([
      cacheService.del(cacheKeys.reportsRecent),
      cacheService.del(cacheKeys.domain(parsed.domain)),
      cacheService.del(cacheKeys.urlScan(parsed.normalizedUrl))
    ]);

    return {
      id: report.id,
      status: 'pending' as const,
      message: 'Threat report received.'
    };
  }

  try {
    const existing = await prisma.threatReport.findFirst({
      where: {
        url: input.url,
        ipHash,
        createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }
    });
    if (existing) {
      return {
        id: existing.id,
        status: 'already_reported' as const,
        message: 'Report already submitted in the last 24 hours.'
      };
    }

    const report = await prisma.threatReport.create({
      data: {
        url: input.url,
        domain: parsed.domain,
        category: persistedCategory,
        description: input.description,
        signals: input.signals ?? {},
        ipHash,
        userAgent: input.userAgent,
        sessionId: input.sessionId
      }
    });

    const distinctReporterCount = await prisma.threatReport.findMany({
      where: { domain: parsed.domain },
      select: { ipHash: true },
      distinct: ['ipHash']
    });
    if (distinctReporterCount.length >= 3) {
      await prisma.domainScore.upsert({
        where: { domain: parsed.domain },
        update: {
          reportCount: distinctReporterCount.length,
          riskScore: distinctReporterCount.length >= 5 ? 80 : 55,
          isConfirmed: distinctReporterCount.length >= 5,
          lastReportAt: new Date()
        },
        create: {
          domain: parsed.domain,
          reportCount: distinctReporterCount.length,
          riskScore: distinctReporterCount.length >= 5 ? 80 : 55,
          isConfirmed: distinctReporterCount.length >= 5,
          lastReportAt: new Date(),
          categories: [persistedCategory]
        }
      });
      if (distinctReporterCount.length >= 5) {
        await prisma.adminLog.create({
          data: {
            action: 'auto_confirm_reports',
            targetType: 'domain',
            targetId: parsed.domain,
            adminId: 'system',
            notes: `Auto-confirmed after ${distinctReporterCount.length} distinct reports`
          }
        });
      }
    }

    await Promise.all([
      cacheService.del(cacheKeys.reportsRecent),
      cacheService.del(cacheKeys.domain(parsed.domain)),
      cacheService.del(cacheKeys.urlScan(parsed.normalizedUrl)),
      invalidateDomainCaches(parsed.domain)
    ]);
    void recalculateDomainScore(parsed.domain);

    return {
      id: report.id,
      status: 'pending' as const,
      message: 'Threat report received.'
    };
  } catch (error) {
    throw new DatabaseError('Database temporarily unavailable', error);
  }
};

export const getRecentConfirmedReports = async () => {
  const cached = await cacheGetJSON<Awaited<ReturnType<typeof prisma.threatReport.findMany>> | InMemoryReport[]>(cacheKeys.reportsRecent);
  if (cached) {
    return cached;
  }

  if (isNoDb()) {
    const result = inMemoryReports
      .filter((report) => report.status === 'confirmed')
      .slice(0, 20);
    await cacheSetJSON(cacheKeys.reportsRecent, result, 120);
    return result;
  }

  try {
    const result = await prisma.threatReport.findMany({
      where: { status: 'confirmed' },
      orderBy: { createdAt: 'desc' },
      take: 20
    });
    await cacheService.set(cacheKeys.reportsRecent, result, 120);
    return result;
  } catch (error) {
    throw new DatabaseError('Database temporarily unavailable', error);
  }
};
