import { prisma } from '../db/client';
import { DatabaseError } from '../errors';
import { parseAndNormalizeUrl } from '../detection/urlParser';
import { cacheKeys, cacheService } from './cache.service';
import { hashIp } from '../utils/ip';
import { invalidateDomainCaches, recalculateDomainScore } from './domain.service';

export const createThreatReport = async (input: {
  url: string;
  category: 'phishing' | 'scam' | 'malware' | 'redirect' | 'popup_abuse' | 'ad_abuse' | 'data_exfil' | 'crypto_mining' | 'other';
  description: string;
  signals?: Record<string, number>;
  sessionId?: string;
  ip: string;
  userAgent?: string;
}) => {
  const parsed = parseAndNormalizeUrl(input.url);
  const ipHash = hashIp(input.ip);

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
        category: input.category,
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
        update: { isConfirmed: true },
        create: { domain: parsed.domain, isConfirmed: true }
      });
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
  const cached = await cacheService.get<Awaited<ReturnType<typeof prisma.threatReport.findMany>>>(cacheKeys.reportsRecent);
  if (cached) {
    return cached;
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
