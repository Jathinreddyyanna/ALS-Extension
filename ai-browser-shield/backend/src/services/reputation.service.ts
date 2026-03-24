import { prisma } from '../db/client';
import { localPersistence } from './localPersistence.service';
import { cacheGetJSON, cacheSetJSON } from './cache.service';

export interface ReputationResult {
  domainRiskScore: number;
  reportCount: number;
  categories: string[];
  isConfirmed: boolean;
  reputationStatus: 'known_safe' | 'known_threat' | 'unknown' | 'community_flagged';
  confidenceLevel: 'known_safe' | 'known_threat' | 'unknown';
}

export async function getReputation(domain: string): Promise<ReputationResult> {
  const cacheKey = `rep:${domain}`;
  const cached = await cacheGetJSON<ReputationResult>(cacheKey);
  if (cached) return cached;

  try {
    const row = await prisma.domainScore.findUnique({ where: { domain } });

    let result: ReputationResult;
    if (!row) {
      result = {
        domainRiskScore: 0,
        reportCount: 0,
        categories: [],
        isConfirmed: false,
        reputationStatus: 'unknown',
        confidenceLevel: 'unknown'
      };
    } else {
      result = {
        domainRiskScore: row.riskScore,
        reportCount: row.reportCount,
        categories: row.categories ?? [],
        isConfirmed: row.isConfirmed ?? false,
        reputationStatus:
          row.isWhitelisted ? 'known_safe'
            : row.isConfirmed && row.riskScore >= 75 ? 'known_threat'
            : row.isConfirmed && row.riskScore < 10 ? 'known_safe'
              : row.reportCount >= 3 ? 'community_flagged'
                : 'unknown',
        confidenceLevel:
          row.isWhitelisted ? 'known_safe'
            : row.isConfirmed && row.riskScore >= 75 ? 'known_threat'
            : row.isConfirmed && row.riskScore < 10 ? 'known_safe'
              : 'unknown'
      };
    }

    await cacheSetJSON(cacheKey, result, 600);
    return result;
  } catch {
    const fallback = await localPersistence.getDomainScore(domain).catch(() => null);
    if (fallback) {
      const result: ReputationResult = {
        domainRiskScore: fallback.riskScore,
        reportCount: fallback.reportCount,
        categories: fallback.categories ?? [],
        isConfirmed: fallback.isConfirmed ?? false,
        reputationStatus:
          fallback.isWhitelisted ? 'known_safe'
            : fallback.isConfirmed && fallback.riskScore >= 75 ? 'known_threat'
            : fallback.isConfirmed && fallback.riskScore < 10 ? 'known_safe'
              : fallback.reportCount >= 3 ? 'community_flagged'
                : 'unknown',
        confidenceLevel:
          fallback.isWhitelisted ? 'known_safe'
            : fallback.isConfirmed && fallback.riskScore >= 75 ? 'known_threat'
            : fallback.isConfirmed && fallback.riskScore < 10 ? 'known_safe'
              : 'unknown'
      };
      await cacheSetJSON(cacheKey, result, 300);
      return result;
    }

    return {
      domainRiskScore: 0,
      reportCount: 0,
      categories: [],
      isConfirmed: false,
      reputationStatus: 'unknown',
      confidenceLevel: 'unknown'
    };
  }
}
