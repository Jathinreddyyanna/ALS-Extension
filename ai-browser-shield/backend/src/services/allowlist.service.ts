import { prisma } from '../db/client';
import { TRUSTED_DOMAIN_WHITELIST } from '../config/constants';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { getRegisteredDomain } from './domainIntelligence.service';
import { localPersistence } from './localPersistence.service';

export interface AllowlistResult {
  matched: boolean;
  source: 'config' | 'database' | 'none';
  domain?: string;
  reason?: string;
}

const TTL_SECONDS = 1800;

const isConfiguredAllowlisted = (registeredDomain: string): boolean =>
  TRUSTED_DOMAIN_WHITELIST.some((domain) => registeredDomain === domain || registeredDomain.endsWith(`.${domain}`));

export async function resolveAllowlist(rawDomain: string): Promise<AllowlistResult> {
  const registeredDomain = getRegisteredDomain(rawDomain);
  const cacheKey = `allow:${registeredDomain}`;
  const cached = await cacheGetJSON<AllowlistResult>(cacheKey);
  if (cached) {
    return cached;
  }

  if (isConfiguredAllowlisted(registeredDomain)) {
    const result: AllowlistResult = {
      matched: true,
      source: 'config',
      domain: registeredDomain,
      reason: 'verified_domain_registry'
    };
    await cacheSetJSON(cacheKey, result, TTL_SECONDS);
    return result;
  }

  try {
    const row = await prisma.domainScore.findUnique({
      where: { domain: registeredDomain },
      select: { domain: true, isWhitelisted: true, isConfirmed: true, riskScore: true }
    });
    if (row?.isWhitelisted && row.riskScore < 30) {
      const result: AllowlistResult = {
        matched: true,
        source: 'database',
        domain: row.domain,
        reason: row.isConfirmed ? 'confirmed_allowlist' : 'database_allowlist'
      };
      await cacheSetJSON(cacheKey, result, TTL_SECONDS);
      return result;
    }
  } catch {
    const fallback = await localPersistence.getDomainScore(registeredDomain).catch(() => null);
    if (fallback?.isWhitelisted && fallback.riskScore < 30) {
      const result: AllowlistResult = {
        matched: true,
        source: 'database',
        domain: fallback.domain,
        reason: fallback.isConfirmed ? 'confirmed_allowlist' : 'database_allowlist'
      };
      await cacheSetJSON(cacheKey, result, TTL_SECONDS);
      return result;
    }
  }

  const result: AllowlistResult = { matched: false, source: 'none' };
  await cacheSetJSON(cacheKey, result, 300);
  return result;
}
