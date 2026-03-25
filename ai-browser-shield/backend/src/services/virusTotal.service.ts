import { env } from '../config';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { runResilientTask } from './resilience.service';
import { logger } from '../utils/logger';
import type { ThreatIntelProviderResult } from './safeBrowsing.service';

const VIRUSTOTAL_CACHE_TTL_SECONDS = 12 * 60 * 60;

interface VirusTotalUrlReport {
  data?: {
    attributes?: {
      last_analysis_stats?: {
        malicious?: number;
        suspicious?: number;
        harmless?: number;
      };
    };
  };
}

function toUrlId(url: string): string {
  return Buffer.from(url).toString('base64url');
}

function getVirusTotalCacheKey(url: string): string {
  return `virustotal:url:${toUrlId(url)}`;
}

/**
 * Queries VirusTotal for a cached URL analysis summary.
 * Returns `null` when no API key is configured or the provider is unavailable.
 */
export async function checkVirusTotal(url: string): Promise<ThreatIntelProviderResult | null> {
  if (!env.VIRUSTOTAL_API_KEY) return null;

  const cacheKey = getVirusTotalCacheKey(url);
  const cached = await cacheGetJSON<ThreatIntelProviderResult>(cacheKey);
  if (cached) return cached;

  try {
    const response = await runResilientTask(() => fetch(`https://www.virustotal.com/api/v3/urls/${toUrlId(url)}`, {
      headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY }
    }), {
      name: 'virustotal',
      retries: 1,
      timeoutMs: env.PROVIDER_TIMEOUT_MS,
      baseDelayMs: 200
    });

    if (!response.ok) return null;

    const data = await response.json() as VirusTotalUrlReport;
    const stats = data.data?.attributes?.last_analysis_stats;
    const malicious = Number(stats?.malicious ?? 0);
    const suspicious = Number(stats?.suspicious ?? 0);

    const result: ThreatIntelProviderResult = {
      provider: 'virustotal',
      isMalicious: malicious > 0 || suspicious > 2,
      threatTypes: malicious > 0
        ? ['VIRUSTOTAL_MALICIOUS']
        : suspicious > 2
          ? ['VIRUSTOTAL_SUSPICIOUS']
          : [],
      source: 'virustotal',
      confidenceLevel: malicious > 0 ? 'high' : suspicious > 2 ? 'medium' : 'low'
    };

    await cacheSetJSON(cacheKey, result, VIRUSTOTAL_CACHE_TTL_SECONDS);
    return result;
  } catch (error) {
    logger.debug({ err: error, url }, 'virustotal lookup failed');
    return null;
  }
}
