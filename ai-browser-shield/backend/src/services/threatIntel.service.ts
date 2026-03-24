import { env } from '../config';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { checkGoogleSafeBrowsing, type ThreatIntelProviderResult } from './safeBrowsing.service';
import { runResilientTask } from './resilience.service';
import { logger } from '../utils/logger';

export interface ThreatIntelAggregateResult {
  isMalicious: boolean;
  sources: string[];
  threatTypes: string[];
  threatSource: 'google' | 'internal' | 'multi';
  confidenceLevel: 'high' | 'medium' | 'low';
  matchedProviders: ThreatIntelProviderResult[];
}

const AUX_CACHE_TTL_SECONDS = 600;

function toUrlId(url: string): string {
  return Buffer.from(url).toString('base64url');
}

async function fetchVirusTotal(url: string): Promise<ThreatIntelProviderResult | null> {
  if (!env.VIRUSTOTAL_API_KEY) return null;

  try {
    const response = await runResilientTask(() => fetch(`https://www.virustotal.com/api/v3/urls/${toUrlId(url)}`, {
      headers: { 'x-apikey': env.VIRUSTOTAL_API_KEY }
    }), { name: 'virustotal', retries: 1, timeoutMs: env.PROVIDER_TIMEOUT_MS, baseDelayMs: 200 });
    if (!response.ok) return null;

    const data = await response.json() as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } } };
    };
    const stats = data.data?.attributes?.last_analysis_stats;
    const malicious = Number(stats?.malicious ?? 0);
    const suspicious = Number(stats?.suspicious ?? 0);

    return {
      provider: 'virustotal',
      isMalicious: malicious > 0 || suspicious > 2,
      threatTypes: malicious > 0 ? ['VIRUSTOTAL_MALICIOUS'] : suspicious > 2 ? ['VIRUSTOTAL_SUSPICIOUS'] : [],
      source: 'virustotal',
      confidenceLevel: malicious > 0 ? 'high' : suspicious > 2 ? 'medium' : 'low'
    };
  } catch (error) {
    logger.debug({ err: error, url }, 'virustotal lookup failed');
    return null;
  }
}

async function fetchPhishTank(url: string): Promise<ThreatIntelProviderResult | null> {
  if (!env.PHISHTANK_API_KEY) return null;

  const cacheKey = `phishtank:${url}`;
  const cached = await cacheGetJSON<ThreatIntelProviderResult>(cacheKey);
  if (cached) return cached;

  try {
    const form = new URLSearchParams({
      url,
      app_key: env.PHISHTANK_API_KEY,
      format: 'json'
    });

    const response = await runResilientTask(() => fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'ai-browser-shield'
      },
      body: form.toString()
    }), { name: 'phishtank', retries: 1, timeoutMs: env.PROVIDER_TIMEOUT_MS, baseDelayMs: 200 });
    if (!response.ok) return null;

    const data = await response.json() as { results?: { valid?: boolean; in_database?: boolean; verified?: boolean } };
    const matched = Boolean(data.results?.valid && data.results?.in_database && data.results?.verified);

    const result: ThreatIntelProviderResult = {
      provider: 'phishtank',
      isMalicious: matched,
      threatTypes: matched ? ['PHISHTANK_PHISHING'] : [],
      source: 'phishtank',
      confidenceLevel: matched ? 'high' : 'low'
    };
    await cacheSetJSON(cacheKey, result, AUX_CACHE_TTL_SECONDS);
    return result;
  } catch (error) {
    logger.debug({ err: error, url }, 'phishtank lookup failed');
    return null;
  }
}

function summarizeThreatIntel(results: ThreatIntelProviderResult[]): ThreatIntelAggregateResult {
  const matchedProviders = results.filter((result) => result.isMalicious);
  const sources = matchedProviders.map((item) => item.provider);
  const threatTypes = Array.from(new Set(matchedProviders.flatMap((item) => item.threatTypes)));

  return {
    isMalicious: matchedProviders.length > 0,
    sources,
    threatTypes,
    threatSource:
      matchedProviders.some((item) => item.provider === 'google_safe_browsing') ? 'google'
        : matchedProviders.length > 1 ? 'multi'
          : 'internal',
    confidenceLevel:
      matchedProviders.some((item) => item.confidenceLevel === 'high') ? 'high'
        : matchedProviders.some((item) => item.confidenceLevel === 'medium') ? 'medium'
          : 'low',
    matchedProviders
  };
}

export async function aggregateThreatIntel(url: string): Promise<ThreatIntelAggregateResult> {
  const providers: Array<Promise<ThreatIntelProviderResult | null>> = [
    checkGoogleSafeBrowsing(url),
    fetchVirusTotal(url),
    fetchPhishTank(url)
  ];

  const google = await providers[0];
  if (!google) {
    return summarizeThreatIntel([]);
  }
  if (google.isMalicious) {
    return summarizeThreatIntel([google]);
  }

  const others = await Promise.all(providers.slice(1));
  const normalized = [google, ...others.filter((item): item is ThreatIntelProviderResult => item !== null)];
  return summarizeThreatIntel(normalized);
}
