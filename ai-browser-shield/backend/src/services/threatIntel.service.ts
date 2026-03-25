import { env } from '../config';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { checkGoogleSafeBrowsing, type ThreatIntelProviderResult } from './safeBrowsing.service';
import { runResilientTask } from './resilience.service';
import { checkVirusTotal } from './virusTotal.service';
import { resolveFinalUrl } from './urlResolver.service';
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
let openPhishCache: Set<string> | null = null;
let openPhishCacheExpiry = 0;

const OPENPHISH_REFRESH_INTERVAL_MS = 3600000; // 1 hour

async function fetchOpenPhishFeed(): Promise<Set<string>> {
  const now = Date.now();

  // Return cached feed if still valid
  if (openPhishCache && now < openPhishCacheExpiry) {
    return openPhishCache;
  }

  try {
    logger.debug('Fetching OpenPhish feed...');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await runResilientTask(
      () => fetch('https://openphish.com/feed.txt', {
        signal: controller.signal,
        headers: { 'User-Agent': 'ai-browser-shield' }
      }),
      { name: 'openphish_feed', retries: 1, timeoutMs: 10000, baseDelayMs: 500 }
    );

    clearTimeout(timeoutId);

    if (!response.ok) {
      logger.warn({ status: response.status }, 'OpenPhish feed fetch failed');
      return openPhishCache || new Set();
    }

    const text = await response.text();
    const domains = new Set<string>();

    // Extract domains from URLs (one per line)
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const url = new URL(trimmed);
        domains.add(url.hostname);
      } catch {
        // Skip malformed URLs
      }
    }

    openPhishCache = domains;
    openPhishCacheExpiry = now + OPENPHISH_REFRESH_INTERVAL_MS;
    logger.info({ count: domains.size }, 'OpenPhish feed updated');
    return domains;
  } catch (error) {
    logger.debug({ err: error }, 'OpenPhish feed fetch error');
    return openPhishCache || new Set();
  }
}

async function checkOpenPhish(url: string): Promise<ThreatIntelProviderResult | null> {
  try {
    const parsed = new URL(url);
    const openPhishDomains = await fetchOpenPhishFeed();

    if (openPhishDomains.has(parsed.hostname)) {
      logger.warn({ url, hostname: parsed.hostname }, '[OpenPhish] URL matched OpenPhish feed');
      return {
        provider: 'openphish',
        isMalicious: true,
        threatTypes: ['OPENPHISH_PHISHING'],
        source: 'openphish',
        confidenceLevel: 'high'
      };
    }
  } catch (error) {
    logger.debug({ err: error, url }, 'OpenPhish check failed');
  }

  return null;
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
  const resolvedUrl = resolveFinalUrl(url).finalUrl;

  logger.debug({ url: resolvedUrl }, '[GSB] Checking URL against threat intel providers');

  const providers: Array<Promise<ThreatIntelProviderResult | null>> = [
    checkGoogleSafeBrowsing(resolvedUrl),
    checkVirusTotal(resolvedUrl),
    fetchPhishTank(resolvedUrl),
    checkOpenPhish(resolvedUrl)
  ];

  const google = await providers[0];

  logger.debug({
    url: resolvedUrl,
    googleResult: google,
    isMalicious: google?.isMalicious ?? false,
    threatTypes: google?.threatTypes ?? []
  }, '[GSB] Google Safe Browsing result');

  if (!google) {
    logger.warn({ url: resolvedUrl }, '[GSB] Google Safe Browsing returned null - API may be down or quota exceeded');
    // Continue to check other providers including OpenPhish fallback
  } else if (google.isMalicious) {
    logger.warn({ url: resolvedUrl, threatTypes: google.threatTypes }, '[GSB] THREAT DETECTED by Google Safe Browsing');
    return summarizeThreatIntel([google]);
  }

  const others = await Promise.all(providers.slice(1));
  const filtered: ThreatIntelProviderResult[] = others.length > 0
    ? others.filter((item): item is ThreatIntelProviderResult => item !== null)
    : [];
  const normalized = google ? [google, ...filtered] : filtered;
  return summarizeThreatIntel(normalized);
}
