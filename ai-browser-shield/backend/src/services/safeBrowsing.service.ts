import { env } from '../config';
import { cacheGetJSON, cacheSetJSON } from './cache.service';
import { logger } from '../utils/logger';

export interface ThreatIntelProviderResult {
  provider: 'google_safe_browsing' | 'virustotal' | 'phishtank';
  isMalicious: boolean;
  threatTypes: string[];
  source: 'google_safe_browsing' | 'virustotal' | 'phishtank';
  confidenceLevel: 'high' | 'medium' | 'low';
}

interface CircuitState {
  failures: number;
  openedAt: number | null;
}

const SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const SAFE_BROWSING_TIMEOUT_MS = 1500;
const SAFE_BROWSING_TTL_SECONDS = 600;
const MAX_RETRIES = 2;
const CIRCUIT_THRESHOLD = 3;
const CIRCUIT_COOLDOWN_MS = 60_000;
const circuits = new Map<string, CircuitState>();

const DEFAULT_RESULT: ThreatIntelProviderResult = {
  provider: 'google_safe_browsing',
  isMalicious: false,
  threatTypes: [],
  source: 'google_safe_browsing',
  confidenceLevel: 'low'
};

function getCacheKey(url: string): string {
  return `safebrowsing:${url}`;
}

function isCircuitOpen(provider: string): boolean {
  const state = circuits.get(provider);
  if (!state?.openedAt) return false;
  if (Date.now() - state.openedAt > CIRCUIT_COOLDOWN_MS) {
    circuits.set(provider, { failures: 0, openedAt: null });
    return false;
  }
  return true;
}

function recordFailure(provider: string) {
  const current = circuits.get(provider) ?? { failures: 0, openedAt: null };
  const failures = current.failures + 1;
  circuits.set(provider, {
    failures,
    openedAt: failures >= CIRCUIT_THRESHOLD ? Date.now() : current.openedAt
  });
}

function recordSuccess(provider: string) {
  circuits.set(provider, { failures: 0, openedAt: null });
}

async function withRetry<T>(provider: string, task: () => Promise<T>): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    try {
      return await task();
    } catch (error) {
      lastError = error;
    }
  }
  recordFailure(provider);
  throw lastError;
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function callGoogleSafeBrowsing(url: string): Promise<ThreatIntelProviderResult> {
  if (!env.SAFE_BROWSING_API_KEY || isCircuitOpen('google_safe_browsing')) {
    return DEFAULT_RESULT;
  }

  try {
    const result = await withRetry('google_safe_browsing', async () => {
      const response = await fetchWithTimeout(
        `${SAFE_BROWSING_URL}?key=${encodeURIComponent(env.SAFE_BROWSING_API_KEY)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: {
              clientId: 'ai-browser-shield',
              clientVersion: '2.0.0'
            },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }]
            }
          })
        },
        SAFE_BROWSING_TIMEOUT_MS
      );

      if (!response.ok) {
        throw new Error(`safe_browsing_http_${response.status}`);
      }

      const data = await response.json() as { matches?: Array<{ threatType?: string }> };
      const threatTypes = Array.from(new Set((data.matches ?? [])
        .map((match) => match.threatType)
        .filter((value): value is string => typeof value === 'string' && value.length > 0)));

      return {
        provider: 'google_safe_browsing' as const,
        isMalicious: threatTypes.length > 0,
        threatTypes,
        source: 'google_safe_browsing' as const,
        confidenceLevel: threatTypes.length > 0 ? 'high' as const : 'low' as const
      };
    });

    recordSuccess('google_safe_browsing');
    return result;
  } catch (error) {
    logger.warn({
      err: error instanceof Error ? error.message : 'unknown_error',
      url
    }, 'google safe browsing lookup failed, falling back to internal detection');
    return DEFAULT_RESULT;
  }
}

export async function checkGoogleSafeBrowsing(url: string): Promise<ThreatIntelProviderResult> {
  const cacheKey = getCacheKey(url);
  const cached = await cacheGetJSON<ThreatIntelProviderResult>(cacheKey);
  if (cached) {
    return cached;
  }

  const result = await callGoogleSafeBrowsing(url);
  await cacheSetJSON(cacheKey, result, SAFE_BROWSING_TTL_SECONDS);

  if (result.isMalicious) {
    logger.warn({
      url,
      threatTypes: result.threatTypes,
      source: result.source,
      timestamp: new Date().toISOString()
    }, 'google safe browsing hit');
  }

  return result;
}
