import { BRAND_TLD_MAP, GOV_EDU_SUFFIXES, PHISHING_KEYWORDS, REDIRECT_PARAM_KEYS, SUSPICIOUS_TLDS, TRUSTED_BRANDS, TRUSTED_DOMAIN_WHITELIST } from '../config/constants';
import { levenshtein } from '../utils/levenshtein';
import { isIpv4, isIpv6, isPrivateIp } from '../utils/ip';
import { hasMixedScriptHostname } from './homoglyphDetector';
import type { ParsedUrlResult, RiskLevel, UrlScoreResult, UrlScoreSignals } from '../types/scan.types';

const standardPorts = new Set(['80', '443', '8080', '8443', '3000', '5000', '8000', '8888']);

const entropy = (value: string): number => {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let result = 0;
  counts.forEach((count) => {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  });
  return result;
};

const scoreToRiskLevel = (score: number): RiskLevel => {
  if (score >= 75) {
    return 'CRITICAL';
  }
  if (score >= 50) {
    return 'HIGH';
  }
  if (score >= 30) {
    return 'MEDIUM';
  }
  return 'LOW';
};

const getRootLabel = (hostname: string): string => (hostname.replace(/^www\./, '').split('.')[0] ?? '').toLowerCase();

const getTyposquatScore = (hostname: string): number => {
  const root = getRootLabel(hostname).split(/[-_]/)[0] ?? '';
  let best = 0;
  for (const brand of TRUSTED_BRANDS) {
    const normalizedBrand = brand.toLowerCase().replace(/[^a-z0-9]/g, '');
    const normalizedRoot = root.replace(/[^a-z0-9]/g, '');
    if (!normalizedBrand || normalizedRoot === normalizedBrand) {
      continue;
    }
    const distance = levenshtein(normalizedRoot, normalizedBrand);
    if (distance <= 2) {
      best = Math.max(best, 25 - distance * 5);
    }
  }
  return best;
};

const getSuspiciousKeywordScore = (target: string): number => {
  const normalized = target.toLowerCase();
  const hits = PHISHING_KEYWORDS.filter((keyword) => normalized.includes(keyword.toLowerCase())).length;
  return Math.min(15, hits * 3);
};

const getRedirectParamScore = (queryParams: Record<string, string>): number => {
  const keys = Object.keys(queryParams);
  return keys.some((key) => REDIRECT_PARAM_KEYS.includes(key as (typeof REDIRECT_PARAM_KEYS)[number])) ? 10 : 0;
};

const hasRepeatingSegments = (parsed: ParsedUrlResult): boolean => {
  const segments = parsed.path.split('/').filter(Boolean);
  const segmentCounts = segments.reduce<Record<string, number>>((acc, segment) => {
    acc[segment] = (acc[segment] ?? 0) + 1;
    return acc;
  }, {});
  const queryKeys = Object.keys(parsed.queryParams);
  const queryCounts = queryKeys.reduce<Record<string, number>>((acc, key) => {
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  return Object.values(segmentCounts).some((count) => count > 3) || Object.values(queryCounts).some((count) => count > 3);
};

const getTld = (hostname: string): string => hostname.replace(/^\[|\]$/g, '').split('.').at(-1)?.toLowerCase() ?? '';

export const scoreUrl = (parsed: ParsedUrlResult): UrlScoreResult => {
  const hostname = parsed.hostnameUnicode.toLowerCase();
  const hostLabels = hostname.replace(/^\[|\]$/g, '').split('.').filter(Boolean);
  const tld = getTld(hostname);
  const isWhitelisted = TRUSTED_DOMAIN_WHITELIST.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  const trustBonus = GOV_EDU_SUFFIXES.some((suffix) => hostname.endsWith(suffix)) ? -15 : 0;
  const encodedSegments = (parsed.normalizedUrl.match(/%[0-9a-f]{2}/gi) ?? []).length;
  const publicIpHostname = (isIpv4(parsed.hostname) || isIpv6(parsed.hostname.replace(/^\[|\]$/g, ''))) && !isPrivateIp(parsed.hostname);
  const suspiciousTld = SUSPICIOUS_TLDS.some((item) => item === tld) ? 15 : 0;
  const brandInHostname = TRUSTED_BRANDS.find((brand) => hostname.includes(brand.toLowerCase().replace(/[^a-z0-9.-]/g, '')));
  const tldMismatch = brandInHostname && BRAND_TLD_MAP[brandInHostname] && !BRAND_TLD_MAP[brandInHostname]!.includes(tld) ? 15 : 0;

  const signals: UrlScoreSignals = {
    typosquat: getTyposquatScore(hostname),
    suspiciousTLD: suspiciousTld,
    ipAsHostname: publicIpHostname ? 20 : 0,
    longSubdomains: hostLabels.length > 4 ? 10 : 0,
    suspiciousKeywords: getSuspiciousKeywordScore(parsed.decodedUrl),
    encodedChars: encodedSegments > 3 ? 10 : 0,
    pathEntropy: entropy(parsed.path) > 4.5 ? 10 : 0,
    portAnomaly: parsed.port.length > 0 && !standardPorts.has(parsed.port) ? 10 : 0,
    credentialInUrl: parsed.hasCredentials ? 25 : 0,
    idnHomoglyph: hasMixedScriptHostname(parsed.hostnameUnicode) ? 20 : 0,
    excessiveDots: (hostname.match(/\./g) ?? []).length > 5 ? 5 : 0,
    numericSubdomain: hostLabels.slice(0, -2).some((label) => /^\d+$/.test(label)) ? 10 : 0,
    tldMismatch,
    repeatingSegments: hasRepeatingSegments(parsed) ? 8 : 0,
    queryParamCount: Object.keys(parsed.queryParams).length > 10 ? 5 : 0,
    redirectParam: getRedirectParamScore(parsed.queryParams)
  };

  let score = Object.values(signals).reduce((sum, current) => sum + current, 0) + trustBonus;
  if (isWhitelisted && score > 40) {
    score = 40;
  }

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));
  return {
    score: finalScore,
    riskLevel: scoreToRiskLevel(finalScore),
    signals,
    indicators: Object.entries(signals)
      .filter(([, value]) => value > 0)
      .map(([key]) => key)
  };
};
