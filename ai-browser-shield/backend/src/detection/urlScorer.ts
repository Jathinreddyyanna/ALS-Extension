import { analyzeDomain } from '../services/domainIntelligence.service';
import { computeHeuristics } from '../services/scoring.service';
import type { ParsedUrlResult, RiskLevel, UrlScoreResult, UrlScoreSignals } from '../types/scan.types';

const BRAND_TLD_BASELINES: Record<string, string[]> = {
  paypal: ['paypal.com'],
  google: ['google.com'],
  microsoft: ['microsoft.com'],
  amazon: ['amazon.com'],
  apple: ['apple.com'],
  sbi: ['sbi.co.in', 'sbi.bank.in']
};

const scoreToRiskLevel = (score: number): RiskLevel => {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
};

export const scoreUrl = (parsed: ParsedUrlResult): UrlScoreResult => {
  const intel = analyzeDomain(parsed.normalizedUrl);
  const heuristic = computeHeuristics(parsed.normalizedUrl, intel);
  const hostname = intel.decodedHostname.toLowerCase();
  const queryEntries = Object.entries(parsed.queryParams);
  const hostnameLabels = hostname.split('.').filter(Boolean);
  const subdomainLabels = hostnameLabels.slice(0, Math.max(0, hostnameLabels.length - 2));
  const excessiveDots = hostnameLabels.length >= 8 ? 5 : 0;
  const numericSubdomain = subdomainLabels.some((label) => /^\d+$/.test(label)) ? 10 : 0;
  const redirectParam = queryEntries.some(([key, value]) =>
    /^(url|redirect|redirect_uri|next|target|dest)$/i.test(key) && /^https?:\/\//i.test(value)
  ) ? 10 : 0;
  const tldMismatch = Object.entries(BRAND_TLD_BASELINES).some(([brand, allowedDomains]) =>
    hostname.includes(brand) && !allowedDomains.some((domain) => intel.registeredDomain === domain)
  ) ? 10 : 0;

  const signals: UrlScoreSignals = {
    typosquat: heuristic.signals.typosquatScore ?? 0,
    suspiciousTLD: heuristic.signals.suspiciousTLD ?? 0,
    ipAsHostname: heuristic.signals.ipAsHostname ?? 0,
    longSubdomains: heuristic.signals.longSubdomains ?? 0,
    suspiciousKeywords: heuristic.signals.suspiciousKeywords ?? 0,
    encodedChars: heuristic.signals.encodedChars ?? 0,
    pathEntropy: heuristic.signals.pathEntropy ?? 0,
    portAnomaly: heuristic.signals.portAnomaly ?? 0,
    credentialInUrl: parsed.hasCredentials ? 25 : 0,
    idnHomoglyph: intel.homoglyph.score,
    excessiveDots,
    numericSubdomain,
    tldMismatch,
    repeatingSegments: 0,
    queryParamCount: 0,
    redirectParam
  };

  const finalScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(
        heuristic.score +
        signals.credentialInUrl +
        signals.excessiveDots +
        signals.numericSubdomain +
        signals.tldMismatch +
        signals.redirectParam
      )
    )
  );
  return {
    score: finalScore,
    riskLevel: scoreToRiskLevel(finalScore),
    signals,
    indicators: Object.entries(signals)
      .filter(([, value]) => value > 0)
      .map(([key]) => key)
  };
};
