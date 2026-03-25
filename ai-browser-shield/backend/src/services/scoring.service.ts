import type { DomainIntelligence } from './domainIntelligence.service';
import type { DomainEnrichment } from './domainEnrichment.service';

export interface HeuristicResult {
  score: number;
  signals: Record<string, number>;
  signalsUsed: string[];
  positives: string[];
  warnings: string[];
}

export const TRUSTED_DOMAIN_ALLOWLIST = [
  'google.com',
  'mail.google.com',
  'outlook.com',
  'office.com',
  'microsoft.com',
  'yahoo.com',
  'mail.yahoo.com',
  'protonmail.com',
  'icloud.com',
  'apple.com',
  'github.com',
  'linkedin.com',
  'twitter.com',
  'x.com',
  'facebook.com',
  'amazon.com',
  'cloudflare.com',
  'fastly.com'
] as const;

export const TRUSTED_MAIL_DOMAIN_ALLOWLIST = [
  'mail.google.com',
  'outlook.com',
  'office.com',
  'microsoft.com',
  'yahoo.com',
  'mail.yahoo.com',
  'protonmail.com',
  'icloud.com'
] as const;

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
  '.click', '.loan', '.rest', '.cam', '.icu', '.sbs',
  '.monster', '.bar', '.cfd', '.cyou'
];

const TRUSTED_BRANDS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm'
];

const PHISHING_KEYWORDS = [
  'verify', 'suspend', 'confirm', 'credential', 'password',
  'account-update', 'login-verify', 'secure-update', 'kyc-update',
  'prize', 'winner', 'lottery', 'claim-now', 'free-recharge'
];

function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const replaceCost = dp[i - 1]![j - 1]!;
      const deleteCost = dp[i - 1]![j]!;
      const insertCost = dp[i]![j - 1]!;
      dp[i]![j] = a[i - 1] === b[j - 1]
        ? replaceCost
        : 1 + Math.min(deleteCost, insertCost, replaceCost);
    }
  }

  return dp[a.length]![b.length]!;
}

function shannonEntropy(str: string): number {
  if (!str || str.length < 2) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  return -Object.values(freq).reduce((sum, count) => {
    const probability = count / str.length;
    return sum + probability * Math.log2(probability);
  }, 0);
}

function estimateDomainAgeDays(hostname: string, intel: DomainIntelligence): number {
  if (intel.isOfficialTLD) return 3650;
  if (/(^|[-.])(202[4-6]|new|secure|verify|login)([-.]|$)/i.test(hostname)) return 21;
  if (hostname.includes('-') || /\d/.test(intel.registeredLabel)) return 90;
  return 540;
}

const addSignal = (
  signals: Record<string, number>,
  signalsUsed: string[],
  key: string,
  value: number,
  reason: string
) => {
  signals[key] = value;
  if (value > 0) {
    signalsUsed.push(reason);
  }
};

const normalizeHostname = (hostname: string): string => hostname.toLowerCase().replace(/^www\./, '');

const matchesTrustedDomain = (hostname: string, allowlist: readonly string[]): boolean => {
  const normalized = normalizeHostname(hostname);
  return allowlist.some((trusted) => normalized === trusted || normalized.endsWith(`.${trusted}`));
};

export const isTrustedDomain = (hostname: string): boolean =>
  matchesTrustedDomain(hostname, TRUSTED_DOMAIN_ALLOWLIST);

export const isTrustedMailDomain = (hostname: string): boolean =>
  matchesTrustedDomain(hostname, TRUSTED_MAIL_DOMAIN_ALLOWLIST);

export function computeHeuristics(rawUrl: string, intel: DomainIntelligence, enrichment?: DomainEnrichment): HeuristicResult {
  const signals: Record<string, number> = {};
  const signalsUsed: string[] = [];
  const positives = [...intel.positives];
  const warnings = [...intel.warnings];

  const trustedDomain = isTrustedDomain(intel.hostname);

  if (intel.isOfficialTLD && !intel.hasSubdomainSpoofing && !intel.homoglyph.hasHomoglyphRisk) {
    return {
      score: 0,
      signals: {},
      signalsUsed: ['official_tld_bypass'],
      positives,
      warnings
    };
  }

  if (
    trustedDomain &&
    !intel.hasSubdomainSpoofing &&
    !intel.homoglyph.hasHomoglyphRisk &&
    !intel.hasIPHostname &&
    !intel.impersonatedBrand
  ) {
    return {
      score: 2,
      signals: {},
      signalsUsed: ['trusted_domain_allowlist'],
      positives: Array.from(new Set([...positives, 'Trusted service allowlist'])),
      warnings
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      score: 50,
      signals: { parse_failure: 50 },
      signalsUsed: ['url_parse_failure'],
      positives,
      warnings: [...warnings, 'Invalid URL format']
    };
  }

  const hostname = intel.decodedHostname;
  const registeredLabel = intel.registeredLabel.toLowerCase();
  const normalizedRegisteredLabel = registeredLabel.replace(/[^a-z0-9]/g, '');

  let typosquatScore = 0;
  for (const brand of TRUSTED_BRANDS) {
    if (normalizedRegisteredLabel === brand) continue;

    const distance = levenshtein(normalizedRegisteredLabel, brand);
    if (distance > 0 && distance <= 2) {
      typosquatScore = Math.min(25, Math.max(typosquatScore, 14 + (3 - distance) * 5));
      warnings.push('Possible impersonation');
      signalsUsed.push(`typosquat:${brand}`);
      break;
    }
  }
  signals.typosquatScore = typosquatScore;

  const suspiciousTldScore = SUSPICIOUS_TLDS.some((suffix) => hostname.endsWith(suffix)) ? 12 : 0;
  addSignal(signals, signalsUsed, 'suspiciousTLD', suspiciousTldScore, 'suspicious_tld');

  const ipScore = intel.hasIPHostname ? 20 : 0;
  addSignal(signals, signalsUsed, 'ipAsHostname', ipScore, 'ip_hostname');

  const subdomainScore = intel.subdomainDepth > 3 ? Math.min(16, 8 + (intel.subdomainDepth - 3) * 2) : 0;
  addSignal(signals, signalsUsed, 'longSubdomains', subdomainScore, 'excessive_subdomains');

  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const keywordMatches = PHISHING_KEYWORDS.filter((keyword) => pathAndQuery.includes(keyword)).length;
  const keywordScore = Math.min(14, keywordMatches * 4);
  addSignal(signals, signalsUsed, 'suspiciousKeywords', keywordScore, `keywords:${keywordMatches}`);

  const encodedCount = (parsed.href.match(/%[0-9a-f]{2}/gi) || []).length;
  addSignal(signals, signalsUsed, 'encodedChars', encodedCount > 3 ? 8 : 0, 'encoded_chars');

  const entropyTarget = `${normalizedRegisteredLabel}${parsed.pathname}`.replace(/[^a-z0-9/_-]/gi, '');
  const entropyScore = shannonEntropy(entropyTarget) > 4.2 ? 9 : 0;
  addSignal(signals, signalsUsed, 'pathEntropy', entropyScore, 'high_entropy_structure');

  const port = Number.parseInt(parsed.port || '0', 10);
  addSignal(signals, signalsUsed, 'portAnomaly', port > 0 && ![80, 443, 8080, 8443].includes(port) ? 8 : 0, 'port_anomaly');

  const keywordStuffingMatches = TRUSTED_BRANDS.filter((brand) => hostname.includes(brand)).length;
  const keywordStuffingScore = keywordStuffingMatches > 1 ? Math.min(18, keywordStuffingMatches * 6) : 0;
  addSignal(signals, signalsUsed, 'keywordStuffing', keywordStuffingScore, 'keyword_stuffing');

  const domainEntropyScore = shannonEntropy(normalizedRegisteredLabel) > 3.6 ? 10 : 0;
  addSignal(signals, signalsUsed, 'domainEntropy', domainEntropyScore, 'high_domain_entropy');

  const domainAgeDays = enrichment?.domainAgeDays ?? estimateDomainAgeDays(hostname, intel);
  const domainAgeScore = domainAgeDays < 30 ? 18 : domainAgeDays < 120 ? 10 : 0;
  addSignal(signals, signalsUsed, 'domainAge', domainAgeScore, 'newly_registered_domain');
  if (domainAgeScore > 0) warnings.push('Newly registered domain');

  const dnsInstabilityScore = enrichment?.dnsStatus === 'nxdomain' ? 16 : enrichment?.dnsFastFluxRisk ? 12 : 0;
  addSignal(signals, signalsUsed, 'dnsInstability', dnsInstabilityScore, enrichment?.dnsStatus === 'nxdomain' ? 'dns_nxdomain' : 'dns_fast_flux');

  const sslRiskScore =
    enrichment?.sslStatus === 'self_signed' ? 18
      : enrichment?.sslStatus === 'hostname_mismatch' ? 15
        : enrichment?.sslStatus === 'invalid' ? 10
          : 0;
  addSignal(signals, signalsUsed, 'sslRisk', sslRiskScore, `ssl_${enrichment?.sslStatus ?? 'unknown'}`);

  const hostingRiskScore = enrichment?.asnReputation === 'cheap_hosting' ? 10 : 0;
  addSignal(signals, signalsUsed, 'hostingRisk', hostingRiskScore, 'cheap_hosting_provider');

  addSignal(signals, signalsUsed, 'subdomainSpoofing', intel.hasSubdomainSpoofing ? 26 : 0, 'subdomain_spoofing');
  addSignal(signals, signalsUsed, 'brandImpersonation', intel.impersonatedBrand ? 22 : 0, `brand_impersonation:${intel.impersonatedBrand ?? 'unknown'}`);
  addSignal(signals, signalsUsed, 'homoglyphRisk', intel.homoglyph.score, intel.homoglyph.hasPunycode ? 'punycode_domain' : 'homoglyph_attack');

  const weightedScore =
    (signals.typosquatScore ?? 0) * 1.0 +
    (signals.suspiciousTLD ?? 0) * 0.9 +
    (signals.ipAsHostname ?? 0) * 1.1 +
    (signals.longSubdomains ?? 0) * 0.8 +
    (signals.suspiciousKeywords ?? 0) * 0.9 +
    (signals.encodedChars ?? 0) * 0.7 +
    (signals.pathEntropy ?? 0) * 0.8 +
    (signals.portAnomaly ?? 0) * 0.7 +
    (signals.keywordStuffing ?? 0) * 1.0 +
    (signals.domainEntropy ?? 0) * 0.8 +
    (signals.domainAge ?? 0) * 0.9 +
    (signals.dnsInstability ?? 0) * 1.1 +
    (signals.sslRisk ?? 0) * 1.0 +
    (signals.hostingRisk ?? 0) * 0.8 +
    (signals.subdomainSpoofing ?? 0) * 1.0 +
    (signals.brandImpersonation ?? 0) * 1.0 +
    (signals.homoglyphRisk ?? 0) * 1.0;

  const trustReduction = Math.round(intel.trustScore * 0.22);
  const finalScore = Math.min(100, Math.max(0, Math.round(weightedScore - trustReduction)));

  return {
    score: finalScore,
    signals,
    signalsUsed: Array.from(new Set(signalsUsed)),
    positives,
    warnings: Array.from(new Set(warnings))
  };
}
