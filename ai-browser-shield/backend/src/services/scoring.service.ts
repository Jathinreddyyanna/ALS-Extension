import type { DomainIntelligence } from './domainIntelligence.service';
import type { DomainEnrichment } from './domainEnrichment.service';

export interface HeuristicResult {
  score: number;
  signals: Record<string, number>;
  signalsUsed: string[];
  positives: string[];
  warnings: string[];
}

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
  '.click', '.loan', '.rest', '.cam', '.icu', '.sbs',
  '.monster', '.bar', '.cfd', '.cyou',
  // High-risk TLDs commonly used for phishing
  '.digital', '.trade', '.online', '.work', '.party',
  '.review', '.accountant', '.zip', '.mov', '.phd'
];

const TRUSTED_BRANDS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm'
];

const PHISHING_KEYWORDS = [
  'verify', 'suspend', 'confirm', 'credential', 'password',
  'account-update', 'login-verify', 'secure-update', 'kyc-update',
  'prize', 'winner', 'lottery', 'claim-now', 'free-recharge',
  // Crypto-related phishing keywords
  'ledger', 'trezor', 'wallet', 'treasury', 'metamask',
  'coinbase', 'binance', 'crypto', 'blockchain'
];

const FREE_HOSTING_DOMAINS = [
  'pages.dev', 'herokuapp.com', 'xo.je', 'netlify.app',
  'vercel.app', 'web.app', 'firebaseapp.com', 'github.io',
  'gitlab.io', 'azurewebsites.net', 'cloudflareaccess.com'
];

const SUSPICIOUS_PHP_FILES = [
  'login.php', 'class.php', 'secure.php', 'verify.php',
  'update.php', 'auth.php', 'account.php', 'banking.php'
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

export function computeHeuristics(rawUrl: string, intel: DomainIntelligence, enrichment?: DomainEnrichment): HeuristicResult {
  const signals: Record<string, number> = {};
  const signalsUsed: string[] = [];
  const positives = [...intel.positives];
  const warnings = [...intel.warnings];

  if (intel.isOfficialTLD && !intel.hasSubdomainSpoofing && !intel.homoglyph.hasHomoglyphRisk) {
    return {
      score: 0,
      signals: {},
      signalsUsed: ['official_tld_bypass'],
      positives,
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
      typosquatScore = Math.min(40, Math.max(typosquatScore, 25 + (3 - distance) * 7));
      warnings.push('Possible impersonation');
      signalsUsed.push(`typosquat:${brand}`);
      break;
    }
  }
  signals.typosquatScore = typosquatScore;

  const suspiciousTldScore = SUSPICIOUS_TLDS.some((suffix) => hostname.endsWith(suffix)) ? 25 : 0;
  addSignal(signals, signalsUsed, 'suspiciousTLD', suspiciousTldScore, 'suspicious_tld');

  const ipScore = intel.hasIPHostname ? 50 : 0;
  addSignal(signals, signalsUsed, 'ipAsHostname', ipScore, 'ip_hostname');

  const subdomainScore = intel.subdomainDepth > 3 ? Math.min(30, 15 + (intel.subdomainDepth - 3) * 5) : 0;
  addSignal(signals, signalsUsed, 'longSubdomains', subdomainScore, 'excessive_subdomains');

  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const keywordMatches = PHISHING_KEYWORDS.filter((keyword) => pathAndQuery.includes(keyword)).length;
  const keywordScore = Math.min(45, keywordMatches * 10);
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
  const domainAgeScore = domainAgeDays < 30 ? 35 : domainAgeDays < 120 ? 18 : 0;
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

  const hostingRiskScore = enrichment?.asnReputation === 'cheap_hosting' ? 35 : 0;
  addSignal(signals, signalsUsed, 'hostingRisk', hostingRiskScore, 'cheap_hosting_provider');

  addSignal(signals, signalsUsed, 'subdomainSpoofing', intel.hasSubdomainSpoofing ? 45 : 0, 'subdomain_spoofing');
  addSignal(signals, signalsUsed, 'brandImpersonation', intel.impersonatedBrand ? 50 : 0, `brand_impersonation:${intel.impersonatedBrand ?? 'unknown'}`);
  addSignal(signals, signalsUsed, 'homoglyphRisk', intel.homoglyph.score >= 30 ? 40 : intel.homoglyph.score, intel.homoglyph.hasPunycode ? 'punycode_domain' : 'homoglyph_attack');

  // CRITICAL PATTERN: Base64 encoded parameters (common phishing redirect obfuscation)
  const base64ParamScore = /[\?&][a-z0-9_]+=[A-Za-z0-9+/]{20,}={0,2}/i.test(parsed.search) ? 40 : 0;
  addSignal(signals, signalsUsed, 'base64Params', base64ParamScore, 'base64_encoded_params');

  // CRITICAL PATTERN: Crypto-related keywords in domain or path (high-value phishing targets)
  const cryptoKeywordsInDomain = PHISHING_KEYWORDS.slice(7).filter((keyword) =>
    normalizedRegisteredLabel.includes(keyword.replace(/[^a-z0-9]/g, '')) ||
    pathAndQuery.includes(keyword)
  ).length;
  const cryptoKeywordScore = cryptoKeywordsInDomain > 0 ? 45 : 0;
  addSignal(signals, signalsUsed, 'cryptoKeywords', cryptoKeywordScore, `crypto_keywords:${cryptoKeywordsInDomain}`);

  // CRITICAL PATTERN: Free hosting provider (pages.dev, herokuapp.com, etc.)
  const freeHostingScore = FREE_HOSTING_DOMAINS.some((host) => hostname.includes(host)) ? 35 : 0;
  addSignal(signals, signalsUsed, 'freeHosting', freeHostingScore, 'free_hosting_provider');

  // CRITICAL PATTERN: Suspicious PHP file names (login.php, class.php, etc.)
  const hasPhpFile = SUSPICIOUS_PHP_FILES.some((filename) => pathAndQuery.includes(filename));
  const phpFileScore = hasPhpFile ? 35 : 0;
  addSignal(signals, signalsUsed, 'suspiciousPhpFile', phpFileScore, 'suspicious_php_file');

  // CRITICAL PATTERN: Random subdomain (high entropy subdomain like sknanbkyc.digital)
  const subdomainParts = hostname.split('.');
  let randomSubdomainScore = 0;
  if (subdomainParts.length >= 3) {
    const firstSubdomain = subdomainParts[0] || '';
    // High entropy + doesn't match known patterns = likely random
    const subdomainEntropy = shannonEntropy(firstSubdomain);
    if (subdomainEntropy > 3.8 && firstSubdomain.length > 8 && !intel.hasSubdomainSpoofing) {
      randomSubdomainScore = 40;
      addSignal(signals, signalsUsed, 'randomSubdomain', randomSubdomainScore, 'random_subdomain');
    }
  }

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
    (signals.homoglyphRisk ?? 0) * 1.0 +
    (signals.base64Params ?? 0) * 1.0 +
    (signals.cryptoKeywords ?? 0) * 1.0 +
    (signals.freeHosting ?? 0) * 0.9 +
    (signals.suspiciousPhpFile ?? 0) * 0.9 +
    (signals.randomSubdomain ?? 0) * 0.95;

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
