import { analyzeHomoglyphs, type HomoglyphAnalysis } from '../utils/homoglyphDetector';

export interface DomainIntelligence {
  hostname: string;
  decodedHostname: string;
  registeredDomain: string;
  registeredLabel: string;
  isOfficialTLD: boolean;
  officialTld?: string;
  isHTTPS: boolean;
  hasIPHostname: boolean;
  subdomainDepth: number;
  trustScore: number;
  hasSubdomainSpoofing: boolean;
  impersonatedBrand?: string;
  brandInSubdomain?: string;
  homoglyph: HomoglyphAnalysis;
  positives: string[];
  warnings: string[];
}

const OFFICIAL_TLDS = [
  'gov.in', 'nic.in', 'bank.in', 'fin.in', 'edu.in',
  'ac.in', 'res.in', 'mil.in',
  'gov', 'edu', 'mil', 'bank', 'insurance'
];

const PUBLIC_SUFFIXES = [
  'ac.in', 'bank.in', 'co.in', 'com.au', 'com.ro', 'co.nz', 'co.uk',
  'edu.in', 'fin.in', 'gov.in', 'mil.in', 'net.in', 'nic.in',
  'org.in', 'org.uk', 'res.in', 'ac.uk', 'bank', 'edu', 'gov',
  'insurance', 'mil', 'com', 'net', 'org', 'xyz', 'top', 'click',
  'loan', 'rest', 'cam', 'icu', 'sbs', 'ro', 'in', 'uk', 'au', 'nz'
];

const TRUSTED_BRANDS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm'
];

const OFFICIAL_BRAND_DOMAINS: Record<string, string[]> = {
  google: ['google.com'],
  paypal: ['paypal.com'],
  sbi: ['sbi.co.in', 'sbi.bank.in'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  axis: ['axisbank.com'],
  kotak: ['kotak.com', 'kotakbank.com'],
  paytm: ['paytm.com']
};

const normalizeLabel = (value: string): string => value.toLowerCase().replace(/[^a-z0-9]/g, '');

const getSuffixMatch = (hostname: string): string | null => {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const matches = PUBLIC_SUFFIXES.filter((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  if (matches.length === 0) return null;
  return matches.sort((a, b) => b.length - a.length)[0] ?? null;
};

export function getRegisteredDomain(hostname: string): string {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const labels = lower.split('.').filter(Boolean);
  if (labels.length <= 2) {
    return labels.join('.');
  }

  const suffix = getSuffixMatch(lower);
  if (!suffix) {
    return labels.slice(-2).join('.');
  }

  const suffixLabels = suffix.split('.');
  if (labels.length <= suffixLabels.length) {
    return labels.join('.');
  }

  return labels.slice(-(suffixLabels.length + 1)).join('.');
}

export function getSubdomainDepth(hostname: string, registeredDomain: string): number {
  if (!hostname || !registeredDomain || hostname === registeredDomain) return 0;
  const suffix = `.${registeredDomain}`;
  if (!hostname.endsWith(suffix)) return 0;
  const subdomain = hostname.slice(0, -suffix.length);
  return subdomain ? subdomain.split('.').filter(Boolean).length : 0;
}

const findBrandMention = (value: string): string | undefined => {
  const normalizedValue = normalizeLabel(value);
  return TRUSTED_BRANDS.find((brand) => normalizedValue.includes(brand));
};

const isOfficialBrandDomain = (registeredDomain: string, brand: string): boolean => {
  const allowedDomains = OFFICIAL_BRAND_DOMAINS[brand] ?? [];
  return allowedDomains.some((domain) => registeredDomain === domain || registeredDomain.endsWith(`.${domain}`));
};

function computeTrustScore(intel: Omit<DomainIntelligence, 'trustScore' | 'positives' | 'warnings'>): number {
  let score = 45;

  if (intel.isOfficialTLD) score += 35;
  if (intel.isHTTPS) score += 10;
  if (intel.officialTld === 'bank' || intel.officialTld === 'bank.in') score += 10;
  if (intel.hasIPHostname) score -= 55;
  if (intel.subdomainDepth > 3) score -= 10;
  if (intel.subdomainDepth > 5) score -= 15;
  if (intel.hasSubdomainSpoofing) score -= 35;
  if (intel.impersonatedBrand) score -= 20;
  if (intel.homoglyph.hasHomoglyphRisk) score -= Math.min(30, intel.homoglyph.score);

  return Math.min(100, Math.max(0, score));
}

export function analyzeDomain(rawUrl: string): DomainIntelligence {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const isHTTPS = parsed.protocol === 'https:';
    const hasIPHostname = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const registeredDomain = getRegisteredDomain(hostname);
    const registeredLabel = registeredDomain.split('.')[0] ?? registeredDomain;
    const suffix = getSuffixMatch(hostname) ?? '';
    const officialTld = OFFICIAL_TLDS.find((item) => hostname === item || hostname.endsWith(`.${item}`));
    const isOfficialTLD = !hasIPHostname && !!officialTld;
    const subdomainDepth = getSubdomainDepth(hostname, registeredDomain);
    const homoglyph = analyzeHomoglyphs(hostname);

    const subdomainPart = hostname === registeredDomain ? '' : hostname.slice(0, -(registeredDomain.length + 1));
    const brandInSubdomain = subdomainPart ? findBrandMention(subdomainPart) : undefined;
    const labelBrand = findBrandMention(registeredLabel);
    const impersonatedBrand = labelBrand && !isOfficialBrandDomain(registeredDomain, labelBrand) ? labelBrand : undefined;
    const hasSubdomainSpoofing = Boolean(
      brandInSubdomain &&
      !isOfficialBrandDomain(registeredDomain, brandInSubdomain) &&
      subdomainPart.includes('.')
    );

    const partial = {
      hostname,
      decodedHostname: homoglyph.decodedHostname,
      registeredDomain,
      registeredLabel,
      isOfficialTLD,
      officialTld: officialTld ?? undefined,
      isHTTPS,
      hasIPHostname,
      subdomainDepth,
      hasSubdomainSpoofing,
      impersonatedBrand,
      brandInSubdomain,
      homoglyph
    };

    const positives: string[] = [];
    const warnings: string[] = [];

    if (isOfficialTLD) {
      positives.push('Verified domain');
      positives.push(`Trusted TLD (.${officialTld})`);
    }
    if (isHTTPS) positives.push('Secure HTTPS connection');
    if (hasSubdomainSpoofing) warnings.push('Suspicious domain structure');
    if (impersonatedBrand) warnings.push('Possible impersonation');
    if (homoglyph.hasPunycode) warnings.push('Punycode domain detected');
    if (homoglyph.hasHomoglyphRisk) warnings.push('Homoglyph attack indicators');

    return {
      ...partial,
      trustScore: computeTrustScore(partial),
      positives,
      warnings
    };
  } catch {
    return {
      hostname: rawUrl,
      decodedHostname: rawUrl,
      registeredDomain: rawUrl,
      registeredLabel: rawUrl,
      isOfficialTLD: false,
      isHTTPS: false,
      hasIPHostname: false,
      subdomainDepth: 0,
      trustScore: 0,
      hasSubdomainSpoofing: false,
      homoglyph: {
        decodedHostname: rawUrl,
        hasPunycode: false,
        hasMixedScript: false,
        hasHomoglyphRisk: false,
        skeleton: rawUrl,
        score: 0,
        indicators: []
      },
      positives: [],
      warnings: ['Unable to parse domain']
    };
  }
}
