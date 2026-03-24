import { domainToUnicode } from 'node:url';

const latinPattern = /[a-z]/u;
const cyrillicPattern = /[\u0400-\u04FF]/u;
const greekPattern = /[\u0370-\u03FF]/u;

const CONFUSABLE_MAP: Record<string, string> = {
  '0': 'o',
  '1': 'l',
  'i': 'l',
  'l': 'l',
  '3': 'e',
  '5': 's',
  '8': 'b',
  '@': 'a',
  '$': 's',
  '!': 'i',
  '|': 'l',
  'а': 'a',
  'е': 'e',
  'о': 'o',
  'р': 'p',
  'с': 'c',
  'у': 'y',
  'х': 'x',
  'і': 'i',
  'ј': 'j',
  'ԁ': 'd',
  'ԛ': 'q',
  'Ι': 'i',
  'Ο': 'o',
  'Α': 'a',
  'Β': 'b',
  'Ε': 'e',
  'Η': 'h',
  'Κ': 'k',
  'Μ': 'm',
  'Ν': 'n',
  'Ρ': 'p',
  'Τ': 't',
  'Χ': 'x'
};

const TRUSTED_BRANDS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm'
];

export interface HomoglyphAnalysis {
  decodedHostname: string;
  hasPunycode: boolean;
  hasMixedScript: boolean;
  hasHomoglyphRisk: boolean;
  skeleton: string;
  matchedBrand?: string;
  score: number;
  indicators: string[];
}

const toSkeleton = (value: string): string => value
  .normalize('NFKC')
  .toLowerCase()
  .split('')
  .map((char) => CONFUSABLE_MAP[char] ?? char)
  .join('');

const getRootLabel = (hostname: string): string => hostname.replace(/^www\./, '').split('.')[0] ?? '';

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

export const hasMixedScriptHostname = (hostname: string): boolean => {
  const value = hostname.normalize('NFKC');
  const hasLatin = latinPattern.test(value);
  const hasCyrillic = cyrillicPattern.test(value);
  const hasGreek = greekPattern.test(value);
  return Number(hasLatin) + Number(hasCyrillic) + Number(hasGreek) > 1;
};

export function analyzeHomoglyphs(hostname: string): HomoglyphAnalysis {
  const decodedHostname = domainToUnicode(hostname.toLowerCase());
  const hasPunycode = hostname.toLowerCase().includes('xn--');
  const hasMixedScript = hasMixedScriptHostname(decodedHostname);
  const rootLabel = getRootLabel(decodedHostname);
  const skeleton = toSkeleton(rootLabel);

  let matchedBrand: string | undefined;
  for (const brand of TRUSTED_BRANDS) {
    if (rootLabel === brand) continue;
    const brandSkeleton = toSkeleton(brand);
    if (skeleton === brandSkeleton || levenshtein(skeleton, brandSkeleton) === 1) {
      matchedBrand = brand;
      break;
    }
  }

  const indicators: string[] = [];
  if (hasPunycode) indicators.push('punycode_domain');
  if (hasMixedScript) indicators.push('mixed_script_hostname');
  if (matchedBrand) indicators.push(`homoglyph_brand:${matchedBrand}`);

  const score =
    (hasPunycode ? 18 : 0) +
    (hasMixedScript ? 22 : 0) +
    (matchedBrand ? 30 : 0);

  return {
    decodedHostname,
    hasPunycode,
    hasMixedScript,
    hasHomoglyphRisk: score > 0,
    skeleton,
    matchedBrand,
    score: Math.min(50, score),
    indicators
  };
}
