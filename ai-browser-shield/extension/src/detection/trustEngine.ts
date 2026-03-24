import { scoreUrl } from './urlScorer'
import type { TrustResult, VaultEntry } from '../types/vault'

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }

  return dp[m][n]
}

export function extractRootDomain(input: string): string {
  try {
    const url = input.startsWith('http') ? input : `https://${input}`
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase()
  } catch {
    return input.toLowerCase()
  }
}

function similarity(a: string, b: string): number {
  const max = Math.max(a.length, b.length)
  return max === 0 ? 1 : 1 - levenshtein(a, b) / max
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click',
  'loan', 'rest', 'cam', 'icu', 'sbs', 'cyou', 'buzz', 'pw',
])

const DIGIT_SUBS: [string, string][] = [
  ['0', 'o'],
  ['1', 'i'],
  ['1', 'l'],
  ['3', 'e'],
  ['4', 'a'],
  ['5', 's'],
  ['@', 'a'],
  ['$', 's'],
]

function hasDigitSub(domain: string): boolean {
  return DIGIT_SUBS.some(([from, to]) =>
    domain.includes(from) && domain.replaceAll(from, to) !== domain
  )
}

export function evaluateTrust(
  currentUrl: string,
  entries: VaultEntry[]
): TrustResult {
  const domain = extractRootDomain(currentUrl)
  const tld = domain.split('.').pop() ?? ''
  const httpsPresent = currentUrl.startsWith('https://')
  const patterns: string[] = []
  const reasons: string[] = []

  if (!httpsPresent) reasons.push('Site does not use HTTPS - credentials at risk')

  if (SUSPICIOUS_TLDS.has(tld)) {
    patterns.push('suspicious_tld')
    reasons.push(`High-risk domain extension: .${tld}`)
  }

  if (hasDigitSub(domain)) {
    patterns.push('digit_substitution')
    reasons.push('Domain uses character substitution - classic phishing pattern')
  }

  if (domain.split('.').length > 4) {
    patterns.push('deep_subdomain')
    reasons.push('Abnormally deep subdomain nesting')
  }

  if (domain.length > 40) {
    patterns.push('long_domain')
    reasons.push('Unusually long domain name')
  }

  const aiScore = scoreUrl(currentUrl)
  if (aiScore.score >= 40) {
    patterns.push('ai_shield_risk')
    reasons.push(`AI Shield URL risk: ${aiScore.score}/100`)
  }

  let bestMatch: VaultEntry | undefined
  let bestSim = 0
  let isExact = false

  for (const entry of entries) {
    const entryDomain = extractRootDomain(entry.domain)
    if (entryDomain === domain) {
      isExact = true
      bestMatch = entry
      bestSim = 1
      break
    }

    const sim = similarity(entryDomain, domain)
    if (sim > bestSim) {
      bestSim = sim
      bestMatch = entry
    }
  }

  if (!isExact && bestSim > 0.75 && bestMatch) {
    patterns.push('lookalike_domain')
    reasons.push(
      `Looks like ${extractRootDomain(bestMatch.domain)} - possible lookalike (${Math.round(bestSim * 100)}% similar)`
    )
  }

  let score = 100
  if (!httpsPresent) score -= 25
  if (patterns.includes('suspicious_tld')) score -= 30
  if (patterns.includes('digit_substitution')) score -= 35
  if (patterns.includes('lookalike_domain')) score -= 30
  if (patterns.includes('deep_subdomain')) score -= 15
  if (patterns.includes('long_domain')) score -= 10
  if (aiScore.score >= 40) score -= 20
  if (aiScore.score >= 70) score -= 15
  score = Math.max(0, Math.min(100, score))

  const level: TrustResult['level'] =
    score >= 80 ? 'safe'
    : score >= 55 ? 'caution'
    : score >= 30 ? 'danger'
    : 'blocked'

  return {
    score,
    level,
    reasons,
    matchedEntry: bestMatch,
    isExactMatch: isExact,
    similarityScore: bestSim,
    httpsPresent,
    suspiciousPatterns: patterns,
    autofillAllowed: isExact && score >= 80 && httpsPresent,
  }
}
