import type { SignalMap, RiskLevel } from '../types'

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan', '.work', '.party', '.review', '.accountant']
const PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'password', 'credential', 'suspend', 'confirm', 'wallet', 'crypto']
const TRUSTED_DOMAINS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {}
  for (const c of str) freq[c] = (freq[c] || 0) + 1
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / str.length
    return sum + p * Math.log2(p)
  }, 0)
}

function levenshtein(a: string, b: string): number {
  const m = a.length
  const n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0))
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

function getHostnameParts(hostname: string) {
  const normalized = hostname.toLowerCase().replace(/^www\./, '')
  const baseLabel = normalized.split('.')[0]
  const tokens = baseLabel.split(/[^a-z0-9]+/).filter(Boolean)
  return { normalized, baseLabel, tokens }
}

function isTrustedHostname(hostname: string): boolean {
  const { normalized } = getHostnameParts(hostname)
  return TRUSTED_DOMAINS.some((trusted) => normalized === trusted || normalized === `${trusted}.com` || normalized.endsWith(`.${trusted}.com`))
}

function normalizeLookalikes(str: string): string {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/@/g, 'a')
}

function checkTyposquat(hostname: string): number {
  const { baseLabel, tokens } = getHostnameParts(hostname)
  const candidates = [baseLabel, normalizeLookalikes(baseLabel), ...tokens, ...tokens.map(normalizeLookalikes)]

  for (const trusted of TRUSTED_DOMAINS) {
    for (const candidate of candidates) {
      if (!candidate || candidate === trusted) continue
      if (candidate.includes(trusted)) return 30
      if (levenshtein(candidate, trusted) <= 2) return 25
    }
  }

  return 0
}

function checkTLD(hostname: string): number {
  return SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld)) ? 15 : 0
}

function checkKeywords(url: string, hostname: string): number {
  if (isTrustedHostname(hostname)) return 0
  const lower = url.toLowerCase()
  const matches = PHISHING_KEYWORDS.filter(k => lower.includes(k)).length
  return Math.min(20, matches * 5)
}

function checkBrandKeywordCombo(hostname: string, url: string): number {
  if (isTrustedHostname(hostname)) return 0
  const lowerUrl = url.toLowerCase()
  const hasBrand = TRUSTED_DOMAINS.some((trusted) => lowerUrl.includes(trusted))
  const hasAction = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'confirm', 'update'].some((keyword) => lowerUrl.includes(keyword))
  return hasBrand && hasAction ? 20 : 0
}

function checkPort(port: string): number {
  if (!port) return 0
  const p = parseInt(port, 10)
  return [80, 443, 8080, 8443].includes(p) ? 0 : 10
}

export interface ScoreResult {
  score: number
  signals: SignalMap & { brandKeywordCombo?: number }
  riskLevel: RiskLevel
}

export function scoreUrl(rawUrl: string): ScoreResult {
  let u: URL
  try {
    u = new URL(rawUrl)
  } catch {
    return { score: 0, signals: {} as ScoreResult['signals'], riskLevel: 'LOW' }
  }

  const signals: ScoreResult['signals'] = {
    typosquatScore: checkTyposquat(u.hostname),
    suspiciousTLD: checkTLD(u.hostname),
    ipAsHostname: /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) ? 20 : 0,
    longSubdomains: u.hostname.split('.').length > 4 ? 10 : 0,
    suspiciousKeywords: checkKeywords(u.href, u.hostname),
    encodedChars: (u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0,
    pathEntropy: shannonEntropy(u.pathname) > 4.5 ? 10 : 0,
    portAnomaly: checkPort(u.port),
    brandKeywordCombo: checkBrandKeywordCombo(u.hostname, u.href),
  }

  const score = Math.min(100, Object.values(signals).reduce((a, b) => a + (b || 0), 0))
  const riskLevel: RiskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW'

  return { score, signals, riskLevel }
}
