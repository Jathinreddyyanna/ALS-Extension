import type { SignalMap, RiskLevel } from '../types'

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan', '.work', '.party', '.review', '.accountant']
const PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'password', 'credential', 'suspend', 'confirm', 'wallet', 'crypto']
const TRUSTED_DOMAINS = ['google', 'gmail', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']

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

const GOOGLE_TRUSTED_HOSTS = [
  'google.com',
  'gmail.com',
  'mail.google.com',
  'accounts.google.com',
  'classroom.google.com',
  'notifications.google.com',
  'googleusercontent.com',
  'gstatic.com',
]

function isGoogleOwnedHostnameStrict(hostname: string): boolean {
  const normalized = hostname.toLowerCase()
  return GOOGLE_TRUSTED_HOSTS.some(domain => normalized === domain || normalized.endsWith(`.${domain}`))
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

function normalizeToken(value: string): string {
  return value
    .toLowerCase()
    .replace(/^www\./, '')
    .replace(/[0-9]/g, (digit) => ({ '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't' }[digit] || digit))
    .replace(/[^a-z]/g, '')
}

function getHostnameTokens(hostname: string): string[] {
  return hostname
    .replace(/^www\./, '')
    .split('.')[0]
    .split(/[^a-z0-9]+/i)
    .map(normalizeToken)
    .filter(Boolean)
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

function checkBrandAbuse(hostname: string): number {
  const clean = hostname.replace(/^www\./, '').toLowerCase()
  const root = clean.split('.')[0]
  const normalizedRoot = normalizeToken(root)
  const tokens = getHostnameTokens(hostname)
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => clean.endsWith(tld))

  for (const trusted of TRUSTED_DOMAINS) {
    const tokenLooksLikeBrand = tokens.some(token => token.includes(trusted) || levenshtein(token, trusted) <= 2)
    const mentionsBrand = root.includes(trusted) || normalizedRoot.includes(trusted) || tokenLooksLikeBrand
    const isExactTrustedDomain = clean === `${trusted}.com` || clean === `www.${trusted}.com`

    if (!mentionsBrand || isExactTrustedDomain) continue

    if (hasSuspiciousTLD) return 35
    if (root !== trusted) return 20
  }

  return 0
}

function checkKeywords(url: string, hostname: string): number {
  if (isTrustedHostname(hostname)) return 0

  const lower = url.toLowerCase()
  const matches = PHISHING_KEYWORDS.filter(k => lower.includes(k)).length
  let score = Math.min(15, matches * 5)

  const root = hostname.replace(/^www\./, '').split('.')[0]
  const normalizedRoot = normalizeToken(root)
  const tokens = getHostnameTokens(hostname)
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))
  const phishingWords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'password', 'credential', 'confirm', 'wallet']
  const brandMention = TRUSTED_DOMAINS.some(domain =>
    root.includes(domain) ||
    normalizedRoot.includes(domain) ||
    tokens.some(token => token.includes(domain) || levenshtein(token, domain) <= 2)
  )
  const phishingWordMention = phishingWords.some(word => lower.includes(word))

  if (brandMention && phishingWordMention) score += 10
  if (brandMention && hasSuspiciousTLD) score += 10

  return Math.min(30, score)
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

function checkLongUrl(url: string): number {
  if (url.length >= 180) return 15
  if (url.length >= 120) return 10
  if (url.length >= 90) return 5
  return 0
}

function checkManyDots(hostname: string): number {
  const dotCount = (hostname.match(/\./g) || []).length
  if (dotCount >= 4) return 10
  if (dotCount === 3) return 5
  return 0
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

  if (isGoogleOwnedHostnameStrict(u.hostname)) {
    const safeSignals: ScoreResult['signals'] = {
      typosquatScore: 0,
      suspiciousTLD: 0,
      ipAsHostname: 0,
      longSubdomains: 0,
      longUrl: 0,
      manyDots: 0,
      suspiciousKeywords: 0,
      encodedChars: 0,
      pathEntropy: 0,
      portAnomaly: 0,
      punycode: 0,
      atSymbol: 0,
      suspiciousLength: 0,
      brandKeywordCombo: 0,
    }
    return { score: 5, signals: safeSignals, riskLevel: 'LOW' }
  }

  const signals: ScoreResult['signals'] = {
    typosquatScore: checkTyposquat(u.hostname) + checkBrandAbuse(u.hostname),
    suspiciousTLD: checkTLD(u.hostname),
    ipAsHostname: /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) ? 20 : 0,
    longSubdomains: u.hostname.split('.').length > 4 ? 10 : 0,
    longUrl: checkLongUrl(u.href),
    manyDots: checkManyDots(u.hostname),
    suspiciousKeywords: checkKeywords(u.href, u.hostname),
    encodedChars: (u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0,
    pathEntropy: shannonEntropy(u.pathname) > 4.5 ? 10 : 0,
    portAnomaly: checkPort(u.port),
    punycode: u.hostname.includes('xn--') ? 20 : 0,
    atSymbol: u.href.includes('@') ? 15 : 0,
    suspiciousLength: u.hostname.replace(/^www\./, '').split('.')[0].length >= 25 ? 10 : 0,
    brandKeywordCombo: checkBrandKeywordCombo(u.hostname, u.href),
  }

  const score = Math.min(100, Object.values(signals).reduce((a, b) => a + (b || 0), 0))
  const riskLevel: RiskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW'

  return { score, signals, riskLevel }
}
