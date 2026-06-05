import type { SignalMap, RiskLevel } from '../types'

const SUSPICIOUS_TLDS = [
  '.digital', '.trade', '.online', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
  '.top', '.click', '.rest', '.zip', '.icu', '.sbs',
]

const OFFICIAL_TLDS = [
  '.gov.in', '.nic.in', '.bank.in', '.fin.in', '.edu.in', '.ac.in', '.res.in', '.mil.in',
  '.gov', '.edu', '.mil', '.bank', '.insurance',
]

const BRAND_KEYWORDS = ['trezor', 'ledger', 'metamask', 'coinbase', 'paypal', 'google', 'amazon', 'microsoft', 'apple']
const OFFICIAL_BRAND_DOMAINS = ['trezor.io', 'ledger.com', 'metamask.io', 'coinbase.com']
const FREE_HOSTING_DOMAINS = ['pages.dev', 'herokuapp.com', 'netlify.app', 'vercel.app']
const TYPOSQUAT_TARGETS = ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'coinbase', 'metamask', 'trezor', 'ledger']
const SUSPICIOUS_CONTENT_HINTS = ['login', 'signin', 'verify', 'secure', 'wallet', 'seed', 'recovery', 'class.php', 'login.php']

export interface ScoreResult {
  score: number
  signals: SignalMap
  riskLevel: RiskLevel
}

const EMPTY_SIGNALS: SignalMap = {
  typosquatScore: 0,
  suspiciousTLD: 0,
  ipAsHostname: 0,
  longSubdomains: 0,
  suspiciousKeywords: 0,
  encodedChars: 0,
  pathEntropy: 0,
  portAnomaly: 0,
}

function isOfficialDomain(hostname: string): boolean {
  const clean = hostname.replace(/^www\./, '').toLowerCase()
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return false
  return OFFICIAL_TLDS.some((tld) => clean.endsWith(tld))
}

function shannonEntropy(str: string): number {
  if (!str) return 0
  const freq: Record<string, number> = {}
  for (const char of str) freq[char] = (freq[char] || 0) + 1
  return -Object.values(freq).reduce((sum, count) => {
    const probability = count / str.length
    return sum + probability * Math.log2(probability)
  }, 0)
}

function levenshtein(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, (_, row) =>
    Array.from({ length: b.length + 1 }, (_, col) => (row === 0 ? col : col === 0 ? row : 0))
  )

  for (let row = 1; row <= a.length; row += 1) {
    for (let col = 1; col <= b.length; col += 1) {
      matrix[row][col] = a[row - 1] === b[col - 1]
        ? matrix[row - 1][col - 1]
        : 1 + Math.min(matrix[row - 1][col], matrix[row][col - 1], matrix[row - 1][col - 1])
    }
  }

  return matrix[a.length][b.length]
}

function hasBase64Redirect(url: URL): boolean {
  for (const [, rawValue] of url.searchParams.entries()) {
    const value = rawValue.trim()
    if (value.length < 4) continue
    if (!/^[A-Za-z0-9+/_=-]+$/.test(value)) continue

    try {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
      const decoded = atob(padded).trim()
      if (/^https?:\/\//i.test(decoded)) {
        return true
      }
    } catch {
      // Ignore invalid Base64 candidates.
    }
  }

  return false
}

function looksLikeGibberishSubdomain(hostname: string): boolean {
  const labels = hostname.replace(/^www\./, '').split('.')
  const subdomain = labels[0] ?? ''
  if (subdomain.length < 8 || /^\d+$/.test(subdomain)) return false
  const vowels = (subdomain.match(/[aeiou]/gi) || []).length
  const entropy = shannonEntropy(subdomain)
  return entropy > 3.2 && vowels <= 2
}

function isTyposquat(hostname: string): boolean {
  const label = hostname.replace(/^www\./, '').split('.')[0]?.toLowerCase() ?? ''
  if (!label) return false

  return TYPOSQUAT_TARGETS.some((target) => {
    if (label === target) return false
    return levenshtein(label, target) <= 2
  })
}

function scoreSuspiciousKeywords(rawUrl: string): number {
  const lower = rawUrl.toLowerCase()
  const matches = SUSPICIOUS_CONTENT_HINTS.filter((keyword) => lower.includes(keyword)).length
  return Math.min(20, matches * 5)
}

function isOfficialBrandHost(hostname: string): boolean {
  const clean = hostname.replace(/^www\./, '').toLowerCase()
  return OFFICIAL_BRAND_DOMAINS.some((domain) => clean === domain || clean.endsWith(`.${domain}`))
}

export function scoreUrl(rawUrl: string): ScoreResult {
  try {
    const parsedUrl = new URL(rawUrl)
    const hostname = parsedUrl.hostname.toLowerCase()

    if (isOfficialDomain(hostname)) {
      return {
        score: 0,
        signals: EMPTY_SIGNALS,
        riskLevel: 'LOW',
      }
    }

    let total = 0

    const signals: SignalMap = {
      ...EMPTY_SIGNALS,
      typosquatScore: isTyposquat(hostname) ? 50 : 0,
      suspiciousTLD: SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld)) ? 25 : 0,
      ipAsHostname: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 50 : 0,
      longSubdomains: hostname.split('.').length >= 5 ? 30 : 0,
      suspiciousKeywords: scoreSuspiciousKeywords(parsedUrl.href),
      encodedChars: (parsedUrl.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 15 : 0,
      pathEntropy: shannonEntropy(parsedUrl.pathname) > 4.5 ? 10 : 0,
      portAnomaly: parsedUrl.port && !['80', '443', '8080', '8443'].includes(parsedUrl.port) ? 10 : 0,
    }

    total += signals.typosquatScore
    total += signals.suspiciousTLD
    total += signals.ipAsHostname
    total += signals.longSubdomains
    total += signals.suspiciousKeywords
    total += signals.encodedChars
    total += signals.pathEntropy
    total += signals.portAnomaly

    if (looksLikeGibberishSubdomain(hostname)) {
      total += 40
    }

    if (hostname.includes('xn--')) {
      total += 45
    }

    if (/\/(?:login|class)\.php(?:[/?#]|$)/i.test(parsedUrl.pathname)) {
      total += 35
    }

    if (hasBase64Redirect(parsedUrl)) {
      total += 40
    }

    if (BRAND_KEYWORDS.some((brand) => parsedUrl.href.toLowerCase().includes(brand)) && !isOfficialBrandHost(hostname)) {
      const cryptoBrand = ['trezor', 'ledger', 'metamask', 'coinbase'].some((brand) => parsedUrl.href.toLowerCase().includes(brand))
      total += cryptoBrand ? 55 : 20
    }

    if (FREE_HOSTING_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) {
      const suspiciousContent = SUSPICIOUS_CONTENT_HINTS.some((keyword) => parsedUrl.href.toLowerCase().includes(keyword))
      if (suspiciousContent) {
        total += 35
      }
    }

    if (parsedUrl.protocol !== 'https:') {
      total += 30
    }

    const score = Math.min(100, total)
    const riskLevel: RiskLevel =
      score >= 75 ? 'CRITICAL'
        : score >= 50 ? 'HIGH'
          : score >= 30 ? 'MEDIUM'
            : 'LOW'

    return { score, signals, riskLevel }
  } catch {
    return {
      score: 0,
      signals: EMPTY_SIGNALS,
      riskLevel: 'LOW',
    }
  }
}
