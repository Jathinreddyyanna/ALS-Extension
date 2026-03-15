type SignalMap = Record<string, number>
type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type UrlSignals = {
  typosquatScore: number
  suspiciousTLD: number
  ipAsHostname: number
  longSubdomains: number
  suspiciousKeywords: number
  encodedChars: number
  pathEntropy: number
  portAnomaly: number
}

export type UrlScoreResult = {
  score: number
  signals: SignalMap
  riskLevel: RiskLevel
}

const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq',
  '.xyz', '.top', '.click', '.loan', '.work',
  '.party', '.review', '.accountant',
  '.rest', '.zip', '.mov', '.phd', '.prof',
  '.cam', '.cfd', '.cyou', '.icu', '.sbs',
  '.monster', '.bar', '.fin', '.bond',
]

const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'account', 'update',
  'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
  'netflix', 'password', 'credential', 'suspend', 'confirm',
  'wallet', 'crypto', 'filmyzilla', 'piracy', 'torrent', 'movies',
]

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
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

const TRUSTED_DOMAINS = [
  'google', 'facebook', 'amazon', 'apple', 'microsoft',
  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin',
]

function checkTyposquat(hostname: string): number {
  const clean = hostname.replace(/^www\./, '').split('.')[0]
  for (const trusted of TRUSTED_DOMAINS) {
    if (clean !== trusted && levenshtein(clean, trusted) <= 2) return 25
  }
  return 0
}

function checkTLD(hostname: string): number {
  return SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld)) ? 15 : 0
}

function checkKeywords(url: string): number {
  const lower = url.toLowerCase()
  const matches = PHISHING_KEYWORDS.filter((keyword) => lower.includes(keyword)).length
  return Math.min(15, matches * 5)
}

function checkPort(port: string): number {
  if (!port) return 0
  const parsed = parseInt(port, 10)
  return [80, 443, 8080, 8443].includes(parsed) ? 0 : 10
}

export function scoreUrl(rawUrl: string): UrlScoreResult {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(rawUrl)
  } catch {
    return {
      score: 0,
      signals: {} as SignalMap,
      riskLevel: 'LOW',
    }
  }

  const signals: SignalMap = {
    typosquatScore: checkTyposquat(parsedUrl.hostname),
    suspiciousTLD: checkTLD(parsedUrl.hostname),
    ipAsHostname: /^\d{1,3}(\.\d{1,3}){3}$/.test(parsedUrl.hostname) ? 20 : 0,
    longSubdomains: parsedUrl.hostname.split('.').length > 4 ? 10 : 0,
    suspiciousKeywords: checkKeywords(parsedUrl.href),
    encodedChars: (parsedUrl.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0,
    pathEntropy: shannonEntropy(parsedUrl.pathname) > 4.5 ? 10 : 0,
    portAnomaly: checkPort(parsedUrl.port),
  }

  const score = Math.min(100, Object.values(signals).reduce((a, b) => a + b, 0))
  const riskLevel: RiskLevel =
    score >= 75 ? 'CRITICAL'
    : score >= 50 ? 'HIGH'
    : score >= 30 ? 'MEDIUM'
    : 'LOW'

  return { score, signals, riskLevel }
}
