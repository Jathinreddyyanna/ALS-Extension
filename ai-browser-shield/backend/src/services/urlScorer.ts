const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan', '.work', '.party', '.review', '.accountant']
const PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'password', 'credential', 'suspend', 'confirm', 'wallet', 'crypto']

function shannonEntropy(str: string): number {
  if (!str) return 0
  const freq: Record<string, number> = {}
  for (const c of str) freq[c] = (freq[c] || 0) + 1
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / str.length
    return sum + p * Math.log2(p)
  }, 0)
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0))
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
  return dp[m][n]
}

const TRUSTED_DOMAINS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']

function checkTyposquat(hostname: string): number {
  const clean = hostname.replace(/^www\./, '').split('.')[0]
  for (const trusted of TRUSTED_DOMAINS) {
    if (clean !== trusted && levenshtein(clean, trusted) <= 2) return 25
  }
  return 0
}

function checkTLD(hostname: string): number {
  return SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld)) ? 20 : 0
}

function checkKeywords(url: string): number {
  const lower = url.toLowerCase()
  const matches = PHISHING_KEYWORDS.filter(k => lower.includes(k)).length
  return Math.min(30, matches * 6)
}

function checkPort(port: string): number {
  if (!port) return 0
  const p = parseInt(port)
  return [80, 443, 8080, 8443].includes(p) ? 0 : 10
}

export interface ScoreResult {
  score: number
  signals: Record<string, number>
}

export function scoreUrl(rawUrl: string): ScoreResult {
  let u: URL
  try { u = new URL(rawUrl) } catch { return { score: 0, signals: {} } }

  const signals = {
    typosquatScore:     checkTyposquat(u.hostname),
    suspiciousTLD:      checkTLD(u.hostname),
    ipAsHostname:       /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) ? 20 : 0,
    longSubdomains:     u.hostname.split('.').length > 4 ? 10 : 0,
    suspiciousKeywords: checkKeywords(u.href),
    encodedChars:       (u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0,
    pathEntropy:        shannonEntropy(u.pathname) > 4.5 ? 10 : 0,
    portAnomaly:        checkPort(u.port),
  }

  let score = Math.min(100, Object.values(signals).reduce((a, b) => a + b, 0))

  if (signals.suspiciousTLD > 0 && signals.suspiciousKeywords >= 12) score += 20
  if (signals.typosquatScore > 0 && signals.suspiciousKeywords >= 6) score += 15
  if (signals.ipAsHostname > 0 && signals.suspiciousKeywords >= 6) score += 10
  score = Math.min(100, score)

  return { score, signals }
}
