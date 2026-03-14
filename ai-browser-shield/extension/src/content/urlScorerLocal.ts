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
  const m = a.length, n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0))
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
  return dp[m][n]
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
  const clean = normalizeToken(hostname.split('.')[0])
  for (const trusted of TRUSTED_DOMAINS) {
    if (clean !== trusted && levenshtein(clean, trusted) <= 2) return 25
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

function checkKeywords(url: string): number {
  const lower = url.toLowerCase()
  const matches = PHISHING_KEYWORDS.filter(k => lower.includes(k)).length
  let score = Math.min(15, matches * 5)

  const hostname = (() => { try { return new URL(url).hostname.toLowerCase() } catch { return '' } })()
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

function checkPort(port: string): number {
  if (!port) return 0
  const p = parseInt(port)
  return [80, 443, 8080, 8443].includes(p) ? 0 : 10
}

export function scoreUrlLocal(rawUrl: string): { score: number; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
  let u: URL
  try { u = new URL(rawUrl) } catch { return { score: 0, riskLevel: 'LOW' } }

  const score = Math.min(100, [
    checkTyposquat(u.hostname) + checkBrandAbuse(u.hostname),
    checkTLD(u.hostname),
    /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) ? 20 : 0,
    u.hostname.split('.').length > 4 ? 10 : 0,
    checkKeywords(u.href),
    (u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0,
    shannonEntropy(u.pathname) > 4.5 ? 10 : 0,
    checkPort(u.port),
  ].reduce((a, b) => a + b, 0))

  const riskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW'
  return { score, riskLevel }
}
