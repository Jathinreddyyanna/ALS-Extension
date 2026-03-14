// Hover preview keeps URL scoring local so the content script stays self-contained.
const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.loan', '.work', '.party', '.review', '.accountant']
const PHISHING_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'password', 'credential', 'suspend', 'confirm', 'wallet', 'crypto']
const TRUSTED_DOMAINS = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']

const RISK_COLORS: Record<string, { bg: string; text: string; emoji: string }> = {
  CRITICAL: { bg: '#450A0A', text: '#FCA5A5', emoji: 'ALERT' },
  HIGH: { bg: '#431407', text: '#FED7AA', emoji: 'WARN' },
  MEDIUM: { bg: '#422006', text: '#FEF08A', emoji: 'RISK' },
  LOW: { bg: '#052E16', text: '#86EFAC', emoji: 'SAFE' },
}

let tooltip: HTMLElement | null = null

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

function scoreUrl(rawUrl: string) {
  let u: URL
  try {
    u = new URL(rawUrl)
  } catch {
    return { score: 0, riskLevel: 'LOW' as const }
  }

  const { baseLabel, tokens } = getHostnameParts(u.hostname)
  const candidates = [baseLabel, normalizeLookalikes(baseLabel), ...tokens, ...tokens.map(normalizeLookalikes)]
  const typosquatScore = TRUSTED_DOMAINS.some((trusted) => candidates.some((candidate) => candidate && candidate !== trusted && (candidate.includes(trusted) || levenshtein(candidate, trusted) <= 2))) ? 30 : 0
  const suspiciousTLD = SUSPICIOUS_TLDS.some((tld) => u.hostname.endsWith(tld)) ? 15 : 0
  const lowerUrl = u.href.toLowerCase()
  const suspiciousKeywords = isTrustedHostname(u.hostname) ? 0 : Math.min(20, PHISHING_KEYWORDS.filter((keyword) => lowerUrl.includes(keyword)).length * 5)
  const brandKeywordCombo = !isTrustedHostname(u.hostname) && TRUSTED_DOMAINS.some((trusted) => lowerUrl.includes(trusted)) && ['login', 'signin', 'verify', 'secure', 'account', 'password', 'confirm', 'update'].some((keyword) => lowerUrl.includes(keyword)) ? 20 : 0
  const encodedChars = (u.href.match(/%[0-9a-f]{2}/gi) || []).length > 3 ? 10 : 0
  const pathEntropy = shannonEntropy(u.pathname) > 4.5 ? 10 : 0
  const portAnomaly = u.port && ![80, 443, 8080, 8443].includes(parseInt(u.port, 10)) ? 10 : 0
  const ipAsHostname = /^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname) ? 20 : 0
  const longSubdomains = u.hostname.split('.').length > 4 ? 10 : 0

  const score = Math.min(100, typosquatScore + suspiciousTLD + suspiciousKeywords + brandKeywordCombo + encodedChars + pathEntropy + portAnomaly + ipAsHostname + longSubdomains)
  const riskLevel = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW'

  return { score, riskLevel }
}

function removeTooltip() {
  tooltip?.remove()
  tooltip = null
}

function createTooltip(x: number, y: number, url: string, score: number, riskLevel: string) {
  removeTooltip()
  const colors = RISK_COLORS[riskLevel] || RISK_COLORS.LOW

  tooltip = document.createElement('div')
  tooltip.id = 'abs-hover-tooltip'
  tooltip.style.cssText = `
    position:fixed;z-index:2147483646;
    background:${colors.bg};border:1px solid ${colors.text}44;
    color:${colors.text};padding:8px 12px;border-radius:10px;
    font-family:system-ui,sans-serif;font-size:12px;font-weight:600;
    pointer-events:none;box-shadow:0 4px 16px rgba(0,0,0,0.5);
    max-width:280px;word-break:break-all;
    transition:opacity 0.15s ease;
  `

  const displayUrl = url.length > 50 ? url.slice(0, 50) + '...' : url
  tooltip.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
      <span>${colors.emoji}</span>
      <span style="letter-spacing:1px;text-transform:uppercase;font-size:10px;">${riskLevel} RISK · ${score}/100</span>
    </div>
    <div style="opacity:0.7;font-weight:400;font-size:11px;">${displayUrl}</div>
  `

  const left = Math.min(x + 12, window.innerWidth - 300)
  const top = Math.max(y - 60, 8)
  tooltip.style.left = left + 'px'
  tooltip.style.top = top + 'px'

  document.body.appendChild(tooltip)
}

export function initHoverPreview() {
  let hoverTimeout: ReturnType<typeof setTimeout> | null = null

  document.addEventListener('mouseover', (e) => {
    const anchor = (e.target as HTMLElement).closest('a')
    if (!anchor) return

    const href = anchor.getAttribute('href')
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return

    let fullUrl = href
    try {
      fullUrl = new URL(href, window.location.href).href
    } catch {
      return
    }

    if (fullUrl.startsWith(window.location.origin)) return

    hoverTimeout = setTimeout(() => {
      const { score, riskLevel } = scoreUrl(fullUrl)
      if (score >= 30) {
        createTooltip(e.clientX, e.clientY, fullUrl, score, riskLevel)
      }
    }, 300)
  })

  document.addEventListener('mouseout', (e) => {
    const anchor = (e.target as HTMLElement).closest('a')
    if (!anchor) return
    if (hoverTimeout) {
      clearTimeout(hoverTimeout)
      hoverTimeout = null
    }
    removeTooltip()
  })

  document.addEventListener('click', removeTooltip)
  document.addEventListener('scroll', removeTooltip, { passive: true })
}
