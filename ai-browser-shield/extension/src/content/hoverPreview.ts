const RISK_COLORS: Record<string, { bg: string; text: string; emoji: string }> = {
  CRITICAL: { bg: '#450A0A', text: '#FCA5A5', emoji: 'Alert' },
  HIGH:     { bg: '#431407', text: '#FED7AA', emoji: 'Warn' },
  MEDIUM:   { bg: '#422006', text: '#FEF08A', emoji: 'Caution' },
  LOW:      { bg: '#052E16', text: '#86EFAC', emoji: 'Safe' },
}

type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

function scorePreviewUrl(rawUrl: string): { score: number; riskLevel: RiskLevel } {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return { score: 0, riskLevel: 'LOW' }
  }

  const lower = url.href.toLowerCase()
  let score = 0

  if (/(login|verify|secure|account|password|wallet|crypto)/.test(lower)) score += 10
  if (/(filmyzilla|torrent|movies|piracy|movierulz|dramacool)/.test(lower)) score += 15
  if (/\.(tk|ml|ga|cf|gq|xyz|top|click|rest|zip|icu|sbs)$/.test(url.hostname)) score += 15
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) score += 20
  if ((url.href.match(/%[0-9a-f]{2}/gi) || []).length > 3) score += 10
  if (url.hostname.split('.').length > 4) score += 10

  const capped = Math.min(100, score)
  const riskLevel: RiskLevel =
    capped >= 75 ? 'CRITICAL' :
    capped >= 50 ? 'HIGH' :
    capped >= 30 ? 'MEDIUM' :
    'LOW'

  return { score: capped, riskLevel }
}

let tooltip: HTMLElement | null = null

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
      <span style="letter-spacing:1px;text-transform:uppercase;font-size:10px;">${riskLevel} risk · ${score}/100</span>
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
      const { score, riskLevel } = scorePreviewUrl(fullUrl)
      if (score >= 30) {
        createTooltip(e.clientX, e.clientY, fullUrl, score, riskLevel)
      }
    }, 300)
  })

  document.addEventListener('mouseout', (e) => {
    const anchor = (e.target as HTMLElement).closest('a')
    if (!anchor) return
    if (hoverTimeout) { clearTimeout(hoverTimeout); hoverTimeout = null }
    removeTooltip()
  })

  document.addEventListener('click', removeTooltip)
  document.addEventListener('scroll', removeTooltip, { passive: true })
}
