import { decodeRedirectChain, type DecodedRedirectResult, type RedirectIntentType } from './redirectDecoder'

const TRUSTED_DOMAINS = new Set([
  'google.com',
  'github.com',
  'stackoverflow.com',
  'wikipedia.org',
  'en.wikipedia.org',
  'amazon.com',
  'amazon.in',
  'linkedin.com',
  'youtube.com',
  'microsoft.com',
  'docs.microsoft.com',
  'support.microsoft.com',
  'apple.com',
  'support.apple.com',
])

const TRACKER_NETWORKS: Record<string, { category: string; owner: string; risk: number }> = {
  'doubleclick.net': { category: 'tracker', owner: 'Google', risk: 1 },
  'googletagmanager.com': { category: 'tracker', owner: 'Google', risk: 1 },
  'googleadservices.com': { category: 'tracker', owner: 'Google', risk: 1 },
  'facebook.com': { category: 'social', owner: 'Meta', risk: 1 },
  'facebook.net': { category: 'social', owner: 'Meta', risk: 1 },
  'instagram.com': { category: 'social', owner: 'Meta', risk: 1 },
  'linkedin.com': { category: 'social', owner: 'LinkedIn', risk: 1 },
  'outbrain.com': { category: 'content_network', owner: 'Outbrain', risk: 3 },
  'taboola.com': { category: 'content_network', owner: 'Taboola', risk: 3 },
  'mgid.com': { category: 'content_network', owner: 'MGID', risk: 3 },
  'zergnet.com': { category: 'content_network', owner: 'ZergNet', risk: 3 },
  'yumenetworks.com': { category: 'content_network', owner: 'Yume Networks', risk: 3 },
  'adstr.net': { category: 'redirect_network', owner: 'Unknown', risk: 4 },
  'propellerads.com': { category: 'ad_network', owner: 'PropellerAds', risk: 3 },
  'adcash.com': { category: 'ad_network', owner: 'AdCash', risk: 3 },
  'zedo.com': { category: 'ad_network', owner: 'Zedo', risk: 3 },
  'exoclick.com': { category: 'ad_network', owner: 'ExoClick', risk: 3 },
  'clickbank.net': { category: 'affiliate', owner: 'Clickbank', risk: 3 },
  'clickbank.com': { category: 'affiliate', owner: 'Clickbank', risk: 3 },
  'cj.com': { category: 'affiliate', owner: 'Commission Junction', risk: 2 },
  'rakutenmarketing.com': { category: 'affiliate', owner: 'Rakuten', risk: 2 },
  'awin.com': { category: 'affiliate', owner: 'Awin', risk: 2 },
  'impact.com': { category: 'affiliate', owner: 'Impact', risk: 2 },
  'partnerize.com': { category: 'affiliate', owner: 'Partnerize', risk: 2 },
  'shareasale.com': { category: 'affiliate', owner: 'ShareASale', risk: 2 },
  'tradedoubler.com': { category: 'affiliate', owner: 'TradeDoubler', risk: 2 },
  'linkshare.com': { category: 'affiliate', owner: 'LinkShare', risk: 2 },
  'bit.ly': { category: 'shortener', owner: 'Bitly', risk: 2 },
  'tinyurl.com': { category: 'shortener', owner: 'TinyURL', risk: 2 },
  't.co': { category: 'shortener', owner: 'X', risk: 1 },
  'ow.ly': { category: 'shortener', owner: 'HootSuite', risk: 1 },
  'buff.ly': { category: 'shortener', owner: 'Buffer', risk: 1 },
  'tiny.cc': { category: 'shortener', owner: 'TinyCC', risk: 2 },
  'rb.gy': { category: 'shortener', owner: 'RB.GY', risk: 2 },
}

const AD_SELECTORS = [
  '[class*="ad"]',
  '[class*="sponsor"]',
  '[class*="promo"]',
  '[data-ad]',
  '[data-sponsored]',
]

const DOWNLOAD_EXTENSIONS = ['.exe', '.msi', '.apk', '.zip', '.rar', '.dmg', '.pkg', '.iso', '.jar']
const HIGH_RISK_THRESHOLD = 6
const CRITICAL_THRESHOLD = 8
const SENSITIVE_BRANDS = ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'linkedin', 'youtube', 'github', 'bank', 'netflix']

export interface ClickContext {
  source: 'article' | 'ad' | 'iframe' | 'unknown'
  inIframe: boolean
  opensNewTab: boolean
  isDownload: boolean
  pageTrusted: boolean
}

export interface PreclickAssessment {
  score: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  reasons: string[]
  destinationUrl: string
  redirect: DecodedRedirectResult
  context: ClickContext
}

function sendRuntimeMessageSafe(message: unknown) {
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore background availability issues.
  }
}

function normalizeHostname(hostname: string): string {
  return hostname.replace(/^www\./, '').toLowerCase()
}

function isTrustedDomain(hostname: string): boolean {
  const clean = normalizeHostname(hostname)
  if (TRUSTED_DOMAINS.has(clean)) return true
  return Array.from(TRUSTED_DOMAINS).some((domain) => clean.endsWith(`.${domain}`))
}

function getRootAnchor(eventTarget: EventTarget | null): HTMLAnchorElement | null {
  if (!(eventTarget instanceof Element)) return null
  const anchor = eventTarget.closest('a[href]')
  return anchor instanceof HTMLAnchorElement ? anchor : null
}

function analyzeContext(anchor: HTMLAnchorElement, event: MouseEvent): ClickContext {
  const inIframe = window.top !== window.self
  const pageTrusted = isTrustedDomain(window.location.hostname)
  const opensNewTab = anchor.target === '_blank' || event.ctrlKey || event.metaKey || event.button === 1
  const isDownload = Boolean(anchor.download) || DOWNLOAD_EXTENSIONS.some((extension) => anchor.href.toLowerCase().includes(extension))

  const isAdPlacement = AD_SELECTORS.some((selector) => anchor.closest(selector))
  const source: ClickContext['source'] =
    inIframe ? 'iframe'
      : isAdPlacement ? 'ad'
        : anchor.closest('article, main, [role="article"]') ? 'article'
          : 'unknown'

  return {
    source,
    inIframe,
    opensNewTab,
    isDownload,
    pageTrusted,
  }
}

function scoreRedirectIntent(intentType: RedirectIntentType): number {
  switch (intentType) {
    case 'AFFILIATE':
      return 3
    case 'TRACKING':
      return 2
    case 'SHORTENER':
      return 2
    case 'TRAFFIC_MONETIZATION':
      return 4
    case 'PHISHING_VECTOR':
      return 8
    default:
      return 1
  }
}

function scoreDomain(hostname: string): number {
  const clean = normalizeHostname(hostname)
  if (!clean) return 1
  if (isTrustedDomain(clean)) return 0

  const tracker = Object.entries(TRACKER_NETWORKS).find(([domain]) => clean === domain || clean.endsWith(`.${domain}`))
  if (tracker) return tracker[1].risk

  return 1
}

function mismatchScore(anchor: HTMLAnchorElement, destinationHostname: string): number {
  const text = (anchor.textContent ?? '').trim().toLowerCase()
  if (!text || !destinationHostname) return 0

  const mentionsBrand = ['login', 'signin', 'verify', 'download', 'play'].some((keyword) => text.includes(keyword))
  const mentionsSensitiveBrand = SENSITIVE_BRANDS.some((keyword) => text.includes(keyword))
  const mentionsTrustedDomain = Array.from(TRUSTED_DOMAINS).some((domain) => text.includes(domain.split('.')[0]))
  const destinationTrusted = isTrustedDomain(destinationHostname)

  if (mentionsTrustedDomain && !destinationTrusted) return 2
  if (mentionsSensitiveBrand && !destinationTrusted) return 2
  if (mentionsBrand && !destinationTrusted) return 1
  return 0
}

function enforceBaselineRule(
  score: number,
  destinationHostname: string,
  context: ClickContext
): number {
  if (score < 3 && !isTrustedDomain(destinationHostname)) {
    if (context.source === 'unknown' && !context.pageTrusted) {
      return Math.max(score, 3)
    }

    if ((context.source === 'ad' || context.inIframe) && !context.pageTrusted) {
      return Math.max(score, 6)
    }
  }

  return score
}

export function computeAssessment(anchor: HTMLAnchorElement, event: MouseEvent): PreclickAssessment {
  const redirect = decodeRedirectChain(anchor.href)
  const context = analyzeContext(anchor, event)
  const destinationHostname = normalizeHostname(new URL(redirect.finalUrl).hostname)
  const reasons: string[] = []

  let score = 0

  if (context.inIframe) {
    score += 2
    reasons.push('Link is inside an iframe')
  }
  if (context.source === 'ad') {
    score += 1
    reasons.push('Link appears in ad-like placement')
  }
  if (context.isDownload) {
    score += 1
    reasons.push('Link appears to trigger a download')
  }

  const domainRisk = scoreDomain(destinationHostname)
  score += domainRisk
  if (domainRisk > 0 && !isTrustedDomain(destinationHostname)) {
    reasons.push('Destination domain is unknown or monetized')
  }

  const redirectTypeScore = scoreRedirectIntent(redirect.intentType)
  score += redirectTypeScore
  if (redirect.intentType !== 'STANDARD') {
    reasons.push(`Redirect intent classified as ${redirect.intentType.toLowerCase().replace(/_/g, ' ')}`)
  }

  const chainPenalty = Math.min(4, Math.max(0, redirect.chain.length - 1))
  score += chainPenalty
  if (chainPenalty > 0) {
    reasons.push(`Redirect chain includes ${redirect.chain.length} hops`)
  }

  if (redirect.usedBase64) {
    score += 2
    reasons.push('Target is Base64-obfuscated')
  }
  if (redirect.usedNestedEncoding) {
    score += 2
    reasons.push('Nested URL encoding detected')
  }
  if (redirect.trackingParams.length > 0) {
    score += 1
    reasons.push(`Tracking parameters detected: ${redirect.trackingParams.slice(0, 3).join(', ')}`)
  }
  if (redirect.redirectParams.length > 0) {
    score += 1
    reasons.push(`Redirect parameters present: ${redirect.redirectParams.slice(0, 2).join(', ')}`)
  }

  const deceptiveScore = mismatchScore(anchor, destinationHostname)
  score += deceptiveScore
  if (deceptiveScore > 0) {
    reasons.push('Anchor text does not match final destination')
  }

  if (!isTrustedDomain(destinationHostname) && context.source === 'unknown' && !context.pageTrusted) {
    reasons.push('Unknown destination from unknown context')
  } else if (!isTrustedDomain(destinationHostname) && (context.source === 'ad' || context.inIframe) && !context.pageTrusted) {
    reasons.push('Unknown destination from risky context')
  }

  const finalScore = Math.min(10, enforceBaselineRule(score, destinationHostname, context))
  const riskLevel =
    finalScore >= CRITICAL_THRESHOLD ? 'CRITICAL'
      : finalScore >= HIGH_RISK_THRESHOLD ? 'HIGH'
        : finalScore >= 3 ? 'MEDIUM'
          : 'LOW'

  return {
    score: finalScore,
    riskLevel,
    reasons: Array.from(new Set(reasons)),
    destinationUrl: redirect.finalUrl,
    redirect,
    context,
  }
}

function buildWarningMessage(assessment: PreclickAssessment): string {
  const chainSummary = assessment.redirect.chain.length > 2
    ? `Redirect chain: ${assessment.redirect.chain.map((hop) => hop.hostname).filter(Boolean).join(' -> ')}`
    : `Final destination: ${assessment.destinationUrl}`

  return [
    `Shield flagged this click as ${assessment.riskLevel} risk (${assessment.score}/10).`,
    assessment.reasons.slice(0, 3).join(' | '),
    chainSummary,
    'Proceed anyway?'
  ].filter(Boolean).join('\n\n')
}

function navigateAfterOverride(anchor: HTMLAnchorElement, assessment: PreclickAssessment, event: MouseEvent) {
  if (contextIsolationGuard(anchor)) return

  if (assessment.context.opensNewTab) {
    window.open(assessment.destinationUrl, '_blank', 'noopener,noreferrer')
    return
  }

  if (event.shiftKey) {
    window.open(assessment.destinationUrl, '_blank', 'noopener,noreferrer')
    return
  }

  window.location.assign(assessment.destinationUrl)
}

function contextIsolationGuard(anchor: HTMLAnchorElement): boolean {
  return !anchor.isConnected || !document.contains(anchor)
}

export function initLinkInterceptor() {
  const handleClick = (event: MouseEvent) => {
    const anchor = getRootAnchor(event.target)
    if (!anchor) return
    if (!anchor.href || !/^https?:/i.test(anchor.href)) return

    const assessment = computeAssessment(anchor, event)

    sendRuntimeMessageSafe({
      type: 'PRECLICK_RISK_EVALUATED',
      payload: {
        href: anchor.href,
        finalUrl: assessment.destinationUrl,
        score: assessment.score,
        riskLevel: assessment.riskLevel,
        reasons: assessment.reasons,
        redirectChain: assessment.redirect.chain.map((hop) => hop.url),
        trackingParams: assessment.redirect.trackingParams,
        intentType: assessment.redirect.intentType,
        sourceContext: assessment.context.source,
      },
    })

    if (assessment.score < HIGH_RISK_THRESHOLD) return

    event.preventDefault()
    event.stopPropagation()

    const proceed = window.confirm(buildWarningMessage(assessment))
    sendRuntimeMessageSafe({
      type: 'PRECLICK_NAVIGATION_DECISION',
      payload: {
        href: anchor.href,
        finalUrl: assessment.destinationUrl,
        score: assessment.score,
        riskLevel: assessment.riskLevel,
        proceeded: proceed,
        reasons: assessment.reasons,
      },
    })

    if (proceed) {
      navigateAfterOverride(anchor, assessment, event)
    }
  }

  document.addEventListener('click', handleClick, true)
}
