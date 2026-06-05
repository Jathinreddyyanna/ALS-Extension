import { decodeRedirectChain, type DecodedRedirectResult, type RedirectIntentType } from './redirectDecoder'

const TRUSTED_DOMAINS = new Set([
  'google.com',
  'google.co.in',
  'google.co.uk',
  'github.com',
  'stackoverflow.com',
  'wikipedia.org',
  'en.wikipedia.org',
  'amazon.com',
  'amazon.in',
  'amazon.co.uk',
  'ebay.com',
  'paypal.com',
  'stripe.com',
  'linkedin.com',
  'youtube.com',
  'microsoft.com',
  'office.com',
  'outlook.com',
  'docs.microsoft.com',
  'support.microsoft.com',
  'apple.com',
  'support.apple.com',
  'facebook.com',
  'instagram.com',
  'netflix.com',
  'openai.com',
  'chatgpt.com',
  'walmart.com',
  'target.com',
  'shopify.com',
  'flipkart.com',
  'sbi.co.in',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'citi.com',
])

const TRACKER_NETWORKS: Record<string, { category: string; owner: string; risk: number }> = {
  'doubleclick.net': { category: 'tracker', owner: 'Google', risk: 0 },
  'googletagmanager.com': { category: 'tracker', owner: 'Google', risk: 0 },
  'googleadservices.com': { category: 'tracker', owner: 'Google', risk: 0 },
  'facebook.com': { category: 'social', owner: 'Meta', risk: 0 },
  'facebook.net': { category: 'social', owner: 'Meta', risk: 0 },
  'instagram.com': { category: 'social', owner: 'Meta', risk: 0 },
  'linkedin.com': { category: 'social', owner: 'LinkedIn', risk: 0 },
  'outbrain.com': { category: 'content_network', owner: 'Outbrain', risk: 1 },
  'taboola.com': { category: 'content_network', owner: 'Taboola', risk: 1 },
  'mgid.com': { category: 'content_network', owner: 'MGID', risk: 1 },
  'adstr.net': { category: 'redirect_network', owner: 'Unknown', risk: 3 },
  'propellerads.com': { category: 'ad_network', owner: 'PropellerAds', risk: 2 },
  'adcash.com': { category: 'ad_network', owner: 'AdCash', risk: 2 },
  'zedo.com': { category: 'ad_network', owner: 'Zedo', risk: 2 },
  'clickbank.net': { category: 'affiliate', owner: 'Clickbank', risk: 1 },
  'clickbank.com': { category: 'affiliate', owner: 'Clickbank', risk: 1 },
  'cj.com': { category: 'affiliate', owner: 'Commission Junction', risk: 0 },
  'rakutenmarketing.com': { category: 'affiliate', owner: 'Rakuten', risk: 0 },
  'awin.com': { category: 'affiliate', owner: 'Awin', risk: 0 },
  'impact.com': { category: 'affiliate', owner: 'Impact', risk: 0 },
  'partnerize.com': { category: 'affiliate', owner: 'Partnerize', risk: 0 },
  'shareasale.com': { category: 'affiliate', owner: 'ShareASale', risk: 0 },
  'bit.ly': { category: 'shortener', owner: 'Bitly', risk: 1 },
  'tinyurl.com': { category: 'shortener', owner: 'TinyURL', risk: 1 },
  't.co': { category: 'shortener', owner: 'X', risk: 0 },
  'ow.ly': { category: 'shortener', owner: 'HootSuite', risk: 0 },
  'buff.ly': { category: 'shortener', owner: 'Buffer', risk: 0 },
  'tiny.cc': { category: 'shortener', owner: 'TinyCC', risk: 1 },
  'rb.gy': { category: 'shortener', owner: 'RB.GY', risk: 1 },
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
const SENSITIVE_PATH_PATTERN = /login|signin|auth|verify|account|checkout|payment|billing|oauth|callback|consent/i
const SAFE_PROTOCOL_PATTERN = /^https?:/i
const DISALLOWED_PROTOCOLS = ['javascript:', 'data:', 'blob:', 'file:']
const MODAL_ID = 'abs-preclick-modal'

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

/**
 * Sends a best-effort internal extension event.
 */
function sendRuntimeMessageSafe(message: unknown) {
  try {
    chrome.runtime.sendMessage(message, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Ignore background availability issues.
  }
}

/**
 * Normalizes a hostname for reputation checks.
 */
function normalizeHostname(hostname: string): string {
  return hostname.replace(/^www\./, '').toLowerCase()
}

/**
 * Returns true when the hostname belongs to a trusted service family.
 */
function isTrustedDomain(hostname: string): boolean {
  const clean = normalizeHostname(hostname)
  if (TRUSTED_DOMAINS.has(clean)) return true
  return Array.from(TRUSTED_DOMAINS).some((domain) => clean.endsWith(`.${domain}`))
}

/**
 * Returns true when a destination is a sensitive but common legitimate flow.
 */
function isSensitiveTrustedFlow(url: string, hostname: string): boolean {
  return isTrustedDomain(hostname) && SENSITIVE_PATH_PATTERN.test(url)
}

/**
 * Resolves the anchor associated with a click target.
 */
function getRootAnchor(eventTarget: EventTarget | null): HTMLAnchorElement | null {
  if (!(eventTarget instanceof Element)) return null
  const anchor = eventTarget.closest('a[href]')
  return anchor instanceof HTMLAnchorElement ? anchor : null
}

/**
 * Derives page context around the click.
 */
function analyzeContext(anchor: HTMLAnchorElement, event: MouseEvent): ClickContext {
  const inIframe = window.top !== window.self
  const pageTrusted = isTrustedDomain(window.location.hostname)
  const opensNewTab = anchor.target === '_blank' || event.ctrlKey || event.metaKey || event.button === 1
  const isDownload = Boolean(anchor.download) || DOWNLOAD_EXTENSIONS.some((extension) => anchor.href.toLowerCase().includes(extension))
  const isAdPlacement = AD_SELECTORS.some((selector) => anchor.closest(selector))

  return {
    source: inIframe ? 'iframe' : isAdPlacement ? 'ad' : anchor.closest('article, main, [role="article"]') ? 'article' : 'unknown',
    inIframe,
    opensNewTab,
    isDownload,
    pageTrusted,
  }
}

/**
 * Scores the redirect intent class.
 */
function scoreRedirectIntent(intentType: RedirectIntentType): number {
  switch (intentType) {
    case 'AFFILIATE':
      return 1
    case 'TRACKING':
      return 0
    case 'SHORTENER':
      return 1
    case 'TRAFFIC_MONETIZATION':
      return 3
    case 'PHISHING_VECTOR':
      return 8
    default:
      return 0
  }
}

/**
 * Returns the reputation contribution for the destination domain.
 */
function scoreDomain(hostname: string): number {
  const clean = normalizeHostname(hostname)
  if (!clean || isTrustedDomain(clean)) return 0

  const tracker = Object.entries(TRACKER_NETWORKS).find(([domain]) => clean === domain || clean.endsWith(`.${domain}`))
  return tracker?.[1].risk ?? 1
}

/**
 * Adds a mismatch penalty when the link text implies a different trusted destination.
 */
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

/**
 * Applies a conservative baseline only to genuinely unknown risky flows.
 */
function enforceBaselineRule(
  score: number,
  destinationHostname: string,
  destinationUrl: string,
  context: ClickContext
): number {
  if (isTrustedDomain(destinationHostname) || isSensitiveTrustedFlow(destinationUrl, destinationHostname)) {
    return score
  }

  if (score < 3 && !context.pageTrusted && context.source === 'unknown') {
    return Math.max(score, 2)
  }

  if (score < HIGH_RISK_THRESHOLD && !context.pageTrusted && (context.source === 'ad' || context.inIframe)) {
    return Math.max(score, 4)
  }

  return score
}

/**
 * Calculates the full pre-click risk assessment for a link interaction.
 */
export function computeAssessment(anchor: HTMLAnchorElement, event: MouseEvent): PreclickAssessment {
  const redirect = decodeRedirectChain(anchor.href)
  const context = analyzeContext(anchor, event)
  const destinationHostname = normalizeHostname(new URL(redirect.finalUrl).hostname)
  const reasons: string[] = []
  let score = 0

  if (context.inIframe && !isTrustedDomain(destinationHostname)) {
    score += 1
    reasons.push('Link is inside an embedded frame')
  }
  if (context.source === 'ad' && !isTrustedDomain(destinationHostname)) {
    score += 1
    reasons.push('Link appears in an ad-like placement')
  }
  if (context.isDownload && !isTrustedDomain(destinationHostname)) {
    score += 1
    reasons.push('Link appears to trigger a download')
  }

  const domainRisk = scoreDomain(destinationHostname)
  score += domainRisk
  if (domainRisk > 1 && !isTrustedDomain(destinationHostname)) {
    reasons.push('Destination domain has weak trust signals')
  }

  const redirectTypeScore = scoreRedirectIntent(redirect.intentType)
  score += redirectTypeScore
  if (redirect.intentType === 'PHISHING_VECTOR') {
    reasons.push('Redirect target is obfuscated')
  } else if (redirect.intentType === 'TRAFFIC_MONETIZATION') {
    reasons.push('Redirect path passes through a monetized network')
  }

  const chainPenalty = Math.min(4, Math.max(0, redirect.chain.length - 1))
  score += chainPenalty
  if (chainPenalty >= 3) {
    reasons.push(`Redirect chain includes ${redirect.chain.length} hops`)
  }

  if (redirect.usedBase64) {
    score += 2
    reasons.push('Target uses Base64 obfuscation')
  }
  if (redirect.usedNestedEncoding) {
    score += 1
    reasons.push('Nested URL encoding detected')
  }

  const deceptiveScore = mismatchScore(anchor, destinationHostname)
  score += deceptiveScore
  if (deceptiveScore > 0) {
    reasons.push('Link label does not match the final destination')
  }

  const finalScore = Math.min(10, enforceBaselineRule(score, destinationHostname, redirect.finalUrl, context))
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

/**
 * Returns true when the destination protocol should be blocked before navigation.
 */
function isDisallowedProtocol(href: string): boolean {
  const normalized = href.trim().toLowerCase()
  return DISALLOWED_PROTOCOLS.some((protocol) => normalized.startsWith(protocol))
}

/**
 * Converts an assessment into a calm, human-readable dialog model.
 */
function getDialogCopy(assessment: PreclickAssessment) {
  const topReasons = assessment.reasons.slice(0, 3)
  const headline = assessment.riskLevel === 'CRITICAL'
    ? 'Potentially dangerous redirect'
    : 'Unusual navigation detected'
  const description = assessment.riskLevel === 'CRITICAL'
    ? 'This click looks unsafe and may lead to a deceptive page.'
    : 'This click includes redirect behavior that deserves a second look.'

  return {
    headline,
    description,
    topReasons: topReasons.length > 0 ? topReasons : ['The destination flow looks unusual for this page.'],
    chainSummary: assessment.redirect.chain.length > 2
      ? assessment.redirect.chain.map((hop) => hop.hostname).filter(Boolean).join(' -> ')
      : assessment.destinationUrl,
  }
}

/**
 * Removes the active pre-click modal if present.
 */
function removeExistingModal() {
  document.getElementById(MODAL_ID)?.remove()
}

/**
 * Presents a simple block explanation for unsafe protocols.
 */
function presentBlockedProtocolModal(href: string): Promise<void> {
  removeExistingModal()

  return new Promise((resolve) => {
    const overlay = document.createElement('div')
    overlay.id = MODAL_ID
    overlay.setAttribute('data-shield-injected', '1')
    Object.assign(overlay.style, {
      position: 'fixed',
      inset: '0',
      zIndex: '2147483647',
      background: 'rgba(2, 6, 23, 0.62)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      boxSizing: 'border-box',
    })

    const dialog = document.createElement('div')
    Object.assign(dialog.style, {
      width: 'min(440px, 100%)',
      borderRadius: '20px',
      background: '#0B1220',
      color: '#F8FAFC',
      border: '1px solid rgba(148,163,184,0.18)',
      boxShadow: '0 24px 80px rgba(0,0,0,0.45)',
      overflow: 'hidden',
      fontFamily: 'Inter, system-ui, sans-serif',
    })

    dialog.innerHTML = `
      <div style="padding:20px 20px 0;">
        <div style="font-size:18px;font-weight:700;">Blocked unsafe link</div>
        <div style="margin-top:8px;color:#CBD5E1;font-size:14px;line-height:1.6;">
          This link uses a protocol that can execute code or bypass normal browser safety checks.
        </div>
      </div>
      <div style="padding:16px 20px;">
        <div style="padding:12px;border-radius:12px;background:rgba(15,23,42,0.9);font-size:12px;color:#E2E8F0;word-break:break-word;">
          ${href}
        </div>
      </div>
      <div style="display:flex;justify-content:flex-end;padding:0 20px 20px;">
        <button data-action="dismiss" style="min-width:120px;border-radius:12px;padding:11px 16px;border:none;background:#2563EB;color:white;font-weight:700;cursor:pointer;">
          Understood
        </button>
      </div>
    `

    const finish = () => {
      overlay.remove()
      resolve()
    }

    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) finish()
    })

    dialog.querySelector<HTMLButtonElement>('[data-action="dismiss"]')?.addEventListener('click', finish)
    overlay.appendChild(dialog)
    document.documentElement.appendChild(overlay)
  })
}

/**
 * Presents a product-grade modal instead of using window.confirm.
 */
function presentDecisionModal(assessment: PreclickAssessment): Promise<boolean> {
  removeExistingModal()
  const copy = getDialogCopy(assessment)
  const allowOverride = assessment.riskLevel !== 'CRITICAL'

  return new Promise((resolve) => {
    const overlay = document.createElement('div')
    overlay.id = MODAL_ID
    overlay.setAttribute('data-shield-injected', '1')
    Object.assign(overlay.style, {
      position: 'fixed',
      inset: '0',
      zIndex: '2147483647',
      background: 'rgba(2, 6, 23, 0.62)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px',
      boxSizing: 'border-box',
    })

    const dialog = document.createElement('div')
    Object.assign(dialog.style, {
      width: 'min(480px, 100%)',
      borderRadius: '20px',
      background: '#0B1220',
      color: '#F8FAFC',
      border: '1px solid rgba(148,163,184,0.18)',
      boxShadow: '0 24px 80px rgba(0,0,0,0.45)',
      overflow: 'hidden',
      fontFamily: 'Inter, system-ui, sans-serif',
    })

    dialog.innerHTML = `
      <div style="padding:20px 20px 0;">
        <div style="font-size:18px;font-weight:700;">${copy.headline}</div>
        <div style="margin-top:8px;color:#CBD5E1;font-size:14px;line-height:1.6;">${copy.description}</div>
      </div>
      <div style="padding:16px 20px;">
        ${copy.topReasons.map((reason) => `
          <div style="margin-bottom:8px;padding:10px 12px;border-radius:12px;background:rgba(15,23,42,0.9);font-size:13px;color:#E2E8F0;">
            ${reason}
          </div>
        `).join('')}
        <div style="margin-top:12px;padding:12px;border-radius:12px;background:rgba(37,99,235,0.10);border:1px solid rgba(37,99,235,0.22);font-size:12px;color:#BFDBFE;word-break:break-word;">
          ${copy.chainSummary}
        </div>
      </div>
      <div style="display:flex;gap:12px;justify-content:flex-end;padding:0 20px 20px;">
        <button data-action="cancel" style="min-width:120px;border-radius:12px;padding:11px 16px;border:1px solid rgba(148,163,184,0.25);background:transparent;color:#E2E8F0;font-weight:600;cursor:pointer;">
          ${allowOverride ? 'Stay Safe' : 'Close'}
        </button>
        ${allowOverride ? `
        <button data-action="proceed" style="min-width:120px;border-radius:12px;padding:11px 16px;border:none;background:#2563EB;color:white;font-weight:700;cursor:pointer;">
          Continue
        </button>` : ''}
      </div>
    `

    const finish = (decision: boolean) => {
      overlay.remove()
      resolve(decision)
    }

    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) finish(false)
    })

    dialog.querySelector<HTMLButtonElement>('[data-action="cancel"]')?.addEventListener('click', () => finish(false))
    dialog.querySelector<HTMLButtonElement>('[data-action="proceed"]')?.addEventListener('click', () => finish(true))

    overlay.appendChild(dialog)
    document.documentElement.appendChild(overlay)
  })
}

/**
 * Navigates after the user explicitly overrides the warning.
 */
function navigateAfterOverride(anchor: HTMLAnchorElement, assessment: PreclickAssessment, event: MouseEvent) {
  if (!anchor.isConnected || !document.contains(anchor)) return

  if (assessment.context.opensNewTab || event.shiftKey) {
    window.open(assessment.destinationUrl, '_blank', 'noopener,noreferrer')
    return
  }

  window.location.assign(assessment.destinationUrl)
}

/**
 * Boots the pre-click interception layer for HTTP(S) links.
 */
export function initLinkInterceptor() {
  const handleClick = async (event: MouseEvent) => {
    const anchor = getRootAnchor(event.target)
    if (!anchor) return

    const href = anchor.getAttribute('href') ?? ''
    if (isDisallowedProtocol(href)) {
      event.preventDefault()
      event.stopPropagation()
      sendRuntimeMessageSafe({
        type: 'PRECLICK_NAVIGATION_DECISION',
        payload: {
          href,
          finalUrl: href,
          score: 10,
          riskLevel: 'CRITICAL',
          proceeded: false,
          reasons: ['Blocked unsupported or unsafe protocol'],
        },
      })
      void presentBlockedProtocolModal(href)
      return
    }

    if (!anchor.href || !SAFE_PROTOCOL_PATTERN.test(anchor.href)) return

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

    if (assessment.riskLevel === 'LOW') return

    if (assessment.riskLevel === 'CRITICAL') {
      event.preventDefault()
      event.stopPropagation()
      void presentDecisionModal(assessment)
      sendRuntimeMessageSafe({
        type: 'PRECLICK_NAVIGATION_DECISION',
        payload: {
          href: anchor.href,
          finalUrl: assessment.destinationUrl,
          score: assessment.score,
          riskLevel: assessment.riskLevel,
          proceeded: false,
          reasons: assessment.reasons,
        },
      })
      return
    }

    event.preventDefault()
    event.stopPropagation()
    const proceed = await presentDecisionModal(assessment)
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

  document.addEventListener('click', (event) => {
    void handleClick(event)
  }, true)
}
