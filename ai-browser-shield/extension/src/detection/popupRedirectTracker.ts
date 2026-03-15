export interface PopupEvent {
  url: string
  timestamp: number
  popupUrl?: string
  popupType: 'window' | 'iframe' | 'redirect' | 'meta-refresh'
  userAction: 'blocked' | 'allowed'
}

export interface RedirectChain {
  original: string
  chain: string[]
  totalRedirects: number
  finalUrl: string
  isBlocked: boolean
}

export interface PopupAndRedirectAnalysis {
  website: string
  popupCount: number
  popupThreshold: number
  popupExceeded: boolean
  popupDetails: PopupEvent[]
  redirectChains: RedirectChain[]
  totalRedirects: number
  riskLevel: 'SAFE' | 'CAUTION' | 'DANGEROUS' | 'CRITICAL'
  recommendations: string[]
  shouldBlock: boolean
  flags: string[]
}

export class PopupAndRedirectTracker {
  private popupCount: number = 0
  private popupThreshold: number = 5
  private popupHistory: PopupEvent[] = []
  private redirectChains: RedirectChain[] = []
  private currentWebsite: string = ''
  private redirectStack: string[] = []

  constructor(threshold: number = 5) {
    this.popupThreshold = threshold
  }

  trackPopupWindow(event: {
    url: string
    popupUrl: string
    timestamp: number
  }): { blocked: boolean; reason?: string } {
    this.popupCount++

    const popupEvent: PopupEvent = {
      url: event.url,
      timestamp: event.timestamp,
      popupUrl: event.popupUrl,
      popupType: 'window',
      userAction: 'allowed',
    }

    this.popupHistory.push(popupEvent)

    if (this.popupCount > this.popupThreshold) {
      popupEvent.userAction = 'blocked'
      return {
        blocked: true,
        reason: `Popup threshold exceeded (${this.popupCount}/${this.popupThreshold})`,
      }
    }

    return { blocked: false }
  }

  trackIframeInjection(event: {
    url: string
    iframeUrl: string
    timestamp: number
    isHidden: boolean
  }): { blocked: boolean; reason?: string } {
    this.popupCount++

    const popupEvent: PopupEvent = {
      url: event.url,
      timestamp: event.timestamp,
      popupUrl: event.iframeUrl,
      popupType: 'iframe',
      userAction: 'allowed',
    }

    this.popupHistory.push(popupEvent)

    if (event.isHidden) {
      popupEvent.userAction = 'blocked'
      return {
        blocked: true,
        reason: 'Hidden iframe detected - likely malicious ad/tracker',
      }
    }

    if (this.popupCount > this.popupThreshold) {
      popupEvent.userAction = 'blocked'
      return {
        blocked: true,
        reason: `Popup threshold exceeded (${this.popupCount}/${this.popupThreshold})`,
      }
    }

    return { blocked: false }
  }

  trackRedirect(event: {
    from: string
    to: string
    method: 'header' | 'meta-refresh' | 'javascript' | 'form'
    timestamp: number
  }): { blocked: boolean; reason?: string } {
    if (!this.redirectStack.includes(event.from)) {
      this.redirectStack.push(event.from)
    }
    this.redirectStack.push(event.to)

    let chain = this.redirectChains.find((c) => c.chain.includes(event.from))

    if (!chain) {
      chain = {
        original: event.from,
        chain: [event.from, event.to],
        totalRedirects: 1,
        finalUrl: event.to,
        isBlocked: false,
      }
      this.redirectChains.push(chain)
    } else {
      chain.chain.push(event.to)
      chain.totalRedirects++
      chain.finalUrl = event.to
    }

    if (chain.totalRedirects > 5) {
      chain.isBlocked = true
      return {
        blocked: true,
        reason: `Excessive redirects detected (${chain.totalRedirects}+) - likely phishing attempt`,
      }
    }

    const isSuspicious = this.isRedirectSuspicious(chain)
    if (isSuspicious) {
      return {
        blocked: true,
        reason: isSuspicious,
      }
    }

    return { blocked: false }
  }

  trackMetaRefresh(event: {
    url: string
    redirectUrl: string
    delay: number
    timestamp: number
  }): { blocked: boolean; reason?: string } {
    this.popupCount++

    const popupEvent: PopupEvent = {
      url: event.url,
      timestamp: event.timestamp,
      popupUrl: event.redirectUrl,
      popupType: 'meta-refresh',
      userAction: 'allowed',
    }

    this.popupHistory.push(popupEvent)

    if (event.delay < 2000) {
      popupEvent.userAction = 'blocked'
      return {
        blocked: true,
        reason: 'Instant meta-refresh redirect - likely phishing attempt',
      }
    }

    if (this.popupCount > this.popupThreshold) {
      popupEvent.userAction = 'blocked'
      return {
        blocked: true,
        reason: `Redirect threshold exceeded (${this.popupCount}/${this.popupThreshold})`,
      }
    }

    return { blocked: false }
  }

  analyze(website: string): PopupAndRedirectAnalysis {
    this.currentWebsite = website

    const flags: string[] = []
    const recommendations: string[] = []
    let riskLevel: 'SAFE' | 'CAUTION' | 'DANGEROUS' | 'CRITICAL' = 'SAFE'
    let shouldBlock = false

    const popupExceeded = this.popupCount > this.popupThreshold
    if (popupExceeded) {
      flags.push(
        `Popup threshold exceeded: ${this.popupCount} popups (limit: ${this.popupThreshold})`
      )
      recommendations.push(
        'Avoid interacting with this website - excessive popups indicate malicious behavior'
      )
      riskLevel = 'DANGEROUS'
      shouldBlock = true
    } else if (this.popupCount > this.popupThreshold / 2) {
      flags.push(`High popup count: ${this.popupCount} popups`)
      recommendations.push('Be cautious - multiple popups detected')
      riskLevel = 'CAUTION'
    }

    for (const chain of this.redirectChains) {
      if (chain.totalRedirects > 5) {
        flags.push(
          `Excessive redirects: ${chain.totalRedirects} redirects in chain`
        )
        recommendations.push(`Chain: ${chain.original} -> ... -> ${chain.finalUrl}`)
        riskLevel = 'CRITICAL'
        shouldBlock = true
        chain.isBlocked = true
      } else if (chain.totalRedirects > 2) {
        flags.push(`Multiple redirects: ${chain.totalRedirects} redirects`)
        recommendations.push(
          `Chain: ${chain.original} -> ${chain.finalUrl}`
        )
        if (riskLevel === 'SAFE') riskLevel = 'CAUTION'
      }

      if (this.hasSuspiciousDomainChange(chain)) {
        flags.push('Domain switching detected in redirect chain')
        recommendations.push(
          'Suspicious behavior - redirects change the domain'
        )
        riskLevel = 'DANGEROUS'
        shouldBlock = true
      }
    }

    const blockedEvents = this.popupHistory.filter(
      (e) => e.userAction === 'blocked'
    ).length
    if (blockedEvents > 0) {
      flags.push(`${blockedEvents} suspicious events blocked`)
      riskLevel = 'DANGEROUS'
      shouldBlock = true
    }

    return {
      website,
      popupCount: this.popupCount,
      popupThreshold: this.popupThreshold,
      popupExceeded,
      popupDetails: this.popupHistory,
      redirectChains: this.redirectChains,
      totalRedirects: this.redirectChains.reduce(
        (sum, chain) => sum + chain.totalRedirects,
        0
      ),
      riskLevel,
      recommendations,
      shouldBlock,
      flags,
    }
  }

  private isRedirectSuspicious(chain: RedirectChain): string | null {
    if (this.hasSuspiciousDomainChange(chain)) {
      return `Domain switching: ${chain.original} -> ${chain.finalUrl}`
    }

    if (this.hasTyposquattingInChain(chain)) {
      return 'Typosquatting detected in redirect chain'
    }

    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.pw']
    if (suspiciousTLDs.some((tld) => chain.finalUrl.includes(tld))) {
      return `Redirect to suspicious TLD: ${this.extractDomain(chain.finalUrl)}`
    }

    return null
  }

  private hasSuspiciousDomainChange(chain: RedirectChain): boolean {
    const originalDomain = this.extractDomain(chain.original)
    const finalDomain = this.extractDomain(chain.finalUrl)

    if (originalDomain === finalDomain) {
      return false
    }

    const similarity = this.calculateStringSimilarity(originalDomain, finalDomain)
    if (similarity > 0.7) {
      return true
    }

    return true
  }

  private hasTyposquattingInChain(chain: RedirectChain): boolean {
    if (chain.chain.length < 2) return false

    const firstDomain = this.extractDomain(chain.chain[0])

    for (let i = 1; i < chain.chain.length; i++) {
      const currentDomain = this.extractDomain(chain.chain[i])

      const similarity = this.calculateStringSimilarity(firstDomain, currentDomain)
      if (similarity > 0.6 && similarity < 0.95) {
        return true
      }
    }

    return false
  }

  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url)
      return urlObj.hostname.toLowerCase()
    } catch {
      return url
    }
  }

  private calculateStringSimilarity(a: string, b: string): number {
    const aLower = a.toLowerCase()
    const bLower = b.toLowerCase()

    if (aLower === bLower) return 1

    const longer = aLower.length > bLower.length ? aLower : bLower
    const shorter = aLower.length > bLower.length ? bLower : aLower

    const editDistance = this.levenshteinDistance(longer, shorter)
    return (longer.length - editDistance) / longer.length
  }

  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = []

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i]
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1]
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          )
        }
      }
    }

    return matrix[b.length][a.length]
  }

  reset(): void {
    this.popupCount = 0
    this.popupHistory = []
    this.redirectChains = []
    this.redirectStack = []
  }

  getStats() {
    return {
      totalPopups: this.popupCount,
      popupThreshold: this.popupThreshold,
      blockedEvents: this.popupHistory.filter(
        (e) => e.userAction === 'blocked'
      ).length,
      totalRedirectChains: this.redirectChains.length,
      totalRedirects: this.redirectChains.reduce(
        (sum, chain) => sum + chain.totalRedirects,
        0
      ),
      averageChainLength:
        this.redirectChains.length > 0
          ? this.redirectChains.reduce((sum, chain) => sum + chain.chain.length, 0) /
            this.redirectChains.length
          : 0,
    }
  }
}

export function createPopupAnalysisPayload(
  analysis: PopupAndRedirectAnalysis
): Record<string, unknown> {
  return {
    website: analysis.website,
    popupCount: analysis.popupCount,
    popupExceeded: analysis.popupExceeded,
    redirectCount: analysis.totalRedirects,
    riskLevel: analysis.riskLevel,
    flags: analysis.flags.join(' | '),
    blockedEvents: analysis.popupDetails.filter(
      (e) => e.userAction === 'blocked'
    ).length,
    recommendedAction: analysis.shouldBlock ? 'block' : 'warn',
    timestamp: new Date().toISOString(),
  }
}
