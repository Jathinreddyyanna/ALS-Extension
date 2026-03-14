import type { PageContextSnapshot, RiskLevel } from '../types'

export interface PageAssessment {
  score: number
  explanation: string
}

function isGoogleOwnedHostname(hostname: string): boolean {
  const GOOGLE_TRUSTED_DOMAINS = [
    'google.com',
    'gmail.com',
    'classroom.google.com',
    'notifications.google.com',
    'accounts.google.com',
    'googleusercontent.com',
    'gstatic.com',
  ]
  const normalized = hostname.toLowerCase()
  return GOOGLE_TRUSTED_DOMAINS.some(domain => normalized === domain || normalized.endsWith(`.${domain}`))
}

export function assessPageContext(url: URL, pageContext: PageContextSnapshot | null): PageAssessment {
  let score = 0
  const reasons: string[] = []
  const hostname = url.hostname.toLowerCase()
  const isTrustedGoogleHost = isGoogleOwnedHostname(hostname)
  const content = pageContext
    ? [
        pageContext.title,
        pageContext.bodyPreview,
        ...pageContext.headings,
        ...pageContext.formSignals,
        ...pageContext.actionTexts,
      ].join(' ').toLowerCase()
    : ''

  const vulnTerms = ['xss', 'sql injection', 'csrf', 'command injection', 'directory traversal', 'bugs', 'vulnerable', 'exploit', 'attack lab', 'security test']
  if (content && vulnTerms.some(term => content.includes(term))) {
    score += 35
    reasons.push('This page appears to discuss or demonstrate web security vulnerabilities.')
  }

  const demoHostTerms = ['vulnweb', 'testphp', 'testfire', 'zero.webappsecurity', 'demo.testfire', 'itsecgames']
  if (demoHostTerms.some(term => hostname.includes(term))) {
    score += 35
    reasons.push('This site matches a known security testing or intentionally vulnerable demo environment.')
  }

  const demoContentTerms = [
    'test and demonstration site',
    'web vulnerability scanner',
    'security testing',
    'intentionally vulnerable',
    'demo application',
    'training site',
    'web security',
  ]
  if (content && demoContentTerms.some(term => content.includes(term))) {
    score += 25
    reasons.push('The page content suggests this is a demo or security-testing environment.')
  }

  const urgencyTerms = ['urgent', 'immediately', 'suspended', 'verify now', 'act now', 'limited time', 'confirm now']
  const authTerms = ['sign in', 'log in', 'verify your account', 'password', 'credential', '2fa', 'security check']
  const paymentTerms = ['billing', 'payment', 'credit card', 'debit card', 'wallet', 'seed phrase', 'bank account']
  const fakeSupportTerms = ['tech support', 'call now', 'microsoft support', 'virus detected', 'your device is infected']
  const brandMismatchTerms = ['google', 'microsoft', 'paypal', 'amazon', 'apple', 'bank', 'netflix', 'facebook', 'instagram']

  if (content && authTerms.some(term => content.includes(term))) {
    score += 20
    reasons.push('The page asks for account or credential-related information.')
  }

  if (content && paymentTerms.some(term => content.includes(term))) {
    score += 20
    reasons.push('The page requests payment or financial information.')
  }

  if (content && urgencyTerms.some(term => content.includes(term))) {
    score += 10
    reasons.push('The page uses urgency language to pressure action.')
  }

  if (content && fakeSupportTerms.some(term => content.includes(term))) {
    score += 20
    reasons.push('The page resembles a fake support or scareware flow.')
  }

  if (content && brandMismatchTerms.some(term => content.includes(term)) && !brandMismatchTerms.some(term => hostname.includes(term))) {
    score += 15
    reasons.push('The page references major brands, but the domain does not match those brands.')
  }

  const passwordLikeForms = (pageContext?.formSignals || []).filter(signal =>
    ['password', 'passcode', 'otp', 'card', 'cvv', 'wallet', 'seed'].some(term => signal.toLowerCase().includes(term))
  )
  if (passwordLikeForms.length > 0) {
    score += 15
    reasons.push('The page contains sensitive input fields.')
  }

  if (url.protocol === 'http:') {
    score += 15
    reasons.push('It is being served over insecure HTTP rather than HTTPS.')
  }

  const pageSignals = pageContext?.pageSignals
  if (pageSignals) {
    if (pageSignals.sensitiveFieldCount >= 2) {
      score += Math.min(20, pageSignals.sensitiveFieldCount * 5)
      reasons.push('The page asks for multiple sensitive credentials or payment details.')
    }
    if (pageSignals.hiddenSensitiveFieldCount > 0 || pageSignals.hiddenFormCount > 0) {
      score += 20
      reasons.push('The page contains hidden forms or concealed sensitive fields.')
    }
    if (pageSignals.externalFormActionCount > 0) {
      score += Math.min(25, pageSignals.externalFormActionCount * 12)
      reasons.push('A form submits data to another website, which is a common phishing technique.')
    }
    if (pageSignals.insecureFormActionCount > 0) {
      score += 15
      reasons.push('A form posts data over insecure HTTP.')
    }
    if (pageSignals.loginButtonCount >= 3) {
      score += 10
      reasons.push('The page shows an unusual number of login or verification buttons.')
    }
    if (pageSignals.brandMismatchCount > 0) {
      score += Math.min(20, pageSignals.brandMismatchCount * 10)
      reasons.push('The page branding appears inconsistent with the current domain.')
    }
    if (pageSignals.suspiciousScriptCount >= 2) {
      score += Math.min(15, pageSignals.suspiciousScriptCount * 4)
      reasons.push('The page runs scripts associated with redirects, ad abuse, or injected content.')
    }
    if (pageSignals.autoRedirectHintCount > 0 || pageSignals.metaRefreshCount > 0) {
      score += Math.min(20, pageSignals.autoRedirectHintCount * 4 + pageSignals.metaRefreshCount * 10)
      reasons.push('The page contains auto-redirect behavior or refresh-based navigation tricks.')
    }
  }

  const popupSignals = pageContext?.popupSignals
  if (popupSignals) {
    const overlayThreshold = isTrustedGoogleHost ? 4 : 2
    const newWindowThreshold = isTrustedGoogleHost ? 6 : 3
    const iframeThreshold = isTrustedGoogleHost ? 20 : 12
    const externalLinkThreshold = isTrustedGoogleHost ? 40 : 25

    if (popupSignals.fixedOverlayCount >= overlayThreshold) {
      score += Math.min(30, popupSignals.fixedOverlayCount * 8)
      reasons.push('The page is showing multiple aggressive fixed overlays or fake popups.')
    }
    if (popupSignals.newWindowHints >= newWindowThreshold) {
      score += Math.min(20, popupSignals.newWindowHints * 4)
      reasons.push('The page contains many links or handlers that open new windows.')
    }
    if (popupSignals.iframeCount >= iframeThreshold) {
      score += 10
      reasons.push('The page loads an unusually high number of embedded frames, which is common on ad-abuse sites.')
    }
    if (popupSignals.externalLinkCount >= externalLinkThreshold) {
      score += 10
      reasons.push('The page contains a large number of external links, which can indicate redirect or ad-spam behavior.')
    }
  }

  if (isTrustedGoogleHost) {
    score = Math.min(score, 25)
  }

  return {
    score: Math.min(100, score),
    explanation: reasons.join(' '),
  }
}

export function hasSensitiveContent(pageContext: PageContextSnapshot): boolean {
  const content = [
    pageContext.title,
    pageContext.bodyPreview,
    ...pageContext.headings,
    ...pageContext.formSignals,
    ...pageContext.actionTexts,
  ].join(' ').toLowerCase()

  return ['password', 'verify your account', 'sign in', 'log in', 'wallet', 'seed phrase', 'payment', 'bank'].some(term => content.includes(term))
}

export function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}
