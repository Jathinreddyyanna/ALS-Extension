import type { PageContextSnapshot, RiskLevel } from '../types'

export interface PageAssessment {
  score: number
  explanation: string
}

export function assessPageContext(url: URL, pageContext: PageContextSnapshot | null): PageAssessment {
  let score = 0
  const reasons: string[] = []
  const hostname = url.hostname.toLowerCase()
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
