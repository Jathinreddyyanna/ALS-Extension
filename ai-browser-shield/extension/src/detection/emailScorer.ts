export type EmailRiskLabel = 'safe' | 'suspicious' | 'dangerous'

export interface EmailScoreResult {
  riskScore: number
  riskLabel: EmailRiskLabel
  detectedSignals: string[]
  confidence: number
  explanation: string
  attackType: string
  isSpamFolder: boolean
  signals: Array<{ name: string; score: number }>
}

const MAX_ANALYSIS_CHARS = 6000

const SPAM_KEYWORDS = [
  'urgent', 'immediate', 'immediately', 'final notice', 'last chance',
  'act now', 'limited time', 'account blocked', 'account suspended',
  'action required', 'verify immediately', 'verify account', 'login now',
  'update details', 'reset password', 'confirm account', 'unauthorized access',
  'security alert', 'bank account', 'upi', 'atm', 'credit card', 'debit card',
  'kyc', 'otp', 'transaction failed', 'click link', 'click here', 'click below',
  'winner', 'lottery', 'prize', 'reward', 'free gift', 'free money',
  'instant loan', 'quick loan', 'pre-approved', 'no cibil',
  'bitcoin', 'crypto', 'high return', 'investment plan',
  'parcel on hold', 'delivery failed', 'customs clearance',
  'virus detected', 'remote access', 'system infected',
  'government scheme', 'subsidy', 'grant approved', 'relief fund',
  'registration fee', 'shortlisted', 'google form',
]

const HAM_KEYWORDS = [
  'regards', 'sincerely', 'best wishes', 'official email',
  'privacy policy', 'terms of service', 'invoice attached',
  'payment receipt', 'transaction receipt', 'meeting', 'schedule',
  'assignment submission', 'hall ticket', 'semester', 'attendance',
]

const URGENCY = ['urgent', 'immediate', 'immediately', 'act now', 'final notice', 'last chance', 'limited time', 'action required', 'verify immediately']
const AUTHORITY = ['rbi', 'hdfc', 'sbi', 'irctc', 'aadhaar', 'upi', 'government', 'official', 'security alert', 'bank']
const FEAR = ['account blocked', 'account suspended', 'unauthorized access', 'transaction failed', 'system infected', 'virus detected']
const SCARCITY = ['limited time', 'limited offer', 'last chance', 'exclusive offer', 'final notice']

const TRUSTED_DOMAINS = [
  'kotak.com',
  'hdfcbank.com',
  'sbi.co.in',
  'irctc.co.in',
  'amazon.in',
  'paytm.com',
  'flipkart.com',
  'uber.com',
  'internshala.com',
  'linkedin.com',
  'naukri.com',
  'glassdoor.com',
  'indeed.com',
  'letsintern.com',
]

const SUSPICIOUS_LINKS = [
  'bit.ly',
  'tinyurl',
  'verify-account',
  'login-secure',
  'update-kyc',
  'confirm-identity',
  'validate-account',
  'below link',
  'click the link',
  'google form',
  'click below',
  'earn money',
  'claim reward',
]

const MONEY_BAIT_PATTERNS = [
  /(?:rs\.?|₹|inr)\s*\d+/i,
  /earn\s*\d+/i,
  /get\s*(?:rs\.?|₹|inr)\s*\d+/i,
  /rewarded\s*(?:rs\.?|₹|inr)?\s*\d+/i,
  /credited\s*to\s*your\s*account/i,
]

const JOB_SCAM_PATTERNS = [
  /internship/i,
  /stipend/i,
  /per\s*month/i,
  /work\s*from\s*home/i,
  /registration\s*fee/i,
  /offer\s*letter/i,
  /shortlisted/i,
  /campus\s*drive/i,
  /hr\s*team/i,
]

const OBVIOUSLY_FAKE_DOMAINS = [
  'tempmail', 'throwaway', 'guerrillamail', 'mailinator',
  '10minutemail', 'yopmail', 'sharklasers', 'fakeinbox', 'trashmail',
]

const SUSPICIOUS_TLDS_LIST = ['.xyz', '.tk', '.top', '.ml', '.gq']

function checkSenderReputation(senderEmail: string): number {
  if (!senderEmail) return 0

  const domain = senderEmail.toLowerCase().split('@')[1] || ''

  if (OBVIOUSLY_FAKE_DOMAINS.some((fake) => domain.includes(fake))) {
    return 50
  }

  if (TRUSTED_DOMAINS.some((trusted) => domain.includes(trusted))) {
    return -40 // Increased penalty for trusted domains
  }

  if (SUSPICIOUS_TLDS_LIST.some((tld) => domain.endsWith(tld))) {
    return 40
  }

  return 0
}

function checkLinks(emailText: string): number {
  const lowerText = emailText.toLowerCase()
  for (const link of SUSPICIOUS_LINKS) {
    if (lowerText.includes(link)) return 25
  }
  return 0
}

function checkUrgency(emailText: string): number {
  const urgencyWords = ['urgent', 'immediately', 'account suspended', 'verify now', 'action required']
  const lowerText = emailText.toLowerCase()
  let score = 0
  for (const word of urgencyWords) {
    if (lowerText.includes(word)) score += 10
  }
  return Math.min(score, 50)
}

function checkBrandMismatch(senderEmail: string, emailText: string): number {
  if (!senderEmail) return 0

  const lowerText = emailText.toLowerCase()
  const senderLower = senderEmail.toLowerCase()
  const brands = ['amazon', 'paypal', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'hdfc', 'sbi', 'icici', 'internshala']

  for (const brand of brands) {
    if (lowerText.includes(brand) && !senderLower.includes(brand)) {
      return 25
    }
  }

  return 0
}

function checkJobScam(emailText: string): number {
  const text = emailText.toLowerCase()
  const hits = JOB_SCAM_PATTERNS.filter((pattern) => pattern.test(text)).length

  const hasJobTerms = /internship|stipend|job|hiring|career|offer letter/.test(text)
  const hasLureAmount = /(?:₹|rs\.?\s*)\s*\d+/i.test(text) || /\b\d+\s*k\b/i.test(text)
  const hasActionBait = /click|apply now|fill form|verify|submit details|registration/i.test(text)
  const hasSensitiveAsk = /otp|password|cvv|upi|bank account|aadhaar|pan|card details/i.test(text)
  const hasDeadlinePressure = /urgent|limited time|24 hours|final notice|last chance/i.test(text)
  const hasFeeAsk = /registration fee|processing fee|security deposit|pay now|advance payment/i.test(text)

  // Do not penalize normal career mails that only mention internship/jobs.
  if (!hasJobTerms) return 0
  if (!hasSensitiveAsk && !hasFeeAsk && !hasActionBait && !hasDeadlinePressure && hits < 2) {
    return 0
  }

  let score = 0
  score += Math.min(12, hits * 4)
  if (hasLureAmount) score += 8
  if (hasActionBait) score += 8
  if (hasSensitiveAsk) score += 14
  if (hasFeeAsk) score += 12
  if (hasDeadlinePressure) score += 6

  return Math.min(40, score)
}

function inferAttackType(text: string, indianBrand: string, riskLabel: EmailRiskLabel): string {
  if (text.includes('loan') || text.includes('investment')) return 'Financial Fraud'
  if (text.includes('password') || text.includes('otp') || text.includes('verify')) return 'Credential Harvesting'
  if (text.includes('lottery') || text.includes('prize')) return 'Lottery Scam'
  if (text.includes('delivery') || text.includes('parcel')) return 'Delivery Scam'
  if (text.includes('internship') || text.includes('stipend') || text.includes('registration fee')) return 'Job Scam'
  if (indianBrand !== 'None') return 'Brand Impersonation'
  if (riskLabel !== 'safe') return 'Phishing Attempt'
  return 'None'
}

export function scoreEmail(emailText: string, senderEmail: string = '', isSpamFolder: boolean = false): EmailScoreResult {
  const boundedEmailText = emailText.slice(0, MAX_ANALYSIS_CHARS)
  const text = boundedEmailText.toLowerCase()

  if (!senderEmail) {
    const fromMatch = boundedEmailText.match(/From:?\s*([^\n<]+?)(?:<|$|\n)/i)
    if (fromMatch) {
      const parsed = fromMatch[1].trim()
      const emailMatch = parsed.match(/[\w.-]+@[\w.-]+\.\w+/)
      if (emailMatch) senderEmail = emailMatch[0]
    }
  }

  const spamHits = SPAM_KEYWORDS.filter((keyword) => text.includes(keyword))
  const hamHits = HAM_KEYWORDS.filter((keyword) => text.includes(keyword))

  const triggers: { type: string; evidence: string }[] = []
  URGENCY.forEach((keyword) => { if (text.includes(keyword)) triggers.push({ type: 'URGENCY', evidence: keyword }) })
  AUTHORITY.forEach((keyword) => { if (text.includes(keyword)) triggers.push({ type: 'AUTHORITY', evidence: keyword }) })
  FEAR.forEach((keyword) => { if (text.includes(keyword)) triggers.push({ type: 'FEAR', evidence: keyword }) })
  SCARCITY.forEach((keyword) => { if (text.includes(keyword)) triggers.push({ type: 'SCARCITY', evidence: keyword }) })

  const brands = ['hdfc', 'sbi', 'irctc', 'aadhaar', 'paytm', 'upi', 'npci', 'rbi']
  const indianBrand = brands.find((brand) => text.includes(brand))?.toUpperCase() || 'None'

  let riskScore = 0
  const signals: Array<{ name: string; score: number }> = []

  const spamScore = Math.min(70, spamHits.length * 8)
  riskScore += spamScore
  signals.push({ name: 'Spam keywords', score: spamScore })

  const triggerScore = Math.min(20, triggers.length * 5)
  riskScore += triggerScore
  signals.push({ name: 'Psychological triggers', score: triggerScore })

  const brandScore = indianBrand !== 'None' ? 10 : 0
  riskScore += brandScore
  signals.push({ name: 'Brand impersonation', score: brandScore })

  const senderRepScore = checkSenderReputation(senderEmail)
  riskScore += senderRepScore
  signals.push({ name: 'Sender reputation', score: senderRepScore })

  const linkScore = checkLinks(boundedEmailText)
  riskScore += linkScore
  signals.push({ name: 'Suspicious links', score: linkScore })

  const urgencyScore = checkUrgency(boundedEmailText)
  riskScore += urgencyScore
  signals.push({ name: 'Urgency language', score: urgencyScore })

  const brandMismatchScore = checkBrandMismatch(senderEmail, boundedEmailText)
  riskScore += brandMismatchScore
  signals.push({ name: 'Brand mismatch', score: brandMismatchScore })

  const spamFolderBoost = isSpamFolder ? 40 : 0
  riskScore += spamFolderBoost
  signals.push({ name: 'Gmail spam folder', score: spamFolderBoost })

  const jobScamScore = checkJobScam(boundedEmailText)
  riskScore += jobScamScore
  signals.push({ name: 'Job scam pattern', score: jobScamScore })

  // 💰 Money/Cash Reward Bait Check
  const hasMoneyBait = MONEY_BAIT_PATTERNS.some(p => p.test(text))
  const hasLinkBait = /click\s*below|below\s*link|claim\s*now|get\s*it\s*now/i.test(text)
  if (hasMoneyBait && hasLinkBait) {
    riskScore += 45 // Very aggressive boost for "Cash lure + Click link"
    signals.push({ name: 'Financial reward bait', score: 45 })
  }

  const hamPenalty = Math.min(30, hamHits.length * 5)
  riskScore -= hamPenalty
  signals.push({ name: 'Ham indicators', score: -hamPenalty })

  riskScore = Math.min(100, Math.max(0, riskScore))

  // 🛡️ Two-Level Evaluation Logic
  // Level 1: Mapping local riskScore to 3-tier labels
  // Currently: > 60 is dangerous, 26-60 is suspicious, 0-25 is safe.
  const riskLabel: EmailRiskLabel = riskScore > 60 ? 'dangerous' : riskScore > 25 ? 'suspicious' : 'safe'
  const positiveSignals = signals.filter((signal) => signal.score > 5).length
  const confidence = Math.max(0, Math.min(100, Math.round((positiveSignals / Math.max(1, signals.length)) * 100 + (riskScore / 100) * 30)))
  const attackType = inferAttackType(text, indianBrand, riskLabel)

  const detectedSignals = [
    ...new Set([
      ...triggers.map((trigger) => trigger.evidence),
      ...signals.filter((signal) => signal.score > 0).map((signal) => signal.name),
    ]),
  ].slice(0, 12)

  // Level 1: Heuristic-based explanation for non-technical users
  const explanation = generateLevel1Explanation(riskScore, riskLabel, signals)

  return {
    riskScore,
    riskLabel,
    detectedSignals,
    confidence,
    explanation,
    attackType,
    isSpamFolder,
    signals,
  }
}

/**
 * 🛡️ Level 1 Evaluation Explanation
 * Focuses on immediate heuristic triggers while preserving the core scoring logic.
 */
function generateLevel1Explanation(score: number, label: EmailRiskLabel, signals: any[]): string {
  if (label === 'safe') {
    return 'This email appears safe based on local heuristic rules. No immediate threats detected.'
  }

  const majorSignals = signals
    .filter((s) => s.score >= 20)
    .map((s) => s.name.toLowerCase())
    .slice(0, 2)

  if (label === 'dangerous') {
    return `HIGH RISK: This email is identified as DANGEROUS (${score}/100). Major triggers: ${majorSignals.join(', ') || 'multiple phishing patterns'}. Do not interact with links or attachments.`
  }

  return `CAUTION: This email is SUSPICIOUS (${score}/100). Found signs of ${majorSignals.length > 0 ? majorSignals[0] : 'manipulation indicators'}. Use the "Deep Scan" feature if you aren't certain.`
}
