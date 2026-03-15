import type { EmailAnalysis, EmailSnapshot } from '../types'

const EMAIL_BACKEND_URL = 'http://127.0.0.1:5000/predict'

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

function riskLabel(score: number): EmailAnalysis['final_risk_label'] {
  if (score >= 0.7) return 'dangerous'
  if (score >= 0.4) return 'suspicious'
  return 'safe'
}

function normalizeSubject(subject: string) {
  return (subject || '').toLowerCase().replace(/\s+/g, ' ').trim()
}

function getSenderDomain(data: EmailSnapshot) {
  const sender = (data.fromEmail || data.from || '').toLowerCase().trim()
  const atIndex = sender.lastIndexOf('@')
  return atIndex >= 0 ? sender.slice(atIndex + 1) : ''
}

function hasHighRiskEmailIntent(data: EmailSnapshot) {
  const text = `${data.subject || ''}\n${data.body || ''}`.toLowerCase()
  const links = Array.isArray(data.links) ? data.links : []
  const shortenerRe = /(bit\.ly|tinyurl|forms\.gle|rb\.gy|goo\.gl)/i
  const credentialRe = /\b(password|otp|pin|cvv|bank account|ssn|aadhaar|verify your account|login now|update password)\b/i
  const paymentRe = /\b(fee|payment|upi|wire transfer|crypto|bitcoin|transfer now|pay now)\b/i
  const ipUrlRe = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i

  return (
    credentialRe.test(text) ||
    paymentRe.test(text) ||
    shortenerRe.test(text) ||
    ipUrlRe.test(text) ||
    links.some((link) => shortenerRe.test(link || '') || ipUrlRe.test(link || ''))
  )
}

function isTrustedInstitutionalEmail(data: EmailSnapshot) {
  const senderDomain = getSenderDomain(data)
  if (!senderDomain) return false

  const trustedInstitutionalDomainRe = /(\.ac\.in|\.edu|\.edu\.[a-z]{2}|\.ac\.[a-z]{2}|\.edu\.in)$/i
  const trustedMailerPrefixRe = /^(mailer|mail|noreply|no-reply|notifications?)\./i
  const text = `${data.subject || ''}\n${data.body || ''}\n${data.from || ''}`.toLowerCase()
  const institutionalContextRe = /\b(internship|admission|application|confirmation|registered|registration|submission|receipt|schedule|academic|campus|student|iit|university|college|institute|department)\b/i

  const domainLooksTrusted = trustedInstitutionalDomainRe.test(senderDomain) || trustedMailerPrefixRe.test(senderDomain)
  return domainLooksTrusted && institutionalContextRe.test(text) && !hasHighRiskEmailIntent(data)
}

function isTrustedCorporateBrandEmail(data: EmailSnapshot) {
  const senderDomain = getSenderDomain(data)
  if (!senderDomain) return false

  const text = `${data.subject || ''}\n${data.body || ''}\n${data.from || ''}`.toLowerCase()
  const trustedBrands = [
    { name: 'jpmorgan chase', domains: ['jpmorganchase.com', 'chase.com'] },
    { name: 'chase', domains: ['jpmorganchase.com', 'chase.com'] },
  ]

  const matchedBrand = trustedBrands.find((brand) => {
    const mentionsBrand = text.includes(brand.name)
    const trustedSender = brand.domains.some((domain) => senderDomain === domain || senderDomain.endsWith(`.${domain}`))
    return mentionsBrand && trustedSender
  })

  if (!matchedBrand) return false

  const links = Array.isArray(data.links) ? data.links : []
  const allLinksTrusted = links.every((link) => {
    try {
      const hostname = new URL(link).hostname.toLowerCase()
      return matchedBrand.domains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))
    } catch {
      return true
    }
  })

  return allLinksTrusted && !hasHighRiskEmailIntent(data)
}

function normalizeLikelySafeInstitutionalEmail(data: EmailSnapshot, analysis: EmailAnalysis): EmailAnalysis {
  if (!isTrustedInstitutionalEmail(data)) return analysis

  const filteredPatterns = (analysis.detected_patterns || []).filter(
    (pattern) => !/urgency|sender identity risk|manipulation/i.test(pattern)
  )

  return {
    ...analysis,
    risk_label: 'safe',
    final_risk_label: 'safe',
    final_score: Math.min(analysis.final_score || 0, 0.18),
    detected_patterns: filteredPatterns,
    explanation: 'Trusted institutional confirmation-style email detected. The sender domain appears academic or organizational, and no credential, payment, or unsafe-link phishing signals were found.',
  }
}

function normalizeLikelySafeBrandEmail(data: EmailSnapshot, analysis: EmailAnalysis): EmailAnalysis {
  if (!isTrustedCorporateBrandEmail(data)) return analysis

  const filteredPatterns = (analysis.detected_patterns || []).filter(
    (pattern) => !/urgency|sender identity risk|manipulation/i.test(pattern)
  )

  return {
    ...analysis,
    risk_label: 'safe',
    final_risk_label: 'safe',
    final_score: Math.min(analysis.final_score || 0, 0.18),
    detected_patterns: filteredPatterns,
    explanation: 'Trusted branded email detected. The sender and links match official JPMorgan Chase domains, and no credential, payment-diversion, or unsafe-link phishing signals were found.',
  }
}

function normalizeLikelySafeEmail(data: EmailSnapshot, analysis: EmailAnalysis): EmailAnalysis {
  return normalizeLikelySafeBrandEmail(data, normalizeLikelySafeInstitutionalEmail(data, analysis))
}

function runLocalFallbackAnalysis(data: EmailSnapshot, reason: string): EmailAnalysis {
  const subject = (data.subject || '').toLowerCase()
  const body = (data.body || '').toLowerCase()
  const sender = (data.fromEmail || data.from || '').toLowerCase()
  const text = `${subject}\n${body}`
  const links = Array.isArray(data.links) ? data.links : []

  let score = 0.05
  const detected: string[] = []

  const shortenerRe = /(bit\.ly|tinyurl|forms\.gle|rb\.gy|goo\.gl)/i
  const urgencyRe = /\b(urgent|immediately|act now|final warning|suspended|expire|last chance|verify now)\b/i
  const rewardRe = /\b(prize|reward|bonus|gift|cash|lottery|free money|refund)\b/i
  const credentialRe = /\b(password|otp|pin|cvv|bank account|ssn|aadhaar|verify your account)\b/i
  const paymentRe = /\b(fee|payment|upi|wire transfer|crypto|bitcoin|transfer now)\b/i
  const impersonationRe = /\b(bank|government|microsoft|google|amazon|paypal|hr team|admin)\b/i
  const benignBulletinRe = /\b(holiday|circular|office closed|school closed|public holiday|notice|timetable|schedule|meeting agenda|minutes of meeting|event update|festival leave|vacation|academic calendar)\b/i
  const phishingIntentRe = /\b(verify your account|login now|update password|share otp|share pin|cvv|bank details|transfer now|pay now|claim prize now|click here now|account suspended)\b/i
  const ipUrlRe = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i
  const hasShortenedLink = shortenerRe.test(text) || links.some((link) => shortenerRe.test(link || ''))
  const hasIpLink = ipUrlRe.test(text) || links.some((link) => ipUrlRe.test(link || ''))
  const hasHighRiskIntent = phishingIntentRe.test(text) || hasShortenedLink || hasIpLink || credentialRe.test(text)
  const isBenignBulletin = benignBulletinRe.test(text)

  if (hasShortenedLink) {
    score += 0.25
    detected.push('Shortened or redirect-style link')
  }
  if (hasIpLink) {
    score += 0.25
    detected.push('IP-based URL')
  }
  if (urgencyRe.test(text)) {
    score += 0.2
    detected.push('Urgency pressure language')
  }
  if (rewardRe.test(text)) {
    score += 0.15
    detected.push('Reward or lottery bait')
  }
  if (credentialRe.test(text)) {
    score += 0.2
    detected.push('Sensitive credential request')
  }
  if (paymentRe.test(text)) {
    score += 0.2
    detected.push('Payment request signal')
  }
  if (impersonationRe.test(text) && hasHighRiskIntent) {
    score += 0.1
    detected.push('Authority or brand impersonation cues')
  }

  if (sender) {
    const freeMailRe = /@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|protonmail\.com)$/i
    const suspiciousTldRe = /\.(xyz|top|online|site|click|info)$/i

    if (freeMailRe.test(sender) && impersonationRe.test(text)) {
      score += 0.15
      detected.push('Sender and claimed brand mismatch')
    }
    if (suspiciousTldRe.test(sender)) {
      score += 0.2
      detected.push('Suspicious sender domain')
    }
  }

  if (isBenignBulletin && !hasHighRiskIntent) {
    score = Math.min(score * 0.45, 0.35)
    detected.push('Informational bulletin language')
  }

  const finalScore = clamp(score, 0, 1)
  let label = riskLabel(finalScore)
  if (label === 'dangerous' && !hasHighRiskIntent) {
    label = 'suspicious'
  }

  return normalizeLikelySafeEmail(data, {
    risk_label: label,
    final_risk_label: label,
    final_score: finalScore,
    platform: data.platform,
    detected_patterns: detected,
    explanation: `Local email analysis used (${reason}). Risk score ${Math.round(finalScore * 100)}%. ${detected.length ? `Signals: ${detected.join(', ')}.` : 'No strong scam signals detected.'}`,
    engine: 'local-fallback',
  })
}

export function getEmailHash(data: EmailSnapshot) {
  const subject = (data.subject || '').slice(0, 120)
  const body = data.body || ''
  const bodyHead = body.slice(0, 320)
  const bodyLen = body.length
  return btoa(encodeURIComponent(`${normalizeSubject(subject)}|${bodyHead}|${bodyLen}|${data.platform || ''}`))
}

export async function analyzeEmail(data: EmailSnapshot): Promise<EmailAnalysis> {
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 8000)

    const response = await fetch(EMAIL_BACKEND_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        subject: data.subject || '',
        from: data.from || '',
        fromEmail: data.fromEmail || '',
        body: data.body || '',
        links: data.links || [],
        platform: data.platform || 'gmail',
      }),
      signal: controller.signal,
    })

    clearTimeout(timeout)

    if (!response.ok) {
      return runLocalFallbackAnalysis(data, `backend error ${response.status}`)
    }

    const result = await response.json()
    const label = result.final_risk_label || result.risk_label
    if (!label) {
      return runLocalFallbackAnalysis(data, 'invalid backend response')
    }

    return normalizeLikelySafeEmail(data, {
      risk_label: result.risk_label || label,
      final_risk_label: result.final_risk_label || label,
      final_score: typeof result.final_score === 'number' ? result.final_score : 0,
      platform: result.platform || data.platform,
      explanation: result.explanation || 'Email analysis completed.',
      detected_patterns: Array.isArray(result.detected_patterns) ? result.detected_patterns : [],
      engine: 'remote-ml',
    })
  } catch (error) {
    return runLocalFallbackAnalysis(data, error instanceof Error ? error.message : 'backend unavailable')
  }
}
