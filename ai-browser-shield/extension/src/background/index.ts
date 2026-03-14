import { scoreUrl } from '../detection/urlScorer'
import { assessPageContext, getRiskLevel, hasSensitiveContent } from '../detection/pageScorer'
import { trackRedirect, resetTab } from '../detection/redirectTracker'
import { checkDownload } from '../detection/downloadChecker'
import { saveThreatEvent, setDomainScore } from './storage'
import { scanUrl, scanFile } from '../api/client'
import type { EmailAnalysis, EmailScanInput, PageContextSnapshot } from '../types'

// URL Analysis
async function analyzeUrl(tabId: number, url: string) {
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) return

  let parsedUrl: URL
  try { parsedUrl = new URL(url) } catch { return }
  const hostname = parsedUrl.hostname

  const { score, signals } = scoreUrl(url)
  const pageContext = await getPageContext(tabId)
  const pageAssessment = assessPageContext(parsedUrl, pageContext)
  const effectiveScore = Math.max(score, pageAssessment.score)
  const effectiveRiskLevel = getRiskLevel(effectiveScore)
  const aiSignals = pageAssessment.score > 0
    ? { ...signals, pageContextRisk: pageAssessment.score }
    : signals

  const colors: Record<string, string> = { LOW: '#166534', MEDIUM: '#B45309', HIGH: '#DC2626', CRITICAL: '#7F1D1D' }
  chrome.action.setBadgeBackgroundColor({ color: colors[effectiveRiskLevel], tabId })
  chrome.action.setBadgeText({ text: effectiveRiskLevel === 'LOW' ? 'OK' : effectiveScore.toString(), tabId })

  // Keep the popup in sync even for low-risk sites.
  await setDomainScore(hostname, effectiveScore)

  const shouldUseAi =
    effectiveScore >= 45 ||
    pageAssessment.score >= 20 ||
    (effectiveScore >= 20 && !!pageContext) ||
    (!!pageContext && hasSensitiveContent(pageContext))

  if (effectiveScore < 30 && !shouldUseAi) return

  let aiExplanation = pageAssessment.explanation || getFallbackExplanation(effectiveScore)
  let recommendedAction: 'allow' | 'warn' | 'block' = effectiveScore >= 80 ? 'block' : 'warn'

  if (shouldUseAi) {
    const result = await scanUrl(url, aiSignals, pageContext)
    aiExplanation = result?.explanation || aiExplanation
    recommendedAction = result?.recommendedAction || recommendedAction
  } else if (pageContext && hasSensitiveContent(pageContext)) {
    aiExplanation = 'This page asks for sensitive information or uses suspicious account-verification language. Double-check the site before entering anything.'
    recommendedAction = 'warn'
  }

  chrome.tabs.sendMessage(tabId, {
    type: 'SHOW_OVERLAY',
    payload: { url, score: effectiveScore, riskLevel: effectiveRiskLevel, explanation: aiExplanation, recommendedAction }
  }).catch(() => {})

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'url_threat',
    domain: hostname,
    url,
    riskScore: effectiveScore,
    riskLevel: effectiveRiskLevel,
    aiExplanation,
    timestamp: Date.now()
  })
}

async function getPageContext(tabId: number): Promise<PageContextSnapshot | null> {
  try {
    return await chrome.tabs.sendMessage(tabId, { type: 'GET_PAGE_CONTEXT' })
  } catch {
    return null
  }
}

function getFallbackExplanation(score: number): string {
  if (score >= 80) return 'This website shows multiple high-risk signals. We strongly recommend leaving immediately.'
  if (score >= 60) return 'This website has several suspicious characteristics. Be very cautious with any personal information.'
  return 'This website has unusual patterns. Proceed with caution.'
}

// Navigation listeners
chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return
  resetTab(tabId)
  analyzeUrl(tabId, url)
})

chrome.webNavigation.onCommitted.addListener(({ tabId, url, frameId, transitionQualifiers }) => {
  if (frameId !== 0) return
  if (transitionQualifiers.includes('server_redirect') || transitionQualifiers.includes('client_redirect')) {
    const { exceeded, count, urls } = trackRedirect(tabId, url)
    if (exceeded) {
      chrome.tabs.sendMessage(tabId, { type: 'REDIRECT_WARNING', payload: { count, urls, url } }).catch(() => {})
      saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'redirect_chain',
        domain: (() => { try { return new URL(url).hostname } catch { return 'unknown' } })(),
        url,
        riskScore: 70,
        riskLevel: 'HIGH',
        aiExplanation: `This link bounced through ${count} websites. Attackers use redirect chains to hide the true destination.`,
        timestamp: Date.now()
      })
    }
  }
})

// Download intercept (before file is written)
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  const risk = checkDownload(item.filename, item.mime, item.url)
  if (risk.level === 'safe') { suggest({}); return }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: 'DOWNLOAD_WARNING',
        payload: { filename: item.filename, risk, url: item.url, downloadId: item.id }
      }).catch(() => {})
    }
  })

  saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'download_intercept',
    domain: (() => { try { return new URL(item.url).hostname } catch { return item.url } })(),
    url: item.url,
    riskScore: risk.level === 'high' ? 85 : 50,
    riskLevel: risk.level === 'high' ? 'HIGH' : 'MEDIUM',
    aiExplanation: risk.reason,
    timestamp: Date.now()
  })

  if (risk.level === 'high') {
    chrome.downloads.cancel(item.id)
  } else {
    suggest({})
  }
})

// Post-download AI file scan
chrome.downloads.onChanged.addListener(async (delta) => {
  if (delta.state?.current !== 'complete') return
  const [item] = await chrome.downloads.search({ id: delta.id })
  if (!item?.filename) return

  const ext = '.' + (item.filename.split('.').pop()?.toLowerCase() || 'bin')
  const result = await scanFile({
    filename: item.filename.split(/[\\/]/).pop() || item.filename,
    extension: ext,
    mimeType: item.mime || 'application/octet-stream',
    sizeBytes: item.fileSize || 0,
    sourceUrl: item.url,
  })
  if (!result) return

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'file_scan',
    domain: (() => { try { return new URL(item.url).hostname } catch { return 'unknown' } })(),
    url: item.url,
    riskScore: result.verdict === 'MALICIOUS' ? 95 : result.verdict === 'SUSPICIOUS' ? 60 : 5,
    riskLevel: result.verdict === 'MALICIOUS' ? 'CRITICAL' : result.verdict === 'SUSPICIOUS' ? 'HIGH' : 'LOW',
    aiExplanation: result.explanation,
    verdict: result.verdict,
    timestamp: Date.now()
  })

  if (result.verdict !== 'SAFE') {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: '/icon48.png',
      title: result.verdict === 'MALICIOUS' ? '🚨 Malicious File Detected!' : '⚠️ Suspicious Download',
      message: result.explanation.slice(0, 150),
      priority: result.verdict === 'MALICIOUS' ? 2 : 1,
    })
  }
})

// Unified message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const senderDomain = (() => { try { return new URL(sender.url || '').hostname } catch { return 'unknown' } })()

  if (message.type === 'EMAIL_CONTENT_UPDATE') {
    const data = message.payload as EmailScanInput
    const tabId = sender.tab?.id
    if (!tabId) {
      sendResponse({ ok: false })
      return true
    }

    chrome.storage.local.set({ processingState: true })
    chrome.tabs.sendMessage(tabId, {
      type: 'EMAIL_ANALYSIS_RESULT',
      payload: {
        riskLabel: 'processing',
        finalScore: 0,
        explanation: 'Analyzing this message for phishing and scam signals...',
        platform: data.platform,
        detectedPatterns: [],
        subject: data.subject,
        from: data.from || data.fromEmail || data.platform,
        timestamp: Date.now(),
      } satisfies EmailAnalysis,
    }).catch(() => {})

    analyzeEmailContent(data).then(async (analysis) => {
      const stabilized = stabilizeEmailPrediction(tabId, data, analysis)
      emailPredictionCache.set(tabId, { hash: emailHash(data), result: stabilized })
      await chrome.storage.local.set({
        latestEmailAnalysis: stabilized,
        currentAnalysis: stabilized,
        ['emailAnalysis:' + tabId]: stabilized,
        processingState: false,
      })

      if (stabilized.riskLabel === 'suspicious' || stabilized.riskLabel === 'dangerous') {
        await saveThreatEvent({
          id: crypto.randomUUID(),
          eventType: 'email_phishing',
          domain: data.platform,
          url: sender.url || data.platform,
          riskScore: Math.round(stabilized.finalScore * 100),
          riskLevel: stabilized.riskLabel === 'dangerous' ? 'CRITICAL' : 'MEDIUM',
          aiExplanation: stabilized.explanation,
          timestamp: Date.now(),
        })
      }

      chrome.tabs.sendMessage(tabId, {
        type: 'EMAIL_ANALYSIS_RESULT',
        payload: stabilized,
      }).catch(() => {})
    })

    sendResponse({ ok: true, status: 'processing' })
    return true
  }

  if (message.type === 'POPUP_ATTEMPT') {
    saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'popup_abuse',
      domain: senderDomain,
      url: sender.url || '',
      riskScore: 55,
      riskLevel: 'MEDIUM',
      aiExplanation: `This site tried to open ${message.payload?.count || 'multiple'} popups. Excessive popups are a common scam tactic.`,
      timestamp: Date.now()
    })
    sendResponse({ blocked: true })
    return true
  }

  if (message.type === 'OPEN_REPORT_FORM') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?tab=report' })
    return true
  }

  if (message.type === 'CANCEL_DOWNLOAD') {
    chrome.downloads.cancel(message.payload.downloadId)
    return true
  }

  return true
})

chrome.tabs.onRemoved.addListener((tabId) => resetTab(tabId))

const EMAIL_BACKEND_URL = 'http://127.0.0.1:5000/predict'
const emailPredictionCache = new Map<number, { hash: string; result: EmailAnalysis }>()
const lastEmailRiskByKey = new Map<string, { label: EmailAnalysis['riskLabel']; result: EmailAnalysis; ts: number }>()

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n))
}

function emailHash(data: EmailScanInput): string {
  return JSON.stringify({
    s: data.subject.slice(0, 120),
    b: data.body.slice(0, 320),
    l: data.links.slice(0, 8),
    p: data.platform,
  })
}

function emailRiskRank(label: EmailAnalysis['riskLabel']): number {
  if (label === 'dangerous') return 3
  if (label === 'suspicious') return 2
  if (label === 'safe') return 1
  return 0
}

function stabilizeEmailPrediction(tabId: number, data: EmailScanInput, analysis: EmailAnalysis): EmailAnalysis {
  const key = `${tabId}:${(data.subject || '').toLowerCase().replace(/\s+/g, ' ').trim()}`
  const prev = lastEmailRiskByKey.get(key)
  const now = Date.now()

  if (prev) {
    const prevRank = emailRiskRank(prev.label)
    const incomingRank = emailRiskRank(analysis.riskLabel)
    const ageMs = now - prev.ts
    const bodyLen = (data.body || '').trim().length

    if (prevRank > incomingRank && ageMs < 45000 && bodyLen < 180) {
      return {
        ...prev.result,
        explanation: `${prev.result.explanation} Kept the higher-risk result while the message content was still stabilizing.`.trim(),
      }
    }
  }

  lastEmailRiskByKey.set(key, { label: analysis.riskLabel, result: analysis, ts: now })
  return analysis
}

function buildEmailFallback(data: EmailScanInput, reason: string): EmailAnalysis {
  const text = `${data.subject}\n${data.body}`.toLowerCase()
  const links = data.links || []
  let score = 0.05
  const patterns: string[] = []

  const shortenerRe = /(bit\.ly|tinyurl|forms\.gle|t\.me|wa\.me|rb\.gy|goo\.gl)/i
  const urgencyRe = /\b(urgent|immediately|act now|final warning|suspended|expire|last chance|verify now)\b/i
  const rewardRe = /\b(prize|reward|bonus|gift|cash|lottery|free money|refund)\b/i
  const credentialRe = /\b(password|otp|pin|cvv|bank account|ssn|aadhaar|verify your account)\b/i
  const paymentRe = /\b(fee|payment|upi|wire transfer|crypto|bitcoin|transfer now)\b/i
  const impersonationRe = /\b(bank|government|microsoft|google|amazon|admin|hr team)\b/i
  const benignBulletinRe = /\b(holiday|circular|office closed|notice|timetable|schedule|meeting agenda|minutes of meeting|event update|vacation|academic calendar)\b/i
  const ipUrlRe = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i

  const hasShortener = shortenerRe.test(text) || links.some(link => shortenerRe.test(link))
  const hasIpLink = ipUrlRe.test(text) || links.some(link => ipUrlRe.test(link))
  const hasHighRiskIntent = credentialRe.test(text) || paymentRe.test(text) || urgencyRe.test(text) || hasShortener || hasIpLink
  const isBenignBulletin = benignBulletinRe.test(text)

  if (hasShortener) { score += 0.25; patterns.push('Shortened links') }
  if (hasIpLink) { score += 0.25; patterns.push('IP-based URL') }
  if (urgencyRe.test(text)) { score += 0.2; patterns.push('Urgency language') }
  if (rewardRe.test(text)) { score += 0.15; patterns.push('Reward bait') }
  if (credentialRe.test(text)) { score += 0.2; patterns.push('Credential request') }
  if (paymentRe.test(text)) { score += 0.2; patterns.push('Payment request') }
  if (impersonationRe.test(text) && hasHighRiskIntent) { score += 0.1; patterns.push('Brand impersonation') }

  if (isBenignBulletin && !hasHighRiskIntent) {
    score = Math.min(score * 0.45, 0.35)
    patterns.push('Informational bulletin language')
  }

  const finalScore = clamp(score, 0, 1)
  const riskLabel = finalScore >= 0.7 && hasHighRiskIntent
    ? 'dangerous'
    : finalScore >= 0.4
      ? 'suspicious'
      : 'safe'

  return {
    riskLabel,
    finalScore,
    explanation: `Local analysis used (${reason}). Risk score ${Math.round(finalScore * 100)}%. ${patterns.length ? `Signals: ${patterns.join(', ')}.` : 'No strong scam signals detected.'}`,
    platform: data.platform,
    detectedPatterns: patterns,
    subject: data.subject,
    from: data.from || data.fromEmail || data.platform,
    timestamp: Date.now(),
  }
}

async function analyzeEmailContent(data: EmailScanInput): Promise<EmailAnalysis> {
  const hash = emailHash(data)
  const tabHash = Array.from(emailPredictionCache.entries()).find(([, value]) => value.hash === hash)?.[1]
  if (tabHash) return tabHash.result

  try {
    const res = await fetch(EMAIL_BACKEND_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(data),
    })

    if (!res.ok) {
      return buildEmailFallback(data, `backend error ${res.status}`)
    }

    const result = await res.json()
    return {
      riskLabel: result.final_risk_label || result.risk_label || 'safe',
      finalScore: typeof result.final_score === 'number' ? result.final_score : 0,
      explanation: result.explanation || 'No explanation available.',
      platform: result.platform || data.platform,
      detectedPatterns: Array.isArray(result.detected_patterns) ? result.detected_patterns : [],
      subject: data.subject,
      from: data.from || data.fromEmail || data.platform,
      timestamp: Date.now(),
    }
  } catch (error) {
    return buildEmailFallback(data, error instanceof Error ? error.message : 'backend unavailable')
  }
}
