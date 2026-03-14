import { scoreUrl } from '../detection/urlScorer'
import { assessPageContext, getRiskLevel, hasSensitiveContent } from '../detection/pageScorer'
import { trackRedirect, resetTab } from '../detection/redirectTracker'
import { checkDownload } from '../detection/downloadChecker'
import { saveThreatEvent, setDomainScore } from './storage'
import { scanUrl, scanFile } from '../api/client'
import type { PageContextSnapshot } from '../types'

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
