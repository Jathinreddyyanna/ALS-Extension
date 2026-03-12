import { scoreUrl } from '../detection/urlScorer'
import { trackRedirect, resetTab } from '../detection/redirectTracker'
import { checkDownload } from '../detection/downloadChecker'
import { saveThreatEvent, setDomainScore } from './storage'
import { scanFile } from '../api/client'
import { analyzeUrlWithGemini } from '../api/gemini'
import type { ThreatEvent, RiskLevel, UrlScanResult } from '../types'

const TRUSTED_DOMAINS = new Set([
  'youtube.com', 'youtu.be',
  'google.com', 'accounts.google.com',
  'github.com',
  'amazon.com', 'apple.com', 'microsoft.com', 'paypal.com', 'netflix.com',
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
])

function isTrustedDomain(hostname: string): boolean {
  for (const d of TRUSTED_DOMAINS) {
    if (hostname === d || hostname.endsWith(`.${d}`)) return true
  }
  return false
}

async function getApiBaseUrl(): Promise<string | null> {
  return new Promise(resolve => {
    chrome.storage.sync.get('apiBaseUrl', (r) => {
      const v = (r.apiBaseUrl || '').trim()
      resolve(v || null)
    })
  })
}

function normalizeRiskLevel(level: string): RiskLevel {
  const v = String(level || '').toUpperCase()
  if (v === 'CRITICAL') return 'CRITICAL'
  if (v === 'HIGH') return 'HIGH'
  if (v === 'MEDIUM') return 'MEDIUM'
  return 'LOW'
}

async function scanUrlViaFastApi(url: string, score: number, riskLevel: RiskLevel, indicators: string[]): Promise<UrlScanResult | null> {
  const apiBaseUrl = await getApiBaseUrl()
  if (!apiBaseUrl) return null

  try {
    const res = await fetch(`${apiBaseUrl}/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        score,
        risk_level: riskLevel,
        indicators,
      }),
    })
    if (!res.ok) return null
    const data = await res.json()

    const rl = normalizeRiskLevel(data?.risk_level || data?.riskLevel)
    const rs = typeof data?.score === 'number' ? data.score : (typeof data?.riskScore === 'number' ? data.riskScore : score)
    const rec = data?.recommended_action || data?.recommendedAction || (rl === 'HIGH' || rl === 'CRITICAL' ? 'block' : 'warn')
    const keyIndicators = data?.key_indicators || data?.keyIndicators || data?.threats || []

    return {
      explanation: data?.explanation || 'Analysis complete.',
      riskLevel: rl,
      recommendedAction: rec,
      confidence: typeof data?.confidence === 'number' ? data.confidence : 0.6,
      keyIndicators,
      riskScore: rs,
      cached: !!data?.cached,
    }
  } catch {
    return null
  }
}

// ── URL Analysis ──────────────────────────────────────────────────────────────
async function analyzeUrl(tabId: number, url: string) {
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) return
  let hostname = ''
  try { hostname = new URL(url).hostname } catch { return }

  // Hard allowlist to prevent false positives on trusted domains
  if (isTrustedDomain(hostname)) {
    chrome.action.setBadgeText({ text: '', tabId })
    await setDomainScore(hostname, 0)
    return
  }

  const local = scoreUrl(url)
  const indicators = Object.entries(local.signals)
    .filter(([, v]) => v > 0)
    .map(([k]) => k)

  // Mode 1: FastAPI backend if configured
  const fastApiResult = await scanUrlViaFastApi(url, local.score, local.riskLevel, indicators)

  // Mode 2: Direct Gemini if no backend or backend failed
  const gemini = fastApiResult ? null : await analyzeUrlWithGemini(url, local.score, local.riskLevel, indicators)

  let result: UrlScanResult | null = fastApiResult
  if (!result && gemini) {
    const verdict = gemini.verdict
    const mappedLevel: RiskLevel =
      verdict === 'MALICIOUS' ? (local.score >= 80 ? 'CRITICAL' : 'HIGH') :
      verdict === 'SUSPICIOUS' ? 'MEDIUM' :
      'LOW'
    result = {
      explanation: gemini.explanation,
      riskLevel: mappedLevel,
      recommendedAction: mappedLevel === 'HIGH' || mappedLevel === 'CRITICAL' ? 'block' : 'warn',
      confidence: gemini.confidence,
      keyIndicators: gemini.threats,
      riskScore: local.score,
      cached: false,
    }
  }

  const riskLevel = result?.riskLevel || local.riskLevel
  const riskScore = result?.riskScore ?? local.score
  const explanation = result?.explanation || getFallbackExplanation(riskScore)
  const recommendedAction = result?.recommendedAction || (riskLevel === 'HIGH' || riskLevel === 'CRITICAL' ? 'block' : 'warn')

  const colors: Record<string, string> = { LOW: '#166534', MEDIUM: '#B45309', HIGH: '#DC2626', CRITICAL: '#7F1D1D' }
  chrome.action.setBadgeBackgroundColor({ color: colors[riskLevel], tabId })
  chrome.action.setBadgeText({ text: riskLevel === 'LOW' ? '' : riskScore.toString(), tabId })

  if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
    chrome.tabs.sendMessage(tabId, {
      type: 'SHOW_OVERLAY',
      payload: { url, score: riskScore, riskLevel, explanation, recommendedAction }
    }).catch(() => {})
  }

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'url_threat',
    domain: hostname,
    url,
    riskScore,
    riskLevel,
    aiExplanation: explanation,
    timestamp: Date.now()
  })
  await setDomainScore(hostname, riskScore)
}

function getFallbackExplanation(score: number): string {
  if (score >= 80) return 'This website shows multiple high-risk signals. We strongly recommend leaving immediately.'
  if (score >= 60) return 'This website has several suspicious characteristics. Be very cautious with any personal information.'
  return 'This website has unusual patterns. Proceed with caution.'
}

// ── Navigation Listeners ──────────────────────────────────────────────────────
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

// ── Download Intercept (before file is written) ───────────────────────────────
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

  // Auto-cancel high risk; let medium through (user decides via overlay)
  if (risk.level === 'high') {
    chrome.downloads.cancel(item.id)
  } else {
    suggest({})
  }
})

// ── Post-Download AI File Scan (after file is complete) ───────────────────────
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

// ── Unified Message Handler ───────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const senderDomain = (() => { try { return new URL(sender.url || '').hostname } catch { return 'unknown' } })()

  // Popup abuse reported by content script
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

  // Report button in overlay -> open popup to report tab
  // overlayInjector sends this directly to background (not via content/index.ts relay)
  if (message.type === 'OPEN_REPORT_FORM') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup/index.html') + '?tab=report' })
    return true
  }

  // Content script asking background to cancel a download (downloads API unavailable in content)
  if (message.type === 'CANCEL_DOWNLOAD') {
    chrome.downloads.cancel(message.payload.downloadId)
    return true
  }

  return true
})

// ── Tab Cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => resetTab(tabId))
