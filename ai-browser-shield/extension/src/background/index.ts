import { scoreUrl } from '../detection/urlScorer'
import { trackRedirect, resetTab } from '../detection/redirectTracker'
import { checkDownload } from '../detection/downloadChecker'
import { getDomainScore, saveThreatEvent, setDomainScore } from './storage'
import { scanUrl, scanFile } from '../api/client'
import { analyzeEmail, getEmailHash } from '../email/analyzer'
import type { EmailSnapshot, PageAnalysis, ThreatEvent } from '../types'

const emailPredictionCache: Record<number, { hash: string; result: unknown }> = {}
let currentEmailData: EmailSnapshot = {
  subject: '',
  from: '',
  fromEmail: '',
  body: '',
  links: [],
  platform: 'gmail',
  timestamp: null,
}

function setBadgeForRisk(tabId: number, riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', score: number) {
  const colors: Record<string, string> = { LOW: '#166534', MEDIUM: '#B45309', HIGH: '#DC2626', CRITICAL: '#7F1D1D' }
  chrome.action.setBadgeBackgroundColor({ color: colors[riskLevel], tabId })
  chrome.action.setBadgeText({ text: riskLevel === 'LOW' ? 'OK' : score.toString(), tabId })
}

async function promoteTabRisk(tabId: number | undefined, url: string, score: number, riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') {
  if (!tabId || tabId < 0) return
  try {
    const domain = new URL(url).hostname
    const existing = await getDomainScore(domain)
    await setDomainScore(domain, Math.max(existing || 0, score))
    setBadgeForRisk(tabId, riskLevel, score)
  } catch {}
}

function riskLevelFromScore(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

// ── URL Analysis ──────────────────────────────────────────────────────────────
async function analyzeUrl(tabId: number, url: string) {
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) return
  let hostname = ''
  try { hostname = new URL(url).hostname } catch { return }

  const { score, signals, riskLevel } = scoreUrl(url)
  setBadgeForRisk(tabId, riskLevel, score)

  // Cache the current domain's score for the popup even when the site is low-risk.
  await setDomainScore(hostname, score)

  if (score < 30) return

  let aiExplanation = ''
  if (score >= 60) {
    const result = await scanUrl(url, signals)
    aiExplanation = result?.explanation || getFallbackExplanation(score)
    chrome.tabs.sendMessage(tabId, {
      type: 'SHOW_OVERLAY',
      payload: { url, score, riskLevel, explanation: aiExplanation, recommendedAction: result?.recommendedAction || 'warn' }
    }).catch(() => {})
  }

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'url_threat',
    domain: hostname,
    url,
    riskScore: score,
    riskLevel,
    aiExplanation,
    timestamp: Date.now()
  })
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
      promoteTabRisk(tabId, url, 70, 'HIGH')
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
    const activeTabId = tabs[0]?.id
    if (activeTabId) {
      promoteTabRisk(activeTabId, item.url, risk.level === 'high' ? 85 : 55, risk.level === 'high' ? 'HIGH' : 'MEDIUM')
    }
  })

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

  if (message.action === 'updateEmail') {
    const data = message.data || {}
    currentEmailData = {
      subject: data.subject || 'No Subject',
      from: data.from || 'Unknown Sender',
      fromEmail: data.fromEmail || '',
      body: data.body || '',
      links: data.links || [],
      platform: 'gmail',
      timestamp: Date.now(),
    }

    chrome.storage.local.set({ lastEmail: currentEmailData })
    sendResponse({ success: true, status: 'processing' })

    const tabId = sender.tab?.id
    if (!tabId) return true

    const messageHash = getEmailHash(currentEmailData)
    if (emailPredictionCache[tabId]?.hash === messageHash) {
      chrome.storage.local.set({
        currentAnalysis: emailPredictionCache[tabId].result,
        processingState: false,
      })
      chrome.tabs.sendMessage(tabId, {
        type: 'predictionResult',
        data: emailPredictionCache[tabId].result,
      }).catch(() => {})
      return true
    }

    chrome.storage.local.set({ processingState: true })
    chrome.tabs.sendMessage(tabId, {
      type: 'predictionResult',
      data: { final_risk_label: 'processing', risk_label: 'processing', confidence: 0 },
    }).catch(() => {})

    ;(async () => {
      try {
        console.log('[Email] Starting analysis for:', currentEmailData.subject)
        const result = await analyzeEmail(currentEmailData)
        emailPredictionCache[tabId] = { hash: messageHash, result }

        chrome.storage.local.set({
          currentAnalysis: result,
          processingState: false,
          lastEmail: currentEmailData,
        })

        chrome.tabs.sendMessage(tabId, {
          type: 'predictionResult',
          data: result,
        }).catch(() => {})
        console.log('[Email] Analysis completed:', result.final_risk_label, result.final_score)
      } catch (error) {
        console.error('[Email] Analysis failed:', error)
        const fallbackResult = {
          risk_label: 'error',
          final_risk_label: 'error',
          final_score: 0,
          platform: currentEmailData.platform,
          explanation: error instanceof Error ? error.message : 'Email analysis failed unexpectedly.',
          detected_patterns: [],
          engine: 'local-fallback' as const,
        }

        chrome.storage.local.set({
          currentAnalysis: fallbackResult,
          processingState: false,
          lastEmail: currentEmailData,
        })

        chrome.tabs.sendMessage(tabId, {
          type: 'predictionResult',
          data: fallbackResult,
        }).catch(() => {})
      }
    })()

    return true
  }

  if (message.action === 'getEmail') {
    sendResponse({ email: currentEmailData })
    return true
  }

  // Popup abuse reported by content script
  if (message.type === 'POPUP_ATTEMPT') {
    const popupCount = Number(message.payload?.count || 1)
    const popupRiskScore = popupCount >= 6 ? 85 : popupCount >= 4 ? 70 : popupCount >= 2 ? 55 : 35
    const popupRiskLevel = popupCount >= 6 ? 'HIGH' : popupCount >= 2 ? 'MEDIUM' : 'LOW'
    if (sender.tab?.id && sender.url) {
      promoteTabRisk(sender.tab.id, sender.url, popupRiskScore, popupRiskLevel)
    }
    saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'popup_abuse',
      domain: senderDomain,
      url: sender.url || '',
      riskScore: popupRiskScore,
      riskLevel: popupRiskLevel,
      aiExplanation: `This site triggered ${popupCount} popup or overlay events. Excessive popups are a common scam and ad-abuse tactic.`,
      timestamp: Date.now()
    })
    sendResponse({ blocked: true })
    return true
  }

  // Report button in overlay -> open popup to report tab
  // overlayInjector sends this directly to background (not via content/index.ts relay)
  if (message.type === 'OPEN_REPORT_FORM') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?tab=report' })
    return true
  }

  // Content script asking background to cancel a download (downloads API unavailable in content)
  if (message.type === 'CANCEL_DOWNLOAD') {
    chrome.downloads.cancel(message.payload.downloadId)
    return true
  }

  if (message.type === 'PAGE_ANALYSIS') {
    const tabId = sender.tab?.id
    const url = message.payload?.url || sender.url || ''
    const analysis = message.payload?.analysis as PageAnalysis | undefined
    if (!tabId || !url || !analysis) return true

    ;(async () => {
      const hostname = (() => { try { return new URL(url).hostname } catch { return '' } })()
      if (!hostname) return

      const baseScore = scoreUrl(url).score
      const combinedScore = Math.min(100, Math.max(baseScore, analysis.score, baseScore + Math.round(analysis.score * 0.65)))
      const riskLevel = riskLevelFromScore(combinedScore)
      await setDomainScore(hostname, combinedScore)
      setBadgeForRisk(tabId, riskLevel, combinedScore)

      if (combinedScore >= 30 && analysis.signals.length > 0) {
        await saveThreatEvent({
          id: crypto.randomUUID(),
          eventType: 'url_threat',
          domain: hostname,
          url,
          riskScore: combinedScore,
          riskLevel,
          aiExplanation: analysis.signals.join('. '),
          timestamp: Date.now(),
        })
      }
    })()

    return true
  }

  if (message.type === 'UPDATE_EMAIL_CONTENT') {
    const payload = message.payload as EmailSnapshot
    const tabId = sender.tab?.id
    if (!tabId || !payload) return true

    const normalizedPayload: EmailSnapshot = {
      subject: payload.subject || 'No Subject',
      from: payload.from || 'Unknown Sender',
      fromEmail: payload.fromEmail || '',
      body: payload.body || '',
      links: payload.links || [],
      platform: 'gmail',
      timestamp: Date.now(),
    }

    chrome.storage.local.set({
      lastEmailSnapshot: normalizedPayload,
      processingState: true,
    })

    chrome.tabs.sendMessage(tabId, {
      type: 'EMAIL_PREDICTION_RESULT',
      payload: { final_risk_label: 'processing', risk_label: 'processing' },
    }).catch(() => {})

    const currentHash = getEmailHash(normalizedPayload)
    if (emailPredictionCache[tabId]?.hash === currentHash) {
      chrome.storage.local.set({
        currentEmailAnalysis: emailPredictionCache[tabId].result,
        processingState: false,
      })
      chrome.tabs.sendMessage(tabId, {
        type: 'EMAIL_PREDICTION_RESULT',
        payload: emailPredictionCache[tabId].result,
      }).catch(() => {})
      sendResponse({ success: true, cached: true })
      return true
    }

    ;(async () => {
      try {
        console.log('[Email] Starting analysis for:', normalizedPayload.subject)
        const result = await analyzeEmail(normalizedPayload)
        emailPredictionCache[tabId] = { hash: currentHash, result }

        console.log('[Email] Analysis completed:', result.final_risk_label, result.final_score)
        chrome.storage.local.set({
          currentEmailAnalysis: result,
          lastEmailSnapshot: normalizedPayload,
          processingState: false,
        })

        chrome.tabs.sendMessage(tabId, {
          type: 'EMAIL_PREDICTION_RESULT',
          payload: result,
        }).catch(() => {})
      } catch (error) {
        console.error('[Email] Analysis failed:', error)
        const fallbackResult = {
          risk_label: 'error',
          final_risk_label: 'error',
          final_score: 0,
          platform: normalizedPayload.platform,
          explanation: error instanceof Error ? error.message : 'Email analysis failed unexpectedly.',
          detected_patterns: [],
          engine: 'local-fallback' as const,
        }

        chrome.storage.local.set({
          currentEmailAnalysis: fallbackResult,
          lastEmailSnapshot: normalizedPayload,
          processingState: false,
        })

        chrome.tabs.sendMessage(tabId, {
          type: 'EMAIL_PREDICTION_RESULT',
          payload: fallbackResult,
        }).catch(() => {})
      }
    })()

    sendResponse({ success: true, processing: true })
    return true
  }

  return true
})

// ── Tab Cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  resetTab(tabId)
})
