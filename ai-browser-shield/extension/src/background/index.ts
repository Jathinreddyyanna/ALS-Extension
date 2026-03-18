import { scoreUrl } from '../detection/urlScorer'
import { checkDownload } from '../detection/downloadChecker'
import { trackRedirect, resetTab, trackNewTab, getNewTabInfo, clearNewTabInfo, NEW_TAB_SPAM_WINDOW, RETURN_REDIRECT_WINDOW } from '../detection/redirectTracker'
import { saveThreatEvent, setDomainScore } from './storage'
import { getDomainScore, scanFile, scanUrl } from '../api/client'
import { PopupAndRedirectTracker, type PopupAndRedirectAnalysis } from '../detection/popupRedirectTracker'
import { initTrackerBlocking } from './trackerBackground'
import type { ThreatEvent, RiskLevel, SignalMap } from '../types'

const pendingDownloads = new Map<number, {
  suggest: (result?: chrome.downloads.DownloadFilenameSuggestion) => void
  item: chrome.downloads.DownloadItem
  tabId: number
}>()
const STATIC_ADBLOCK_RULESET_ID = 'adblock'
const blockedCounts: Record<number, { ads: number; trackers: number; cryptominers: number }> = {}
const siteRiskByTab = new Map<number, {
  url: string
  domain: string
  riskScore: number
  riskLevel: RiskLevel
  explanation: string
  source?: string
}>()

// Canonical popup + redirect tracker per tab (Brave-like behavior)
const popupRedirectTrackers = new Map<number, PopupAndRedirectTracker>()
const lastUrlByTab = new Map<number, string>()
const lastPopupRedirectSnapshotByTab = new Map<
  number,
  { popupCount: number; totalRedirects: number; riskLevel: PopupAndRedirectAnalysis['riskLevel'] }
>()
const EMPTY_SIGNALS: SignalMap = {
  typosquatScore: 0,
  suspiciousTLD: 0,
  ipAsHostname: 0,
  longSubdomains: 0,
  suspiciousKeywords: 0,
  encodedChars: 0,
  pathEntropy: 0,
  portAnomaly: 0,
}
const pageLoadTimes = new Map<number, { url: string; ts: number }>()

function getBlockedCategory(ruleId: number): 'ads' | 'trackers' | 'cryptominers' {
  if (ruleId >= 51 && ruleId <= 58) return 'cryptominers'
  if (ruleId >= 59) return 'trackers'
  return 'ads'
}

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request.tabId
    if (typeof tabId !== 'number' || tabId < 0) return

    if (!blockedCounts[tabId]) {
      blockedCounts[tabId] = { ads: 0, trackers: 0, cryptominers: 0 }
    }

    const category = getBlockedCategory(info.rule.ruleId)
    blockedCounts[tabId][category]++
    chrome.storage.local.set({ [`blocked:${tabId}`]: blockedCounts[tabId] })
  })
}

async function ensureAdblockRulesetEnabled() {
  try {
    const enabled = await chrome.declarativeNetRequest.getEnabledRulesets()
    if (!enabled.includes(STATIC_ADBLOCK_RULESET_ID)) {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: [STATIC_ADBLOCK_RULESET_ID],
      })
    }
  } catch (err) {
    console.warn('[Adblock] Failed to verify static ruleset:', err)
  }
}

async function safeSendMessage(tabId: number, message: any) {
  try {
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return
      if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('devtools://')) return
      chrome.tabs.sendMessage(tabId, message, () => {
        void chrome.runtime.lastError
      })
    })
  } catch {
    // Tab may be closed or not ready; ignore
  }
}

function safeSignals(raw: Partial<SignalMap> | null | undefined): SignalMap {
  return {
    typosquatScore: raw?.typosquatScore ?? 0,
    suspiciousTLD: raw?.suspiciousTLD ?? 0,
    ipAsHostname: raw?.ipAsHostname ?? 0,
    longSubdomains: raw?.longSubdomains ?? 0,
    suspiciousKeywords: raw?.suspiciousKeywords ?? 0,
    encodedChars: raw?.encodedChars ?? 0,
    pathEntropy: raw?.pathEntropy ?? 0,
    portAnomaly: raw?.portAnomaly ?? 0,
  }
}

async function safeSetBadge(tabId: number, color: string, text: string) {
  try {
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return
      chrome.action.setBadgeBackgroundColor({ color, tabId }, () => {
        void chrome.runtime.lastError
      })
      chrome.action.setBadgeText({ text, tabId }, () => {
        void chrome.runtime.lastError
      })
    })
  } catch {
    // Ignore badge updates for tabs that no longer exist.
  }
}

function safeSuggest(
  suggest: (suggestion?: any) => void,
  filename?: string | null
) {
  try {
    if (typeof filename === 'string' && filename.trim().length > 0) {
      suggest({ filename: filename.trim() })
      return
    }
    suggest()
  } catch {
    try {
      suggest()
    } catch {
      // Ignore invalid suggestion failures.
    }
  }
}

function getSiteRiskContext(tabId?: number | null, url?: string) {
  if (typeof tabId === 'number') {
    const existing = siteRiskByTab.get(tabId)
    if (existing) return existing
  }

  if (url) {
    try {
      const hostname = new URL(url).hostname
      for (const value of siteRiskByTab.values()) {
        if (value.domain === hostname) return value
      }
    } catch {
      // ignore invalid URLs
    }
  }

  return null
}

function shouldEscalateFromSiteRisk(siteRisk: { riskLevel: RiskLevel; riskScore: number } | null | undefined) {
  if (!siteRisk) return false
  return siteRisk.riskLevel === 'HIGH' || siteRisk.riskLevel === 'CRITICAL' || siteRisk.riskScore >= 50
}

function getPopupRedirectTracker(tabId: number): PopupAndRedirectTracker {
  let tracker = popupRedirectTrackers.get(tabId)
  if (!tracker) {
    tracker = new PopupAndRedirectTracker()
    popupRedirectTrackers.set(tabId, tracker)
  }
  return tracker
}

function resetPopupRedirectTracker(tabId: number) {
  const tracker = popupRedirectTrackers.get(tabId)
  if (tracker) {
    tracker.reset()
  }
  lastUrlByTab.delete(tabId)
  lastPopupRedirectSnapshotByTab.delete(tabId)
}

function popupRiskSeverity(level: PopupAndRedirectAnalysis['riskLevel']): number {
  switch (level) {
    case 'CRITICAL':
      return 3
    case 'DANGEROUS':
      return 2
    case 'CAUTION':
      return 1
    default:
      return 0
  }
}

async function createThreatEventFromPopupRedirect(
  tabId: number,
  url: string,
  analysis: PopupAndRedirectAnalysis,
  source: 'popup' | 'redirect'
) {
  const prev = lastPopupRedirectSnapshotByTab.get(tabId)
  const hasChange =
    !prev ||
    analysis.popupCount > prev.popupCount ||
    analysis.totalRedirects > prev.totalRedirects ||
    popupRiskSeverity(analysis.riskLevel) > popupRiskSeverity(prev.riskLevel)

  if (!hasChange) return

  lastPopupRedirectSnapshotByTab.set(tabId, {
    popupCount: analysis.popupCount,
    totalRedirects: analysis.totalRedirects,
    riskLevel: analysis.riskLevel,
  })

  let eventType: ThreatEvent['eventType'] = 'popup_abuse'
  if (source === 'redirect' || analysis.totalRedirects > 0) {
    eventType = 'redirect_chain'
  }

  const riskScoreMap: Record<PopupAndRedirectAnalysis['riskLevel'], number> = {
    SAFE: 10,
    CAUTION: 45,
    DANGEROUS: 75,
    CRITICAL: 90,
  }
  const riskScore = riskScoreMap[analysis.riskLevel] ?? 45
  const domain = (() => {
    try {
      return new URL(url).hostname
    } catch {
      return analysis.website || 'unknown'
    }
  })()

  const explanation =
    analysis.flags.join(' | ') ||
    (source === 'redirect'
      ? 'Potentially abusive redirect behavior detected on this site.'
      : 'Excessive popups or overlays detected on this site.')

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType,
    domain,
    url,
    riskScore,
    riskLevel:
      analysis.riskLevel === 'CRITICAL'
        ? 'CRITICAL'
        : analysis.riskLevel === 'DANGEROUS'
          ? 'HIGH'
          : analysis.riskLevel === 'CAUTION'
            ? 'MEDIUM'
            : 'LOW',
    aiExplanation: explanation,
    timestamp: Date.now(),
  })
}

function isClearlyJunkRedirect(url: string): boolean {
  try {
    const u = new URL(url)
    const host = u.hostname
    const tld = host.split('.').pop() || ''
    const badTlds = ['top', 'cyou', 'click', 'xyz', 'loan', 'online']
    if (badTlds.includes(tld)) return true
    if (host.length > 40 && /[0-9]/.test(host) && /[a-z]/i.test(host)) return true
    return false
  } catch {
    return false
  }
}

function isSpamPattern(url: string): boolean {
  try {
    const u = new URL(url)
    const host = u.hostname.toLowerCase()
    const full = url.toLowerCase()
    const spamTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.loan', '.rest', '.cam', '.icu', '.sbs']
    const spamKeywords = [
      'free-spin', 'you-won', 'winner', 'prize-claim', 'lucky-draw',
      'free-recharge', 'cashback-offer', 'earn-money', 'work-from-home',
      'click-here', 'claim-now', 'limited-offer', 'congratulations',
      'adult', 'xxx', 'casino', 'bet365', 'gambling',
      'download-now', 'install-now', 'update-required', 'virus-detected',
      'your-pc-is-infected', 'call-support', 'tech-support',
    ]

    if (spamTLDs.some((tld) => host.endsWith(tld))) return true
    if (spamKeywords.some((keyword) => full.includes(keyword))) return true
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true
    if (url.length > 300) return true
    if (u.searchParams.has('click_id') && u.searchParams.has('offer_id')) return true
    if (u.searchParams.has('aff_id') || u.searchParams.has('affiliate_id')) return true

    return false
  } catch {
    return false
  }
}

const lastAnalyzed = new Map<number, string>()

async function analyzeUrl(tabId: number, url: string) {
  if (typeof tabId !== 'number' || tabId < 0) return
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://') || url.startsWith('devtools://')) return
  let hostname = ''
  try { hostname = new URL(url).hostname } catch { return }
  if (!hostname) return

  if (lastAnalyzed.get(tabId) === url) return
  lastAnalyzed.set(tabId, url)
  lastUrlByTab.set(tabId, url)

  const local = scoreUrl(url)
  const signals: SignalMap = safeSignals(local?.signals ?? EMPTY_SIGNALS)

  const colors: Record<string, string> = { LOW: '#166534', MEDIUM: '#B45309', HIGH: '#DC2626', CRITICAL: '#7F1D1D' }
  try {
    await safeSetBadge(tabId, colors[local.riskLevel] ?? '#166534', local.riskLevel === 'LOW' ? '' : local.score.toString())
  } catch (err) {
    console.debug('[UI] Failed to update heuristic badge for tab', tabId, err)
  }

  try {
    const result = await scanUrl(url, signals, {
      headers: {
        'x-api-key': import.meta.env.VITE_API_KEY!,
      },
    })
    if (!result) {
      await setDomainScore(hostname, local.score)
      siteRiskByTab.set(tabId, {
        url,
        domain: hostname,
        riskScore: local.score,
        riskLevel: local.riskLevel,
        explanation: getFallbackExplanation(local.score),
        source: 'heuristic',
      })
      return
    }

    const finalScore = typeof result.riskScore === 'number' ? result.riskScore : local.score
    const finalRiskLevel = result.riskLevel || local.riskLevel
    const explanation = result.explanation || getFallbackExplanation(finalScore)
    const recommendedAction = result.recommendedAction ?? 'warn'
    const source = result.source || 'backend'

    await safeSetBadge(tabId, colors[finalRiskLevel] ?? '#166534', finalRiskLevel === 'LOW' ? '' : String(finalScore))

    await setDomainScore(hostname, finalScore)

    if (finalRiskLevel === 'HIGH' || finalRiskLevel === 'CRITICAL') {
      safeSendMessage(tabId, {
        type: 'SHOW_OVERLAY',
        payload: {
          url,
          score: finalScore,
          riskLevel: finalRiskLevel,
          explanation,
          recommendedAction,
        },
      })
    }

    if (finalScore >= 30) {
      await saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'url_threat',
        domain: hostname,
        url,
        riskScore: finalScore,
        riskLevel: finalRiskLevel,
        aiExplanation: explanation,
        source,
        timestamp: Date.now(),
      })
    }

    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: finalScore,
      riskLevel: finalRiskLevel,
      explanation,
      source,
    })
  } catch (err) {
    console.debug('[Background] scanUrl unavailable, using heuristic only:', err)
    await setDomainScore(hostname, local.score)

    if (local.score >= 30) {
      await saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'url_threat',
        domain: hostname,
        url,
        riskScore: local.score,
        riskLevel: local.riskLevel,
        aiExplanation: '',
        source: 'heuristic',
        timestamp: Date.now(),
      })
    }

    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: local.score,
      riskLevel: local.riskLevel,
      explanation: getFallbackExplanation(local.score),
      source: 'heuristic',
    })
  }
}

function getFallbackExplanation(score: number): string {
  if (score >= 80) return 'This website shows multiple high-risk signals. We strongly recommend leaving immediately.'
  if (score >= 60) return 'This website has several suspicious characteristics. Be very cautious with any personal information.'
  return 'This website has unusual patterns. Proceed with caution.'
}

// ── Navigation Listeners ──────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return
  const lastLoad = pageLoadTimes.get(tabId)
  if (lastLoad) {
    const timeSinceLoad = Date.now() - lastLoad.ts
    const isDifferentUrl = lastLoad.url !== url

    if (isDifferentUrl && timeSinceLoad < RETURN_REDIRECT_WINDOW) {
      const { score } = scoreUrl(url)
      if (score >= 30 || isSpamPattern(url)) {
        chrome.tabs.update(tabId, { url: lastLoad.url }, () => {
          void chrome.runtime.lastError
        })

        safeSendMessage(tabId, {
          type: 'CLICKJACK_WARNING',
          payload: {
            blockedUrl: url,
            score,
            riskLevel: 'HIGH',
            reason: `This site tried to redirect you to ${(() => { try { return new URL(url).hostname } catch { return url } })()} immediately after loading. This is a common trick used by piracy and scam sites.`,
          },
        })

        saveThreatEvent({
          id: crypto.randomUUID(),
          eventType: 'redirect_chain',
          domain: (() => { try { return new URL(url).hostname } catch { return url } })(),
          url,
          riskScore: 75,
          riskLevel: 'HIGH',
          aiExplanation: `Automatic redirect attack: site tried to redirect to ${url} within ${timeSinceLoad}ms of page load.`,
          timestamp: Date.now(),
        }).catch(() => {})

        pageLoadTimes.delete(tabId)
        return
      }
    }
    pageLoadTimes.delete(tabId)
  }

  blockedCounts[tabId] = { ads: 0, trackers: 0, cryptominers: 0 }
  chrome.storage.local.set({ [`blocked:${tabId}`]: blockedCounts[tabId] })
  resetTab(tabId)
  resetPopupRedirectTracker(tabId)
  analyzeUrl(tabId, url)
})

chrome.webNavigation.onCommitted.addListener(({ tabId, url, frameId, transitionQualifiers }) => {
  if (frameId !== 0) return
  if (transitionQualifiers.includes('server_redirect') || transitionQualifiers.includes('client_redirect')) {
    const redirectState = trackRedirect(tabId, url)
    if (redirectState.exceeded) {
      safeSendMessage(tabId, { type: 'REDIRECT_WARNING', payload: { count: redirectState.count, urls: redirectState.urls, url } })
    }

    const previousUrl = lastUrlByTab.get(tabId) || url
    const tracker = getPopupRedirectTracker(tabId)
    const { blocked, reason } = tracker.trackRedirect({
      from: previousUrl,
      to: url,
      method: 'header',
      timestamp: Date.now(),
    })
    lastUrlByTab.set(tabId, url)

    if (blocked) {
      const hostname = (() => {
        try {
          return new URL(previousUrl).hostname
        } catch {
          return 'unknown'
        }
      })()
      const analysis = tracker.analyze(hostname)
      void createThreatEventFromPopupRedirect(tabId, previousUrl, analysis, 'redirect')

      const primaryChain = analysis.redirectChains[analysis.redirectChains.length - 1]
      if (primaryChain && (analysis.riskLevel === 'CAUTION' || analysis.riskLevel === 'DANGEROUS')) {
        safeSendMessage(tabId, {
          type: 'REDIRECT_WARNING',
          payload: { count: primaryChain.totalRedirects, urls: primaryChain.chain, url },
        })
      }

      if (analysis.riskLevel === 'CRITICAL' || isClearlyJunkRedirect(url)) {
        // Attempt to close obviously junk / critical redirect tabs.
        // Ignore all errors (tab may already be closed or changed).
        try {
          chrome.tabs.get(tabId, (tab) => {
            if (!chrome.runtime.lastError && tab) {
              chrome.tabs.remove(tabId, () => {
                void chrome.runtime.lastError;
              });
            }
          });
        } catch {
          // No-op: background errors are intentionally suppressed here.
        }
      }
    }
  }
})

chrome.tabs.onCreated.addListener((tab) => {
  const tabId = tab.id
  if (typeof tabId !== 'number') return

  chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
    const openerTab = activeTabs[0]
    if (!openerTab?.id || !openerTab.url) return

    try {
      const openerHost = new URL(openerTab.url).hostname
      const safeHosts = ['google.com', 'github.com', 'youtube.com', 'bing.com', 'stackoverflow.com']
      if (safeHosts.some((host) => openerHost.endsWith(host))) return
    } catch {
      return
    }

    trackNewTab(tabId, openerTab.id, tab.pendingUrl || tab.url || '')
  })
})

chrome.webNavigation.onDOMContentLoaded.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return
  if (!url || url.startsWith('chrome://') || url.startsWith('about:')) return
  pageLoadTimes.set(tabId, { url, ts: Date.now() })
})

// Some SPA navigations don't fire onBeforeNavigate; analyze on tab update as a backup.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    const url = changeInfo.url || tab.url
    if (!url) return

    const newTabInfo = getNewTabInfo(tabId)
    if (!newTabInfo) return

    const age = Date.now() - newTabInfo.ts
    if (age > NEW_TAB_SPAM_WINDOW) {
      clearNewTabInfo(tabId)
      return
    }

    const { score, riskLevel } = scoreUrl(url)
    const isSpamUrl = isSpamPattern(url)

    if (score >= 40 || isSpamUrl || riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
      chrome.tabs.remove(tabId, () => {
        void chrome.runtime.lastError
      })
      clearNewTabInfo(tabId)

      const openerTabId = newTabInfo.openerTabId
      console.warn('[Background] Click-jacking blocked:', url)
      safeSendMessage(openerTabId, {
        type: 'CLICKJACK_WARNING',
        payload: {
          blockedUrl: url,
          score,
          riskLevel,
          reason: isSpamUrl
            ? 'This site tried to open a known spam/ad URL in a new tab without your permission.'
            : `This site tried to silently open a suspicious URL (risk score: ${score}/100) in a new tab.`,
        },
      })

      saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'popup_abuse',
        domain: (() => { try { return new URL(url).hostname } catch { return url } })(),
        url,
        riskScore: Math.max(score, 65),
        riskLevel: 'HIGH',
        aiExplanation: `Click-jacking detected: site tried to open ${url} silently in a new tab.`,
        timestamp: Date.now(),
      }).catch(() => {})
      return
    }

    clearNewTabInfo(tabId)
    return
  }

  if (changeInfo.status === 'complete' && tab.url) {
    analyzeUrl(tabId, tab.url)
  }
})

// ── Zero-Trust Download Intercept (cancel + backend approval) ─────────────────
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  const filename = item?.filename
  if (!filename || filename.trim() === '') {
    safeSuggest(suggest)
    return
  }

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tabId = tabs[0]?.id ?? -1
    const localRisk = checkDownload(filename, item.mime ?? '', item.url ?? '')

    pendingDownloads.set(item.id, { suggest, item, tabId })

    let sourceDomain = ''
    let domainRiskScore = 0
    let domainReportCount = 0
    let domainCategories: string[] = []

    try {
      sourceDomain = new URL(item.url ?? '').hostname
      const domainData = sourceDomain ? await getDomainScore(sourceDomain) : null
      if (domainData) {
        domainRiskScore = domainData.riskScore ?? 0
        domainReportCount = domainData.reportCount ?? 0
        domainCategories = domainData.categories ?? []
      }
    } catch {
      sourceDomain = ''
    }

    let aiResult: Awaited<ReturnType<typeof scanFile>> = null
    try {
      const ext = '.' + (filename.split('.').pop()?.toLowerCase() || 'bin')
      aiResult = await scanFile({
        filename,
        extension: ext,
        mimeType: item.mime || 'application/octet-stream',
        sizeBytes: item.fileSize || 0,
        sourceUrl: item.url || '',
        sourceDomain,
        domainRiskScore,
        domainReportCount,
        domainCategories,
      })
    } catch {
      aiResult = null
    }

    const verdict = aiResult?.verdict ?? (localRisk.level === 'high' ? 'MALICIOUS' : localRisk.level === 'medium' ? 'SUSPICIOUS' : 'SAFE')
    const explanation = aiResult?.explanation ?? localRisk.reason
    const recommendedAction = aiResult?.recommendedAction ?? (localRisk.level === 'high' ? 'block' : localRisk.level === 'medium' ? 'warn' : 'allow')
    const confidence = aiResult?.confidence ?? 0.6
    const indicators = aiResult?.indicators?.length ? aiResult.indicators : [localRisk.reason]

    if (verdict === 'SAFE' && domainRiskScore < 30 && localRisk.level === 'safe') {
      const pending = pendingDownloads.get(item.id)
      if (pending) {
        safeSuggest(pending.suggest)
        pendingDownloads.delete(item.id)
      }
      return
    }

    safeSendMessage(tabId, {
      type: 'DOWNLOAD_WARNING',
      payload: {
        filename,
        downloadId: item.id,
        verdict,
        explanation,
        confidence,
        indicators,
        recommendedAction,
        sourceDomain,
        domainRiskScore,
        domainReportCount,
        sourceRisk: aiResult?.sourceRisk ?? (domainRiskScore >= 75 ? 'dangerous' : domainRiskScore >= 30 ? 'suspicious' : 'safe'),
      },
    })

    void saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'download_intercept',
      domain: sourceDomain || (() => { try { return new URL(item.url ?? '').hostname } catch { return 'unknown' } })(),
      url: item.url ?? '',
      riskScore: verdict === 'MALICIOUS' ? 90 : verdict === 'SUSPICIOUS' ? 55 : 20,
      riskLevel: verdict === 'MALICIOUS' ? 'CRITICAL' : verdict === 'SUSPICIOUS' ? 'HIGH' : 'LOW',
      aiExplanation: explanation,
      timestamp: Date.now(),
    })
  })

  return true
})

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === 'interrupted' || delta.state?.current === 'complete') {
    pendingDownloads.delete(delta.id)
  }
})

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') {
    return false
  }

  const senderDomain = (() => { try { return new URL(sender.url || '').hostname } catch { return 'unknown' } })()

  // Popup abuse reported by content script
  if (message.type === 'POPUP_ATTEMPT') {
    const tabId = sender.tab?.id
    if (tabId == null) {
      return false
    }

    const tracker = getPopupRedirectTracker(tabId)
    const kind = (message.payload?.kind as 'window' | 'iframe' | 'overlay' | 'meta-refresh' | undefined) || 'window'
    const popupUrl =
      (message.payload?.popupUrl as string | undefined) ||
      (message.payload?.url as string | undefined) ||
      sender.url ||
      ''
    const pageUrl = sender.url || popupUrl
    const now = Date.now()

    if (kind === 'iframe' || kind === 'overlay') {
      tracker.trackIframeInjection({
        url: pageUrl,
        iframeUrl: popupUrl,
        timestamp: now,
        isHidden: !!message.payload?.isHidden,
      })
    } else {
      tracker.trackPopupWindow({
        url: pageUrl,
        popupUrl,
        timestamp: now,
      })
    }

    const analysis = tracker.analyze(senderDomain)
    void createThreatEventFromPopupRedirect(tabId, pageUrl, analysis, 'popup')

    // Force an immediate re-scan so the UI updates with the new popup signals
    lastAnalyzed.delete(tabId)
    void analyzeUrl(tabId, pageUrl)

    sendResponse?.({
      popupCount: analysis.popupCount,
      popupThreshold: analysis.popupThreshold,
      riskLevel: analysis.riskLevel,
    })
    return false
  }

  // Report button in overlay -> open popup to report tab
  // overlayInjector sends this directly to background (not via content/index.ts relay)
  if (message.type === 'OPEN_REPORT_FORM') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?tab=report' })
    return false
  }

  if (message.type === 'ALLOW_DOWNLOAD') {
    const downloadId = message.payload?.downloadId
    if (typeof downloadId !== 'number') return false
    const pending = pendingDownloads.get(downloadId)
    if (!pending) return false

    safeSuggest(pending.suggest)
    pendingDownloads.delete(downloadId)
    return false
  }

  if (message.type === 'CANCEL_DOWNLOAD') {
    const downloadId = message.payload?.downloadId
    if (typeof downloadId !== 'number') return false
    const pending = pendingDownloads.get(downloadId)
    if (pending) {
      safeSuggest(pending.suggest)
      chrome.downloads.cancel(downloadId, () => {
        void chrome.runtime.lastError
      })
      pendingDownloads.delete(downloadId)
    } else {
      chrome.downloads.cancel(downloadId, () => {
        void chrome.runtime.lastError
      })
    }
    return false
  }

  if (message.type === 'GET_BLOCKED_COUNTS') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id ?? -1
      sendResponse(blockedCounts[tabId] ?? { ads: 0, trackers: 0, cryptominers: 0 })
    })
    return true
  }

  if (message.type === 'REPORT_BACK_REDIRECT') {
    const { fromUrl, toUrl, tabId: msgTabId } = message.payload ?? {}
    if (fromUrl && toUrl) {
      safeSendMessage(msgTabId ?? (sender.tab?.id ?? -1), {
        type: 'CLICKJACK_WARNING',
        payload: {
          blockedUrl: toUrl,
          score: 70,
          riskLevel: 'HIGH',
          reason: `This site tried to redirect you away from ${(() => { try { return new URL(fromUrl).hostname } catch { return fromUrl } })()} without your permission.`,
        },
      })
    }
    return true
  }

  return false
})

// ── Tab Cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  resetTab(tabId)
  resetPopupRedirectTracker(tabId)
  pageLoadTimes.delete(tabId)
  siteRiskByTab.delete(tabId)
  delete blockedCounts[tabId]
  chrome.storage.local.remove(`blocked:${tabId}`)
})

void ensureAdblockRulesetEnabled()
initTrackerBlocking()
