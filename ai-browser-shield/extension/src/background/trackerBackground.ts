import { saveThreatEvent } from './storage'
import { classifyUrl, getTabStats, recordBlock, resetTabStats, type TabStats } from '../detection/trackerEngine'
import type { RiskLevel } from '../types'

const TRACKER_EVENT_THROTTLE_MS = 15_000
const lastTrackerEventByKey = new Map<string, number>()

function safeActionCall<T>(fn: () => Promise<T>): void {
  try {
    void fn().catch(() => {})
  } catch {
    // Ignore transient extension API errors.
  }
}

async function maybeRecordBlockedTracker(requestUrl: string, tabId: number): Promise<void> {
  if (tabId < 0) return

  const classified = classifyUrl(requestUrl)
  if (!classified) return

  let tabUrl = requestUrl
  try {
    const tab = await chrome.tabs.get(tabId)
    tabUrl = tab.url || requestUrl
  } catch {
    return
  }

  const stats = await recordBlock(requestUrl, tabId, tabUrl, classified.category, classified.bytes)
  const hostname = (() => {
    try {
      return new URL(requestUrl).hostname
    } catch {
      return requestUrl
    }
  })()

  const eventKey = `${tabId}:${classified.category}:${hostname}`
  const now = Date.now()
  const previous = lastTrackerEventByKey.get(eventKey) || 0
  if (now - previous < TRACKER_EVENT_THROTTLE_MS) {
    return
  }
  lastTrackerEventByKey.set(eventKey, now)

  const riskScoreByCategory = {
    ad: 20,
    tracker: 35,
    fingerprinter: 60,
    social: 25,
    cryptominer: 95,
    bounce_tracker: 55,
  } as const

  const riskLevelByCategory: Record<typeof classified.category, RiskLevel> = {
    ad: 'LOW',
    tracker: 'MEDIUM',
    fingerprinter: 'HIGH',
    social: 'LOW',
    cryptominer: 'CRITICAL',
    bounce_tracker: 'HIGH',
  }

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType: 'ad_block',
    domain: hostname,
    url: requestUrl,
    riskScore: riskScoreByCategory[classified.category],
    riskLevel: riskLevelByCategory[classified.category],
    aiExplanation: `Blocked ${classified.category.replace('_', ' ')} request on ${stats.tabDomain}. Saved approximately ${classified.bytes} bytes.`,
    source: 'dnr+trackerdb',
    timestamp: now,
  })

  updateTabBadge(tabId)
}

function updateTabBadge(tabId: number): void {
  safeActionCall(async () => {
    const stats: TabStats | null = await getTabStats(tabId)
    if (!stats || stats.total === 0) return

    const text = stats.total > 999 ? '1k+' : stats.total > 99 ? '99+' : String(stats.total)

    chrome.action.getBadgeText({ tabId }, (existing) => {
      if (chrome.runtime.lastError) return

      const existingNum = parseInt(existing || '0', 10)
      if (existingNum >= 30) return

      safeActionCall(async () => {
        await chrome.tabs.get(tabId)
        await chrome.action.setBadgeBackgroundColor({ color: '#1D4ED8', tabId })
      })
      safeActionCall(async () => {
        await chrome.tabs.get(tabId)
        await chrome.action.setBadgeText({ text, tabId })
      })
    })
  })
}

export function initTrackerBlocking(): void {
  if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((details) => {
      const requestUrl = details.request?.url
      const tabId = typeof details.request?.tabId === 'number' ? details.request.tabId : -1
      if (!requestUrl) return
      void maybeRecordBlockedTracker(requestUrl, tabId)
    })
  }

  chrome.webNavigation.onCommitted.addListener(({ tabId, frameId }) => {
    if (frameId !== 0) return
    void resetTabStats(tabId)
  })

  chrome.tabs.onRemoved.addListener((tabId) => {
    void resetTabStats(tabId)
  })

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type !== 'GET_TAB_TRACKER_STATS') return false

    const tabId = message.payload?.tabId
    if (typeof tabId !== 'number') {
      sendResponse({ stats: null })
      return true
    }

    void getTabStats(tabId)
      .then((stats) => sendResponse({ stats: stats ?? null }))
      .catch(() => sendResponse({ stats: null }))

    return true
  })

  console.log('[TrackerShield] Tracker blocking initialized')
}
