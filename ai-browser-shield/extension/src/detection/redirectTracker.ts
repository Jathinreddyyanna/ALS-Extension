const redirectMap = new Map<number, { count: number; urls: string[]; firstSeen: number }>()
const newTabMap = new Map<number, { openerTabId: number; url: string; ts: number }>()

const REDIRECT_THRESHOLD = 2
const NEW_TAB_SPAM_WINDOW_MS = 3000
const RETURN_REDIRECT_WINDOW_MS = 5000

export function trackRedirect(tabId: number, url: string): {
  exceeded: boolean
  count: number
  urls: string[]
} {
  const existing = redirectMap.get(tabId) ?? { count: 0, urls: [], firstSeen: Date.now() }
  existing.count++
  existing.urls.push(url)
  redirectMap.set(tabId, existing)
  return {
    exceeded: existing.count > REDIRECT_THRESHOLD,
    count: existing.count,
    urls: existing.urls,
  }
}

export function trackNewTab(newTabId: number, openerTabId: number, url: string): void {
  newTabMap.set(newTabId, { openerTabId, url, ts: Date.now() })
}

export function getNewTabInfo(tabId: number): { openerTabId: number; url: string; ts: number } | null {
  return newTabMap.get(tabId) ?? null
}

export function clearNewTabInfo(tabId: number): void {
  newTabMap.delete(tabId)
}

export function resetTab(tabId: number) {
  redirectMap.delete(tabId)
  newTabMap.delete(tabId)
}

export const REDIRECT_THRESHOLD_VALUE = REDIRECT_THRESHOLD
export const NEW_TAB_SPAM_WINDOW = NEW_TAB_SPAM_WINDOW_MS
export const RETURN_REDIRECT_WINDOW = RETURN_REDIRECT_WINDOW_MS
