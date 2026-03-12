const REDIRECT_THRESHOLD = 3
const redirectMap = new Map<number, { count: number; urls: string[] }>()

export function trackRedirect(tabId: number, url: string): { exceeded: boolean; count: number; urls: string[] } {
  const existing = redirectMap.get(tabId) || { count: 0, urls: [] }
  existing.count++
  existing.urls.push(url)
  redirectMap.set(tabId, existing)

  if (existing.count > REDIRECT_THRESHOLD) {
    return { exceeded: true, count: existing.count, urls: existing.urls }
  }
  return { exceeded: false, count: existing.count, urls: existing.urls }
}

export function resetTab(tabId: number) {
  redirectMap.delete(tabId)
}
