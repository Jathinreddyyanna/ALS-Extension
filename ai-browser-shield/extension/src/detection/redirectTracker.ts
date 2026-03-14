const REDIRECT_THRESHOLD = 3
const REDIRECT_WINDOW_MS = 12000

const redirectMap = new Map<number, { count: number; urls: string[]; lastTs: number; host?: string }>()

function getHostname(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

export function trackRedirect(tabId: number, url: string): { exceeded: boolean; count: number; urls: string[] } {
  const now = Date.now()
  const existing = redirectMap.get(tabId)
  const hostname = getHostname(url)

  if (!existing || now - existing.lastTs > REDIRECT_WINDOW_MS) {
    const fresh = { count: 1, urls: [url], lastTs: now, host: hostname }
    redirectMap.set(tabId, fresh)
    return { exceeded: false, count: fresh.count, urls: fresh.urls }
  }

  const isNewHop = existing.urls[existing.urls.length - 1] !== url
  const isCrossDomain = hostname && existing.host && hostname !== existing.host

  if (isNewHop || isCrossDomain) {
    existing.count += 1
    existing.urls.push(url)
  }

  existing.lastTs = now
  existing.host = hostname || existing.host
  redirectMap.set(tabId, existing)

  return {
    exceeded: existing.count > REDIRECT_THRESHOLD,
    count: existing.count,
    urls: existing.urls,
  }
}

export function resetTab(tabId: number) {
  redirectMap.delete(tabId)
}
