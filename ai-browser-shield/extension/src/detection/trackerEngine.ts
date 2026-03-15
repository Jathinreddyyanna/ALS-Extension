export type TrackerCategory =
  | 'ad'
  | 'tracker'
  | 'fingerprinter'
  | 'social'
  | 'cryptominer'
  | 'bounce_tracker'

export interface TabStats {
  tabId: number
  tabUrl: string
  tabDomain: string
  ads: number
  trackers: number
  fingerprinters: number
  social: number
  cryptominers: number
  bounceTrackers: number
  total: number
  bandwidthSavedBytes: number
  lastUpdated: number
}

export interface SessionStats {
  totalBlocked: number
  ads: number
  trackers: number
  fingerprinters: number
  social: number
  cryptominers: number
  bounceTrackers: number
  bandwidthSavedBytes: number
  sitesProtected: number
  since: number
}

const SESSION_KEY = 'trackerSessionStats'
const TAB_STATS_PREFIX = 'tracker:tab:'

const TRACKER_DB: Array<[string, TrackerCategory, number]> = [
  ['doubleclick.net', 'ad', 8200],
  ['googlesyndication.com', 'ad', 12000],
  ['adnxs.com', 'ad', 9500],
  ['ads.twitter.com', 'ad', 6000],
  ['amazon-adsystem.com', 'ad', 7800],
  ['outbrain.com', 'ad', 11000],
  ['taboola.com', 'ad', 13000],
  ['rubiconproject.com', 'ad', 5500],
  ['openx.net', 'ad', 4200],
  ['pubmatic.com', 'ad', 3800],
  ['criteo.com', 'ad', 7200],
  ['google-analytics.com', 'tracker', 4800],
  ['analytics.google.com', 'tracker', 4800],
  ['scorecardresearch.com', 'tracker', 2100],
  ['quantserve.com', 'tracker', 1900],
  ['chartbeat.com', 'tracker', 3200],
  ['segment.com', 'tracker', 4300],
  ['segment.io', 'tracker', 4300],
  ['hotjar.com', 'tracker', 18000],
  ['fullstory.com', 'tracker', 22000],
  ['mouseflow.com', 'tracker', 14000],
  ['intercom.io', 'tracker', 28000],
  ['hubspot.com', 'tracker', 19000],
  ['fingerprintjs.com', 'fingerprinter', 31000],
  ['fingerprint.com', 'fingerprinter', 31000],
  ['threatmetrix.com', 'fingerprinter', 12000],
  ['sift.com', 'fingerprinter', 9800],
  ['perimeterx.com', 'fingerprinter', 11000],
  ['datadome.co', 'fingerprinter', 9700],
  ['facebook.com/tr', 'social', 3600],
  ['connect.facebook.net', 'social', 41000],
  ['platform.twitter.com', 'social', 38000],
  ['static.ads-twitter.com', 'social', 11000],
  ['linkedin.com', 'social', 24000],
  ['snap.licdn.com', 'social', 8900],
  ['platform.linkedin.com', 'social', 29000],
  ['pinterest.com', 'social', 9700],
  ['ct.pinterest.com', 'social', 5400],
  ['tiktok.com', 'social', 31000],
  ['analytics.tiktok.com', 'social', 12000],
  ['coinhive.com', 'cryptominer', 0],
  ['coin-hive.com', 'cryptominer', 0],
  ['crypto-loot.com', 'cryptominer', 0],
  ['jsecoin.com', 'cryptominer', 0],
  ['bounce.me', 'bounce_tracker', 1200],
  ['t.co', 'bounce_tracker', 900],
  ['bit.ly', 'bounce_tracker', 800],
  ['ow.ly', 'bounce_tracker', 700],
  ['tinyurl.com', 'bounce_tracker', 700],
  ['smarturl.it', 'bounce_tracker', 900],
  ['linktr.ee', 'bounce_tracker', 1100],
]

const exactMap = new Map<string, [TrackerCategory, number]>()
const suffixMap = new Map<string, [TrackerCategory, number]>()

for (const [pattern, category, bytes] of TRACKER_DB) {
  if (pattern.includes('/')) exactMap.set(pattern, [category, bytes])
  else suffixMap.set(pattern, [category, bytes])
}

function emptySessionStats(): SessionStats {
  return {
    totalBlocked: 0,
    ads: 0,
    trackers: 0,
    fingerprinters: 0,
    social: 0,
    cryptominers: 0,
    bounceTrackers: 0,
    bandwidthSavedBytes: 0,
    sitesProtected: 0,
    since: Date.now(),
  }
}

export function classifyUrl(url: string): { category: TrackerCategory; bytes: number } | null {
  let hostname = ''
  let fullPath = ''
  try {
    const u = new URL(url)
    hostname = u.hostname.replace(/^www\./, '')
    fullPath = `${u.hostname}${u.pathname}`
  } catch {
    return null
  }

  for (const [pattern, val] of exactMap) {
    if (fullPath.startsWith(pattern)) return { category: val[0], bytes: val[1] }
  }

  for (const [domain, val] of suffixMap) {
    if (hostname === domain || hostname.endsWith(`.${domain}`)) {
      return { category: val[0], bytes: val[1] }
    }
  }

  return null
}

export async function getSessionStats(): Promise<SessionStats> {
  const result = await chrome.storage.local.get(SESSION_KEY)
  return result[SESSION_KEY] || emptySessionStats()
}

export async function getTabStats(tabId: number): Promise<TabStats | null> {
  const result = await chrome.storage.local.get(`${TAB_STATS_PREFIX}${tabId}`)
  return result[`${TAB_STATS_PREFIX}${tabId}`] || null
}

export async function resetTabStats(tabId: number): Promise<void> {
  await chrome.storage.local.remove(`${TAB_STATS_PREFIX}${tabId}`)
}

export async function resetSessionStats(): Promise<void> {
  await chrome.storage.local.set({ [SESSION_KEY]: emptySessionStats() })
}

function applyCategoryCount(target: SessionStats | TabStats, category: TrackerCategory) {
  if (category === 'ad') target.ads++
  if (category === 'tracker') target.trackers++
  if (category === 'fingerprinter') target.fingerprinters++
  if (category === 'social') target.social++
  if (category === 'cryptominer') target.cryptominers++
  if (category === 'bounce_tracker') target.bounceTrackers++
}

export async function recordBlock(
  url: string,
  tabId: number,
  tabUrl: string,
  category: TrackerCategory,
  bytes: number
): Promise<TabStats> {
  const tabDomain = (() => { try { return new URL(tabUrl).hostname } catch { return tabUrl } })()
  const tabKey = `${TAB_STATS_PREFIX}${tabId}`
  const existing = await getTabStats(tabId)
  const nextTab: TabStats = existing || {
    tabId,
    tabUrl,
    tabDomain,
    ads: 0,
    trackers: 0,
    fingerprinters: 0,
    social: 0,
    cryptominers: 0,
    bounceTrackers: 0,
    total: 0,
    bandwidthSavedBytes: 0,
    lastUpdated: Date.now(),
  }

  nextTab.tabUrl = tabUrl
  nextTab.tabDomain = tabDomain
  nextTab.total++
  nextTab.bandwidthSavedBytes += bytes
  nextTab.lastUpdated = Date.now()
  applyCategoryCount(nextTab, category)

  const session = await getSessionStats()
  session.totalBlocked++
  session.bandwidthSavedBytes += bytes
  applyCategoryCount(session, category)
  session.sitesProtected = Math.max(session.sitesProtected, 1)

  await chrome.storage.local.set({
    [tabKey]: nextTab,
    [SESSION_KEY]: session,
  })

  return nextTab
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}
