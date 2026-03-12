import type { ThreatEvent } from '../types'

const HISTORY_KEY = 'threatHistory'
const MAX_HISTORY = 100

export async function saveThreatEvent(event: ThreatEvent): Promise<void> {
  const history = await getThreatHistory()
  history.unshift(event)
  if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY)
  await chrome.storage.local.set({ [HISTORY_KEY]: history })
}

export async function getThreatHistory(): Promise<ThreatEvent[]> {
  const result = await chrome.storage.local.get(HISTORY_KEY)
  return result[HISTORY_KEY] || []
}

export async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(HISTORY_KEY)
}

export async function setDomainScore(domain: string, score: number): Promise<void> {
  const key = `score:${domain}`
  await chrome.storage.local.set({ [key]: { score, ts: Date.now() } })
}

export async function getDomainScore(domain: string): Promise<number | null> {
  const key = `score:${domain}`
  const result = await chrome.storage.local.get(key)
  const cached = result[key]
  if (!cached) return null
  // expire after 10 minutes
  if (Date.now() - cached.ts > 10 * 60 * 1000) return null
  return cached.score
}
