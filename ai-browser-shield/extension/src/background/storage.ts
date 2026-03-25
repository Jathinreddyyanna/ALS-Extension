import type { ThreatEvent } from '../types'
import { storeThreatEvent } from '../api/client'
import { toHashedUrl } from '../lib/security'

const HISTORY_KEY = 'threatHistory'
const MAX_HISTORY = 100

/**
 * Removes raw URL material before persisting threat history locally.
 */
async function redactThreatEvent(event: ThreatEvent): Promise<ThreatEvent> {
  return {
    ...event,
    url: await toHashedUrl(event.url),
  }
}

/**
 * Persists a threat event locally and syncs eligible events to the backend.
 */
export async function saveThreatEvent(event: ThreatEvent): Promise<void> {
  const history = await getThreatHistory()
  history.unshift(await redactThreatEvent(event))
  if (history.length > MAX_HISTORY) history.splice(MAX_HISTORY)
  await chrome.storage.local.set({ [HISTORY_KEY]: history })
  if (event.eventType !== 'url_threat' && event.eventType !== 'file_scan') {
    try {
      await storeThreatEvent(event)
    } catch {
      // Keep local history even when backend sync is unavailable.
    }
  }
}

/**
 * Returns the locally cached threat history.
 */
export async function getThreatHistory(): Promise<ThreatEvent[]> {
  const result = await chrome.storage.local.get(HISTORY_KEY)
  return result[HISTORY_KEY] || []
}

/**
 * Clears locally cached threat history.
 */
export async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(HISTORY_KEY)
}

/**
 * Stores a per-domain score cache entry.
 */
export async function setDomainScore(domain: string, score: number): Promise<void> {
  const key = `score:${domain}`
  await chrome.storage.local.set({ [key]: { score, ts: Date.now() } })
}

/**
 * Reads a non-expired cached domain score.
 */
export async function getDomainScore(domain: string): Promise<number | null> {
  const key = `score:${domain}`
  const result = await chrome.storage.local.get(key)
  const cached = result[key]
  if (!cached) return null
  if (Date.now() - cached.ts > 10 * 60 * 1000) return null
  return cached.score
}
