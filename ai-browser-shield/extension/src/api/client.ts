import type {
  ThreatReport,
  UrlScanResult,
  FileScanResult,
  DomainScore,
  CommunityReport,
  SignalMap,
  ThreatEvent,
} from '../types'
import { getEffectiveApiBaseUrl } from '../config'

const BASE_URL =
  (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_API_BASE_URL) ||
  'http://localhost:3001/api/v1'
const DOMAIN_MISS_TTL_MS = 10 * 60 * 1000

async function resolveBaseUrl(): Promise<string> {
  try {
    return await getEffectiveApiBaseUrl()
  } catch {
    return BASE_URL
  }
}

function normalizeSignals(signals: SignalMap): SignalMap {
  return {
    typosquatScore: signals?.typosquatScore ?? 0,
    suspiciousTLD: signals?.suspiciousTLD ?? 0,
    ipAsHostname: signals?.ipAsHostname ?? 0,
    longSubdomains: signals?.longSubdomains ?? 0,
    suspiciousKeywords: signals?.suspiciousKeywords ?? 0,
    encodedChars: signals?.encodedChars ?? 0,
    pathEntropy: signals?.pathEntropy ?? 0,
    portAnomaly: signals?.portAnomaly ?? 0,
  }
}

async function post<T>(path: string, body: unknown): Promise<T | null> {
  try {
    const baseUrl = await resolveBaseUrl()
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Extension-Version': '1.0.0' },
      body: JSON.stringify(body),
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

async function get<T>(path: string): Promise<T | null> {
  try {
    const baseUrl = await resolveBaseUrl()
    const res = await fetch(`${baseUrl}${path}`, {
      headers: { 'X-Extension-Version': '1.0.0' },
    })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

async function getDomainMiss(domain: string): Promise<boolean> {
  try {
    const key = `domain-miss:${domain}`
    const result = await chrome.storage.local.get(key)
    const cached = result[key] as { ts?: number } | undefined
    return typeof cached?.ts === 'number' && Date.now() - cached.ts < DOMAIN_MISS_TTL_MS
  } catch {
    return false
  }
}

async function setDomainMiss(domain: string): Promise<void> {
  try {
    const key = `domain-miss:${domain}`
    await chrome.storage.local.set({ [key]: { ts: Date.now() } })
  } catch {
    // Ignore storage failures; backend fallback still works.
  }
}

async function clearDomainMiss(domain: string): Promise<void> {
  try {
    await chrome.storage.local.remove(`domain-miss:${domain}`)
  } catch {
    // Ignore storage failures.
  }
}

export async function scanUrl(url: string, signals: SignalMap): Promise<UrlScanResult | null> {
  if (!url || !signals) return null
  return post<UrlScanResult>('/scan/url', { url, signals: normalizeSignals(signals) })
}

export async function scanFile(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  sourceDomain?: string
  domainRiskScore?: number
  domainReportCount?: number
  domainCategories?: string[]
  contentSnippet?: string
}): Promise<FileScanResult | null> {
  if (!data?.filename) return null
  return post<FileScanResult>('/scan/file', data)
}

export async function submitReport(report: ThreatReport): Promise<{ status: string } | null> {
  if (!report?.url) return null
  return post<{ status: string }>('/reports', report)
}

export async function getRecentFeed(): Promise<CommunityReport[]> {
  const data = await get<CommunityReport[]>('/reports/recent')
  return Array.isArray(data) ? data : []
}

export async function getDomainScore(domain: string): Promise<DomainScore | null> {
  if (!domain) return null
  if (await getDomainMiss(domain)) return null
  const data = await get<any>(`/scan/domain/${encodeURIComponent(domain)}/score`)
  if (!data) {
    await setDomainMiss(domain)
    return null
  }

  await clearDomainMiss(domain)

  if (data.risk_score !== undefined) {
    return {
      domain: data.domain,
      riskScore: data.risk_score ?? 0,
      reportCount: data.report_count ?? 0,
      categories: Array.isArray(data.categories) ? data.categories : [],
      lastUpdated: data.last_updated ?? new Date().toISOString(),
      aiSummary: data.ai_summary ?? null,
      aiThreatLevel: data.ai_threat_level ?? null,
      aiRecommendation: data.ai_recommendation ?? null,
    }
  }

  return data as DomainScore
}

export async function getThreatEvents(domain: string): Promise<ThreatEvent[]> {
  if (!domain) return []
  const query = `?domain=${encodeURIComponent(domain)}&limit=100`
  const data = await get<ThreatEvent[]>(`/scan/events${query}`)
  return Array.isArray(data) ? data : []
}

export async function storeThreatEvent(event: ThreatEvent): Promise<boolean> {
  const result = await post<{ ok?: boolean }>('/scan/events', {
    ...event,
    metadata: {
      persistedBy: 'extension',
    },
  })
  return !!result
}
