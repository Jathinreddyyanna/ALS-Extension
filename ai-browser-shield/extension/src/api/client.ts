import type { ThreatReport, UrlScanResult, FileScanResult, DomainScore, CommunityReport, SignalMap, PageContextSnapshot } from '../types'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001/api/v1'

interface ApiError {
  status: number
  message: string
  errors?: Record<string, string>
}

async function post<T>(path: string, body: unknown): Promise<{ data: T | null; error: ApiError | null }> {
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Extension-Version': '1.0.0',
      },
      body: JSON.stringify(body),
    })

    const responseText = await res.text()
    let data: T | null = null

    try {
      data = JSON.parse(responseText)
    } catch {
      data = null
    }

    if (!res.ok) {
      return {
        data: null,
        error: {
          status: res.status,
          message: `Request failed with status ${res.status}`,
          errors: typeof data === 'object' && data !== null ? (data as any).errors : undefined,
        },
      }
    }

    return { data, error: null }
  } catch (err) {
    return {
      data: null,
      error: {
        status: 0,
        message: err instanceof Error ? err.message : 'Network error',
      },
    }
  }
}

async function get<T>(path: string): Promise<{ data: T | null; error: ApiError | null }> {
  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      headers: { 'X-Extension-Version': '1.0.0' },
    })

    const responseText = await res.text()
    let data: T | null = null

    try {
      data = JSON.parse(responseText)
    } catch {
      data = null
    }

    if (!res.ok) {
      return {
        data: null,
        error: {
          status: res.status,
          message: `Request failed with status ${res.status}`,
        },
      }
    }

    return { data, error: null }
  } catch (err) {
    return {
      data: null,
      error: {
        status: 0,
        message: err instanceof Error ? err.message : 'Network error',
      },
    }
  }
}

export async function scanUrl(url: string, signals: SignalMap, pageContext?: PageContextSnapshot | null): Promise<UrlScanResult | null> {
  const { data } = await post('/scan/url', { url, signals: signals || {}, pageContext: pageContext || undefined })
  return data
}

export async function scanFile(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  contentSnippet?: string
}): Promise<FileScanResult | null> {
  const { data: result } = await post('/scan/file', data)
  return result
}

export async function submitReport(report: ThreatReport): Promise<{ status: string } | null> {
  const { data } = await post('/reports', report)
  return data
}

export async function getRecentFeed(): Promise<CommunityReport[]> {
  const { data } = await get<CommunityReport[]>('/reports/recent')
  return data || []
}

export async function getDomainScore(domain: string): Promise<DomainScore | null> {
  const { data } = await get(`/scan/domain/${domain}/score`)
  return data
}
