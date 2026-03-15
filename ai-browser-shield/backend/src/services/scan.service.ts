import { prisma } from '../db/client'
import { cacheGetJSON, cacheSetJSON, keys } from './cache.service'
import { analyzeUrl, analyzeFile } from '../ai/client'
import type { UrlScanInput, FileScanInput, ThreatEventInput } from '../schemas'

type PersistedUrlScanResult = {
  explanation: string
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  recommendedAction: 'allow' | 'warn' | 'block'
  confidence: number
  keyIndicators?: string[]
  riskScore?: number
  heuristic?: number
  source?: string
  cached: boolean
  db?: {
    reportCount: number
    categories: string[]
    domainRiskScore: number
    lastSeen: Date | string | null
  }
  vt?: {
    vendorsFlagged: number
    vendorsTotal: number
    score: number
  }
}

function inferCategoriesFromSignals(
  signals: Record<string, number>,
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
): string[] {
  const categories = new Set<string>()
  if ((signals.popupRedirectRisk || 0) > 0) categories.add('popup_abuse')
  if ((signals.redirectChainRisk || 0) > 0 || (signals.redirectRisk || 0) > 0) categories.add('redirect')
  if ((signals.phishingRisk || 0) > 0 || (signals.typosquatScore || 0) > 0) categories.add('phishing')
  if ((signals.malwareRisk || 0) > 0) categories.add('malware')
  if (categories.size === 0 && (riskLevel === 'HIGH' || riskLevel === 'CRITICAL')) categories.add('other')
  return [...categories]
}

async function persistUrlObservation(params: {
  domain: string
  url: string
  result: PersistedUrlScanResult
  signals: Record<string, number>
  computedSignals?: Record<string, number>
  popupRisk?: number
  abuseEvents?: number
  reportCount?: number
  reportCategories?: string[]
  dbRiskScore?: number
}) {
  const {
    domain,
    url,
    result,
    signals,
    computedSignals = {},
    popupRisk = 0,
    abuseEvents = 0,
    reportCount = 0,
    reportCategories = [],
    dbRiskScore = 0,
  } = params

  const riskScore = result.riskScore ?? 0
  const inferredCategories = inferCategoriesFromSignals(signals, result.riskLevel)
  const mergedCategories = [...new Set([...(reportCategories || []), ...inferredCategories])]
  const nextDomainRisk = Math.min(100, Math.round(dbRiskScore * 0.65 + riskScore * 0.35))

  await prisma.domainScore.upsert({
    where: { domain },
    update: {
      riskScore: nextDomainRisk,
      categories: mergedCategories,
      last_report_at: new Date(),
    },
    create: {
      domain,
      riskScore: nextDomainRisk,
      reportCount,
      categories: mergedCategories,
    },
  }).catch(() => {})

  // Ensure the domain exists in the DomainScore table
  const existingDomain = await prisma.domainScore.findUnique({ where: { domain } });
  if (!existingDomain) {
    await prisma.domainScore.create({
      data: {
        domain,
        riskScore: 0,
        reportCount: 0,
        categories: [],
        category_counts: {},
        is_confirmed: false,
      },
    });
  }

  await prisma.detectionEvent.create({
    data: {
      eventType: 'url_threat',
      domain,
      url,
      riskScore,
      riskLevel: result.riskLevel,
      signals: {
        source: result.source || 'unknown',
        cached: result.cached,
        confidence: result.confidence,
        keyIndicators: result.keyIndicators || [],
        recommended_action: result.recommendedAction,
        popupRisk,
        abuseEvents,
        reportCount,
        reportCategories,
        previousDomainRiskScore: dbRiskScore,
        inputSignals: signals,
        computedSignals,
        vt: result.vt || null,
      } as any,
      aiExplanation: result.explanation,
    },
  }).catch(() => {})
}

function extractDomain(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

export async function scanUrl(data: UrlScanInput) {
  const cacheKey = keys.urlScan(data.url)
  const cached = await cacheGetJSON(cacheKey)
  if (cached) return { ...cached, cached: true }

  const signals = (data.signals ?? {}) as Record<string, number>
  const heuristic = Math.min(100,
    Object.values(signals).reduce((a: number, b) => a + (Number(b) || 0), 0))

  const domain = extractDomain(data.url)

  // Fetch DB score first — community truth overrides everything
  let dbRiskScore = 0
  let dbReportCount = 0
  try {
    const dbRow = await prisma.domainScore.findUnique({ where: { domain } })
    if (dbRow) {
      dbRiskScore = dbRow.riskScore
      dbReportCount = dbRow.reportCount
    }
  } catch { /* non-blocking */ }

  // Call Gemini AI
  const aiResult = await analyzeUrl(data.url, signals, heuristic)

  // Combined formula: H×0.20 + AI×conf×0.50 + DB×0.30 + boosts
  const aiNumeric = aiResult.riskLevel === 'CRITICAL' ? 95
    : aiResult.riskLevel === 'HIGH' ? 80
    : aiResult.riskLevel === 'MEDIUM' ? 50 : 15
  const conf = Math.min(1, Math.max(0, aiResult.confidence ?? 0.5))

  let score = (heuristic * 0.20) + (aiNumeric * conf * 0.50) + (dbRiskScore * 0.30)

  // Boosts
  if (aiResult.recommendedAction === 'block') score += 12
  else if (aiResult.recommendedAction === 'warn') score += 6
  if ((signals.typosquatScore ?? 0) > 0) score += 8
  if ((signals.ipAsHostname ?? 0) > 0) score += 15
  if ((signals.suspiciousTLD ?? 0) > 0 && (signals.suspiciousKeywords ?? 0) > 0) score += 7
  if (dbReportCount >= 3) score += 10
  if (dbReportCount >= 5) score += 10

  // RULE: never show a lower score than what community has confirmed
  if (dbRiskScore > 0) score = Math.max(score, dbRiskScore)

  const finalScore = Math.min(100, Math.round(score))
  const finalRiskLevel = finalScore >= 75 ? 'CRITICAL'
    : finalScore >= 50 ? 'HIGH'
    : finalScore >= 30 ? 'MEDIUM' : 'LOW'

  const payload = {
    ...aiResult,
    riskLevel: finalRiskLevel,
    riskScore: finalScore,
    heuristic,
    dbRiskScore,
    dbReportCount,
    cached: false,
  }

  const ttl = finalScore >= 60 ? 900 : 3600
  await cacheSetJSON(cacheKey, payload, ttl)

  prisma.detectionEvent.create({
    data: {
      eventType: 'url_threat', domain, url: data.url,
      riskScore: finalScore, riskLevel: finalRiskLevel as any,
      signals: signals as any, aiExplanation: aiResult.explanation,
    }
  }).catch(() => {})

  return payload
}

export async function scanFile(data: FileScanInput) {
  let sourceDomain = (data as any).sourceDomain || ''
  if (!sourceDomain) {
    try {
      sourceDomain = new URL(data.sourceUrl).hostname
    } catch {
      sourceDomain = ''
    }
  }

  let domainRiskScore = (data as any).domainRiskScore ?? 0
  let domainReportCount = (data as any).domainReportCount ?? 0
  let domainCategories: string[] = (data as any).domainCategories ?? []

  if (sourceDomain && domainRiskScore === 0) {
    try {
      const dbRow = await prisma.domainScore.findUnique({ where: { domain: sourceDomain } })
      if (dbRow) {
        domainRiskScore = dbRow.riskScore
        domainReportCount = dbRow.reportCount
        domainCategories = dbRow.categories ?? []
      }
    } catch {
      // Non-blocking: AI scan can still run without domain context.
    }
  }

  const result = await analyzeFile({
    ...data,
    sourceDomain,
    domainRiskScore,
    domainReportCount,
    domainCategories,
  })

  prisma.fileScan.create({
    data: {
      filename: data.filename,
      extension: data.extension,
      mimeType: data.mimeType,
      sizeBytes: BigInt(data.sizeBytes),
      sourceUrl: data.sourceUrl,
      verdict: result.verdict,
      confidence: result.confidence,
      aiExplanation: result.explanation,
      indicators: result.indicators,
      recommended_action: result.recommendedAction,
    },
  }).catch(() => {})

  return {
    ...result,
    sourceDomain,
    domainRiskScore,
    domainReportCount,
  }
}

export async function recordThreatEvent(event: ThreatEventInput) {
  const domain = event.domain
  const categories = inferCategoriesFromSignals(event.metadata as Record<string, number> || {}, event.riskLevel)

  await prisma.domainScore.upsert({
    where: { domain },
    update: {
      riskScore: Math.min(100, Math.round((event.riskScore * 0.4) + (categories.length > 0 ? 10 : 0))),
      categories,
      last_report_at: new Date(event.timestamp || Date.now()),
    },
    create: {
      domain,
      riskScore: Math.min(100, Math.max(event.riskScore, categories.length > 0 ? 25 : event.riskScore)),
      categories,
    },
  }).catch(() => {})

  await prisma.detectionEvent.create({
    data: {
      eventType: event.eventType,
      domain,
      url: event.url,
      riskScore: event.riskScore,
      riskLevel: event.riskLevel,
      signals: {
        source: event.source || 'extension',
        metadata: event.metadata || null,
      } as any,
      aiExplanation: event.aiExplanation,
      verdict: event.verdict,
      createdAt: event.timestamp ? new Date(event.timestamp) : undefined,
    },
  })
}

export async function getDomainScore(domain: string) {
  const cacheKey = keys.domainScore(domain)
  const cached = await cacheGetJSON(cacheKey)
  if (cached) return cached

  const score = await prisma.domainScore.findUnique({ where: { domain } }).catch(() => null)
  if (!score) return null

  const result = {
    domain: score.domain,
    riskScore: score.riskScore,
    reportCount: score.reportCount,
    categories: score.categories ?? [],
    lastUpdated: score.lastUpdated?.toISOString() ?? new Date().toISOString(),
  }

  await cacheSetJSON(cacheKey, result, 600)
  return result
}

interface ThreatEventDto {
  id: string
  eventType: 'url_threat' | 'redirect_chain' | 'popup_abuse' | 'download_intercept' | 'file_scan' | 'ad_block'
  domain: string
  url: string
  riskScore: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  aiExplanation?: string
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  timestamp: number
}

export async function getThreatEvents(params: { domain?: string; limit?: number } = {}): Promise<ThreatEventDto[]> {
  const { domain, limit = 100 } = params

  const where = domain ? { domain } : {}

  const events = await prisma.detectionEvent.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: Math.min(Math.max(limit, 1), 500),
  }).catch(() => [])

  return events.map((e) => ({
    id: e.id,
    eventType: e.eventType,
    domain: e.domain,
    url: e.url,
    riskScore: e.riskScore,
    riskLevel: e.riskLevel,
    aiExplanation: e.aiExplanation ?? undefined,
    verdict: e.verdict ?? undefined,
    timestamp: e.createdAt.getTime(),
  }))
}
