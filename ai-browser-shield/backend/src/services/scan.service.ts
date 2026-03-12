import { prisma } from '../db/client'
import { cacheGetJSON, cacheSetJSON, keys } from './cache.service'
import { analyzeUrl, analyzeFile } from '../ai/client'
import { scoreUrl } from './urlScorer'
import type { UrlScanInput, FileScanInput } from '../schemas'

export async function scanUrl(data: UrlScanInput) {
  const cacheKey = keys.urlScan(data.url)

  // Check cache first
  if (!data.force) {
    const cached = await cacheGetJSON(cacheKey)
    if (cached) return { ...cached, cached: true, source: 'cache' }
  }

  // Extract domain for database lookup
  let domain = ''
  try { domain = new URL(data.url).hostname } catch { domain = data.url }

  // Check database for known malicious sites
  const dbRecord = await prisma.detectionEvent.findFirst({
    where: { domain },
    orderBy: { createdAt: 'desc' },
    take: 1,
  }).catch(() => null)

  // Pull community signals from reports/domain score
  const domainScore = await prisma.domainScore.findUnique({
    where: { domain },
  }).catch(() => null)

  const reportCount = domainScore?.reportCount ?? 0
  const reportCategories = domainScore?.categories ?? []
  const dbRiskScore = domainScore?.riskScore ?? 0

  // Hard allowlist for highly trusted domains to avoid false positives
  const TRUSTED_DOMAINS = [
    'github.com', 'google.com', 'accounts.google.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'paypal.com', 'netflix.com', 'facebook.com', 'linkedin.com',
  ]
  if (TRUSTED_DOMAINS.some(d => domain === d || domain.endsWith(`.${d}`))) {
    const safeResult = {
      explanation: 'This site is a well-known trusted domain. No suspicious patterns were detected.',
      riskLevel: 'LOW' as const,
      recommendedAction: 'allow' as const,
      confidence: 0.9,
      keyIndicators: ['Trusted domain'],
      db: {
        reportCount,
        categories: reportCategories,
        domainRiskScore: dbRiskScore,
        lastSeen: domainScore?.lastUpdated || null,
      },
      cached: false,
      source: 'allowlist',
    }
    await cacheSetJSON(cacheKey, safeResult, 3600)
    return safeResult
  }

  // Calculate risk score from signals (fallback to server-side scoring if none provided)
  const computed = scoreUrl(data.url)
  const providedSignals = data.signals || {}
  const signals = Object.keys(providedSignals).length > 0 ? providedSignals : computed.signals
  const baseScore = Math.min(100, Object.values(signals).reduce((a: number, b: number) => a + (b || 0), 0))

  // Blend in community score if available
  const riskScore = Math.min(100, Math.round(baseScore * 0.7 + dbRiskScore * 0.3))

  // If no signals and no reports, short-circuit as LOW to avoid AI false positives
  if (riskScore < 20 && reportCount === 0) {
    const safeResult = {
      explanation: 'No suspicious signals were detected for this site.',
      riskLevel: 'LOW' as const,
      recommendedAction: 'allow' as const,
      confidence: 0.7,
      keyIndicators: ['No suspicious signals'],
      db: {
        reportCount,
        categories: reportCategories,
        domainRiskScore: dbRiskScore,
        lastSeen: domainScore?.lastUpdated || null,
      },
      cached: false,
      source: 'heuristic',
    }
    await cacheSetJSON(cacheKey, safeResult, 3600)
    return safeResult
  }

  // Use Gemini AI for analysis (only if signals or reports suggest risk)
  if (riskScore < 30 && reportCount === 0) {
    const safeResult = {
      explanation: 'No meaningful risk signals were detected for this site.',
      riskLevel: 'LOW' as const,
      recommendedAction: 'allow' as const,
      confidence: 0.7,
      keyIndicators: ['Low-risk signals'],
      db: {
        reportCount,
        categories: reportCategories,
        domainRiskScore: dbRiskScore,
        lastSeen: domainScore?.lastUpdated || null,
      },
      cached: false,
      source: 'heuristic',
    }
    await cacheSetJSON(cacheKey, safeResult, 3600)
    return safeResult
  }

  // Use Gemini AI for analysis
  const aiResult = await analyzeUrl(data.url, signals, riskScore)

  // Merge AI result with database/community signals
  const indicators = [
    ...(aiResult.keyIndicators || []),
    ...(reportCount > 0 ? ['Community reports exist'] : []),
    ...(reportCategories.length > 0 ? [`Reported as: ${reportCategories.join(', ')}`] : []),
  ].slice(0, 5)

  const dbLevel =
    dbRecord?.riskLevel ??
    (dbRiskScore >= 80 ? 'CRITICAL' : dbRiskScore >= 60 ? 'HIGH' : dbRiskScore >= 30 ? 'MEDIUM' : 'LOW')

  const rank: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
  const finalRiskLevel = rank[dbLevel] > rank[aiResult.riskLevel] ? dbLevel : aiResult.riskLevel
  const recommendedAction =
    finalRiskLevel === 'CRITICAL' || finalRiskLevel === 'HIGH' ? 'block' : 'warn'

  const finalResult = {
    ...aiResult,
    riskScore,
    riskLevel: finalRiskLevel,
    recommendedAction,
    keyIndicators: indicators,
    db: {
      reportCount,
      categories: reportCategories,
      domainRiskScore: dbRiskScore,
      lastSeen: domainScore?.lastUpdated || null,
    },
    cached: false,
    source: reportCount > 0 || dbRecord ? 'ai+db' : 'ai',
  }

  // Cache the result
  await cacheSetJSON(cacheKey, finalResult, 3600)

  // Save to database for future lookups
  await prisma.detectionEvent.create({
    data: {
      eventType: 'url_threat',
      domain,
      url: data.url,
      riskScore,
      riskLevel: aiResult.riskLevel,
      signals: signals as any,
      aiExplanation: aiResult.explanation,
    }
  }).catch(() => {}) // non-blocking

  return finalResult
}

export async function scanFile(data: FileScanInput) {
  const result = await analyzeFile(data)

  let domain = ''
  try { domain = new URL(data.sourceUrl).hostname } catch { domain = data.sourceUrl }

  await prisma.fileScan.create({
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
    }
  }).catch(() => {})

  return result
}

export async function getDomainScore(domain: string) {
  const cacheKey = keys.domainScore(domain)
  const cached = await cacheGetJSON(cacheKey)
  if (cached) return cached

  // First check detection events
  const detectionCount = await prisma.detectionEvent.count({
    where: { domain },
  }).catch(() => 0)

  // Check file scans
  const fileScanCount = await prisma.fileScan.count({
    where: { sourceUrl: { contains: domain } },
  }).catch(() => 0)

  // Get from database if exists
  const score = await prisma.domainScore.findUnique({ 
    where: { domain } 
  }).catch(() => null)

  const riskScore = score?.riskScore ?? (detectionCount > 0 ? 50 : 100)
  const trustLevel = riskScore >= 60 ? 'untrusted' : riskScore >= 30 ? 'caution' : 'trusted'

  const result = {
    domain,
    riskScore,
    trustLevel,
    detectionEvents: detectionCount,
    fileScanFlags: fileScanCount,
    lastUpdated: score?.lastUpdated || new Date(),
  }

  await cacheSetJSON(cacheKey, result, 600) // 10 min TTL
  return result
}
