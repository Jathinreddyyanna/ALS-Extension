import { prisma } from '../db/client'
import { cacheGetJSON, cacheSetJSON, keys } from './cache.service'
import { analyzeUrl, analyzeFile } from '../ai/client'
import type { UrlScanInput, FileScanInput } from '../schemas'

export async function scanUrl(data: UrlScanInput) {
  const cacheKey = keys.urlScan(data.url)

  // Check cache first
  const cached = await cacheGetJSON(cacheKey)
  if (cached) return { ...cached, cached: true, source: 'cache' }

  // Extract domain for database lookup
  let domain = ''
  try { domain = new URL(data.url).hostname } catch { domain = data.url }

  // Check database for known malicious sites
  const dbRecord = await prisma.detectionEvent.findFirst({
    where: { domain },
    orderBy: { createdAt: 'desc' },
    take: 1,
  }).catch(() => null)

  // If found in database and recently flagged, use that data
  if (dbRecord && dbRecord.riskLevel !== 'LOW') {
    const dbResult = {
      url: data.url,
      riskLevel: dbRecord.riskLevel,
      riskScore: dbRecord.riskScore,
      explanation: `⚠️ **Previously Reported as Malicious**: ${dbRecord.aiExplanation}`,
      recommendedAction: dbRecord.riskLevel === 'CRITICAL' || dbRecord.riskLevel === 'HIGH' ? 'block' : 'warn',
      confidence: 0.95,
      keyIndicators: ['Found in malicious database', 'Previous threat reports'],
      source: 'database',
      cached: false,
    }
    await cacheSetJSON(cacheKey, dbResult, 3600)
    return dbResult
  }

  // Calculate risk score from signals
  const signals = data.signals || {}
  const riskScore = Math.min(100, Object.values(signals).reduce((a: number, b: number) => a + (b || 0), 0))

  // Use Gemini AI for analysis
  const aiResult = await analyzeUrl(data.url, signals, riskScore)

  // Cache the result
  await cacheSetJSON(cacheKey, aiResult, 3600)

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

  return { ...aiResult, cached: false, source: 'ai' }
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
