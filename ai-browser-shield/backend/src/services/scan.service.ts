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

  const exactUrlRecord = await prisma.detectionEvent.findFirst({
    where: { url: data.url },
    orderBy: { createdAt: 'desc' },
  }).catch(() => null)

  if (exactUrlRecord && exactUrlRecord.riskLevel !== 'LOW') {
    const exactUrlResult = {
      url: data.url,
      riskLevel: exactUrlRecord.riskLevel,
      riskScore: exactUrlRecord.riskScore,
      explanation: exactUrlRecord.aiExplanation || 'This exact URL matches a known bad link in the local threat database.',
      recommendedAction: exactUrlRecord.riskLevel === 'CRITICAL' || exactUrlRecord.riskLevel === 'HIGH' ? 'block' : 'warn',
      confidence: 0.99,
      keyIndicators: ['Known bad URL', 'Matched local threat list'],
      source: 'exact_url',
      cached: false,
    }
    await cacheSetJSON(cacheKey, exactUrlResult, 3600)
    return exactUrlResult
  }

  const knownBadDomain = await prisma.domainScore.findUnique({
    where: { domain },
  }).catch(() => null)

  if (knownBadDomain?.is_confirmed && knownBadDomain.riskScore >= 70) {
    const domainResult = {
      url: data.url,
      riskLevel: knownBadDomain.riskScore >= 90 ? 'CRITICAL' : knownBadDomain.riskScore >= 70 ? 'HIGH' : 'MEDIUM',
      riskScore: knownBadDomain.riskScore,
      explanation: 'This domain matches a known phishing list in the local threat database. Do not enter credentials, payment details, or personal information here.',
      recommendedAction: knownBadDomain.riskScore >= 90 ? 'block' : 'warn',
      confidence: 0.99,
      keyIndicators: ['Known phishing domain', 'Matched local threat list'],
      source: 'domain_score',
      cached: false,
    }
    await cacheSetJSON(cacheKey, domainResult, 3600)
    return domainResult
  }

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
  const aiResult = await analyzeUrl(data.url, signals, riskScore, data.pageContext)

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
  if (cached) {
    const cachedScore = cached as { riskScore?: number; detectionEvents?: number; fileScanFlags?: number }
    const looksLikeLegacyUnknown =
      cachedScore.riskScore === 100 &&
      (cachedScore.detectionEvents ?? 0) === 0 &&
      (cachedScore.fileScanFlags ?? 0) === 0

    if (!looksLikeLegacyUnknown) return cached
  }

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

  // Unknown domains should not default to maximum risk.
  if (!score && detectionCount === 0 && fileScanCount === 0) {
    return null
  }

  const riskScore = score?.riskScore ?? (detectionCount > 0 ? 50 : 10)
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
