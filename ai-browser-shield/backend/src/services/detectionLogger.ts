import { prisma } from '../db/client'

/**
 * Signal map for threat detection contributing factors
 * Maps signal name to numeric score contribution (0-100)
 * 
 * @example
 * {
 *   ipAsHostname: 40,
 *   tooManySubdomains: 10,
 *   ml_subdomains: 35
 * }
 */
export type SignalMap = Record<string, number>

/**
 * Detection Event for logging phishing detections
 */
export interface DetectionLogInput {
  url: string
  score: number
  signals?: SignalMap
  aiExplanation?: string
}

/**
 * Log a phishing detection event to the database
 * 
 * Creates a DetectionEvent record with URL threat analysis results
 * and updates domain risk scores accordingly.
 * 
 * Risk Level Classification:
 *   - 0-25: LOW (SAFE)
 *   - 26-55: MEDIUM (SUSPICIOUS)
 *   - 56-80: HIGH
 *   - 81-100: CRITICAL
 * 
 * @param url - The URL that was analyzed
 * @param score - Risk score (0-100)
 * @param signals - Detected threat signals and their contributions
 * @param aiExplanation - Optional AI analysis explanation
 * @returns The created DetectionEvent record
 * 
 * @example
 * await logDetection('https://phishing-site.tk/login', 85, {
 *   ipAsHostname: 40,
 *   tooManySubdomains: 10,
 *   ml_subdomains: 35
 * }, 'High-risk URL pattern detected')
 */
export async function logDetection(
  url: string,
  score: number,
  signals?: SignalMap,
  aiExplanation?: string
) {
  // Extract domain from URL
  let domain = ''
  try {
    domain = new URL(url).hostname || url
  } catch {
    domain = url
  }

  // Clamp score to 0-100 range
  const clampedScore = Math.min(100, Math.max(0, Math.round(score)))

  // ══════════════════════════════════════════════════════════════════════
  // CALCULATE RISK LEVEL FROM SCORE
  // ══════════════════════════════════════════════════════════════════════
  // Thresholds aligned with urlScorer.ts and UI components
  type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  const riskLevel: RiskLevel =
    clampedScore >= 81 ? 'CRITICAL'
    : clampedScore >= 56 ? 'HIGH'
    : clampedScore >= 26 ? 'MEDIUM'
    : 'LOW'

  // ══════════════════════════════════════════════════════════════════════
  // CREATE DETECTION EVENT
  // ══════════════════════════════════════════════════════════════════════
  const event = await prisma.detectionEvent.create({
    data: {
      eventType: 'url_threat',           // Phishing detection from extension
      domain,
      url,
      riskScore: clampedScore,
      riskLevel,
      signals: signals as any,           // JSON-serializable signals object
      aiExplanation,
    },
  })

  // ══════════════════════════════════════════════════════════════════════
  // UPDATE DOMAIN RISK SCORE
  // ══════════════════════════════════════════════════════════════════════
  // Automatically updates aggregate domain threat metrics for reputation tracking
  
  const existing = await prisma.domainScore.findUnique({ where: { domain } })
  
  if (existing) {
    // Existing domain: increment report count and adjust risk score
    const newRiskScore = Math.min(
      100,
      existing.riskScore + (clampedScore > 50 ? 2 : 1)  // Higher increments for high-risk detections
    )

    await prisma.domainScore.update({
      where: { domain },
      data: {
        reportCount: { increment: 1 },
        riskScore: newRiskScore,
        last_report_at: new Date(),
        categories: existing.categories.includes('phishing')
          ? existing.categories
          : [...existing.categories, 'phishing'],
      },
    })
  } else {
    // New domain: create domain score entry
    await prisma.domainScore.create({
      data: {
        domain,
        riskScore: clampedScore,    // Initial score = detection score
        reportCount: 1,
        categories: ['phishing'],
      },
    })
  }

  return event
}

/**
 * Get recent detection events (for analytics/reporting)
 * 
 * @param limit - Maximum number of events to retrieve (default: 20)
 * @param fromTimestamp - Optional filter: only events after this timestamp
 * @returns Array of recent DetectionEvent records
 */
export async function getRecentDetections(limit = 20, fromTimestamp?: Date) {
  const where: any = {}
  
  if (fromTimestamp) {
    where.createdAt = { gte: fromTimestamp }
  }

  return await prisma.detectionEvent.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: limit,
    include: {
      domain_scores: {
        select: {
          riskScore: true,
          reportCount: true,
          categories: true,
        },
      },
    },
  })
}

/**
 * Get detection statistics for a specific time period
 * 
 * @param hours - Number of hours to look back (default: 24)
 * @returns Detection statistics including counts by risk level
 */
export async function getDetectionStats(hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000)

  const [totalCount, byRiskLevel] = await Promise.all([
    prisma.detectionEvent.count({
      where: { createdAt: { gte: since } },
    }),
    prisma.detectionEvent.groupBy({
      by: ['riskLevel'],
      _count: { id: true },
      where: { createdAt: { gte: since } },
    }),
  ])

  const stats = {
    totalDetections: totalCount,
    byRiskLevel: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    },
    period: `Last ${hours} hours`,
    timestamp: new Date().toISOString(),
  }

  for (const group of byRiskLevel) {
    stats.byRiskLevel[group.riskLevel as keyof typeof stats.byRiskLevel] = group._count.id
  }

  return stats
}

/**
 * Get the top malicious domains by detection count
 * 
 * @param limit - Maximum number of domains (default: 10)
 * @param minScore - Minimum risk score to include (default: 50)
 * @returns Sorted list of high-risk domains
 */
export async function getTopMaliciousDomains(limit = 10, minScore = 50) {
  return await prisma.domainScore.findMany({
    where: { riskScore: { gte: minScore } },
    orderBy: { riskScore: 'desc' },
    take: limit,
    select: {
      domain: true,
      riskScore: true,
      reportCount: true,
      categories: true,
      last_report_at: true,
    },
  })
}
