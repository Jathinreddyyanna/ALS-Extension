import { prisma } from '../db/client'
import { cacheDel, cacheGetJSON, cacheSetJSON, keys } from './cache.service'
import type { ReportInput } from '../schemas'

const isNoDb = () => process.env.NO_DB === 'true'

type InMemoryReport = {
  id: string
  url: string
  domain: string
  category: string
  createdAt: Date
}

const inMemoryReports: InMemoryReport[] = []
const inMemoryDomainScores = new Map<string, {
  riskScore: number
  reportCount: number
  categories: string[]
  lastSeen: Date
}>()

export async function createReport(data: ReportInput, ipHash: string, userAgent?: string) {
  let domain = ''
  try { domain = new URL(data.url).hostname } catch { domain = data.url }

  if (isNoDb()) {
    const now = new Date()
    const existing = inMemoryDomainScores.get(domain)

    if (existing) {
      existing.reportCount += 1
      existing.riskScore = Math.min(100, existing.riskScore + 3)
      existing.lastSeen = now
      if (!existing.categories.includes(data.category)) existing.categories.push(data.category)
    } else {
      inMemoryDomainScores.set(domain, {
        riskScore: 50,
        reportCount: 1,
        categories: [data.category],
        lastSeen: now,
      })
    }

    const report: InMemoryReport = {
      id: crypto.randomUUID(),
      url: data.url,
      domain,
      category: data.category,
      createdAt: now,
    }
    inMemoryReports.unshift(report)

    await Promise.all([
      cacheDel(keys.domainScore(domain)),
      cacheDel(keys.threatFeed()),
    ])

    return report
  }

  const report = await prisma.threatReport.create({
    data: {
      url: data.url,
      domain,
      category: data.category,
      description: data.description,
      signals: data.signals as any,
      ipHash,
      userAgent,
    }
  })

  // Update domain score
  const existing = await prisma.domainScore.findUnique({ where: { domain } })
  if (existing) {
    await prisma.domainScore.update({
      where: { domain },
      data: {
        reportCount: { increment: 1 },
        riskScore: Math.min(100, existing.riskScore + 3),
        categories: existing.categories.includes(data.category)
          ? existing.categories
          : [...existing.categories, data.category],
      }
    })
  } else {
    await prisma.domainScore.create({
      data: {
        domain,
        riskScore: 50,
        reportCount: 1,
        categories: [data.category],
      }
    })
  }

  // Invalidate caches
  await Promise.all([
    cacheDel(keys.domainScore(domain)),
    cacheDel(keys.threatFeed()),
  ])

  return report
}

export async function getRecentFeed(limit = 20) {
  const cached = await cacheGetJSON(keys.threatFeed())
  if (cached) return cached

  if (isNoDb()) {
    const feed = [...inMemoryDomainScores.entries()]
      .sort((a, b) => b[1].lastSeen.getTime() - a[1].lastSeen.getTime())
      .slice(0, limit)
      .map(([domain, value]) => ({
        domain,
        category: value.categories[0] || 'phishing',
        reports: value.reportCount,
        riskScore: value.riskScore,
        lastSeen: value.lastSeen.toISOString(),
      }))

    await cacheSetJSON(keys.threatFeed(), feed, 300)
    return feed
  }

  try {
    // Simpler approach: just get recent domain scores with high risk
    const results = await prisma.domainScore.findMany({
      take: limit,
      orderBy: { last_report_at: 'desc' },
      where: {
        reportCount: { gt: 0 }
      }
    })

    const feed = results.map(r => ({
      domain: r.domain,
      category: Array.isArray(r.categories) && r.categories.length > 0 ? r.categories[0] : 'phishing',
      reports: r.reportCount,
      riskScore: r.riskScore,
      lastSeen: r.last_report_at.toISOString(),
    }))

    await cacheSetJSON(keys.threatFeed(), feed, 300) // 5 min TTL
    return feed
  } catch (err) {
    console.error('Error in getRecentFeed:', err)
    // Return empty array as fallback on error
    return []
  }
}
