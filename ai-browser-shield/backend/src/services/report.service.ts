import { prisma } from '../db/client'
import { cacheDel, cacheGetJSON, cacheSetJSON, keys } from './cache.service'
import type { ReportInput } from '../schemas'

export async function createReport(data: ReportInput, ipHash: string, userAgent?: string) {
  let domain = ''
  try { domain = new URL(data.url).hostname } catch { domain = data.url }

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

  const results = await prisma.threatReport.groupBy({
    by: ['domain', 'category'],
    _count: { id: true },
    orderBy: { _count: { id: 'desc' } },
    take: limit,
    where: {
      deletedAt: null,
      createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    }
  })

  // Enrich with domain scores
  const domains = [...new Set(results.map(r => r.domain))]
  const scores = await prisma.domainScore.findMany({ where: { domain: { in: domains } } })
  const scoreMap = Object.fromEntries(scores.map(s => [s.domain, s.riskScore]))

  const feed = results.map(r => ({
    domain: r.domain,
    category: r.category,
    reports: r._count.id,
    riskScore: scoreMap[r.domain] || 50,
    lastSeen: new Date().toISOString(),
  }))

  await cacheSetJSON(keys.threatFeed(), feed, 300) // 5 min TTL
  return feed
}
