import fs from 'node:fs'
import path from 'node:path'
import dotenv from 'dotenv'
import { prisma } from './client'

dotenv.config({ path: path.resolve(__dirname, '../../../.env') })

const BATCH_SIZE = 1000
const DEFAULT_RISK_SCORE = 98

function getLinksFilePath() {
  return path.resolve(__dirname, '../../../phishinglinks.txt')
}

function normalizeUrl(value: string): string | null {
  const raw = value.trim()
  if (!raw || raw.startsWith('#')) return null

  try {
    const url = new URL(raw)
    url.hash = ''
    return url.toString()
  } catch {
    return null
  }
}

async function ensureDomainScores(domains: string[]) {
  const now = new Date()
  await prisma.domainScore.createMany({
    data: domains.map(domain => ({
      domain,
      riskScore: DEFAULT_RISK_SCORE,
      reportCount: 1,
      categories: ['phishing'],
      category_counts: { phishing: 1 },
      is_confirmed: true,
      first_seen: now,
      last_report_at: now,
    })),
    skipDuplicates: true,
  })
}

async function main() {
  const filePath = getLinksFilePath()

  if (!fs.existsSync(filePath)) {
    throw new Error(`Could not find phishing link list at ${filePath}`)
  }

  console.log(`Importing phishing links from ${filePath}...`)

  const allUrls = Array.from(
    new Set(
      fs.readFileSync(filePath, 'utf8')
        .split(/\r?\n/)
        .map(normalizeUrl)
        .filter((url): url is string => Boolean(url))
    )
  )

  console.log(`Found ${allUrls.length} unique phishing URLs.`)

  let inserted = 0
  const now = new Date()

  for (let index = 0; index < allUrls.length; index += BATCH_SIZE) {
    const batch = allUrls.slice(index, index + BATCH_SIZE)
    const parsedBatch = batch.map(url => ({ url, domain: new URL(url).hostname.toLowerCase() }))

    await ensureDomainScores(Array.from(new Set(parsedBatch.map(item => item.domain))))

    const result = await prisma.detectionEvent.createMany({
      data: parsedBatch.map(item => ({
        eventType: 'url_threat',
        domain: item.domain,
        url: item.url,
        riskScore: DEFAULT_RISK_SCORE,
        riskLevel: 'CRITICAL',
        signals: { matchedKnownBadUrl: true },
        aiExplanation: 'This exact URL matches a known phishing link in the local threat database.',
      })),
      skipDuplicates: true,
    })

    inserted += result.count

    if ((index / BATCH_SIZE + 1) % 20 === 0 || index + BATCH_SIZE >= allUrls.length) {
      console.log(`Processed ${Math.min(index + BATCH_SIZE, allUrls.length)} / ${allUrls.length} URLs...`)
    }
  }

  console.log(`Imported ${inserted} new phishing URLs.`)
}

main()
  .catch(err => {
    console.error('Failed to import phishing URLs:', err)
    process.exitCode = 1
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
