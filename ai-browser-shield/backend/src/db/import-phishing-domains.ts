import fs from 'node:fs'
import path from 'node:path'
import dotenv from 'dotenv'
import { prisma } from './client'

const BATCH_SIZE = 2000
const DEFAULT_RISK_SCORE = 95

dotenv.config({ path: path.resolve(__dirname, '../../../.env') })

function getDomainsFilePath() {
  return path.resolve(__dirname, '../../../phishingdomains.txt')
}

function normalizeDomain(value: string): string | null {
  const domain = value.trim().toLowerCase()
  if (!domain || domain.startsWith('#')) return null
  return domain
}

async function main() {
  const filePath = getDomainsFilePath()

  if (!fs.existsSync(filePath)) {
    throw new Error(`Could not find phishing domain list at ${filePath}`)
  }

  console.log(`Importing phishing domains from ${filePath}...`)

  const allDomains = Array.from(
    new Set(
      fs.readFileSync(filePath, 'utf8')
        .split(/\r?\n/)
        .map(normalizeDomain)
        .filter((domain): domain is string => Boolean(domain))
    )
  )

  console.log(`Found ${allDomains.length} unique domains.`)

  let inserted = 0
  const now = new Date()

  for (let index = 0; index < allDomains.length; index += BATCH_SIZE) {
    const batch = allDomains.slice(index, index + BATCH_SIZE)

    const result = await prisma.domainScore.createMany({
      data: batch.map(domain => ({
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

    inserted += result.count

    if ((index / BATCH_SIZE + 1) % 20 === 0 || index + BATCH_SIZE >= allDomains.length) {
      console.log(`Processed ${Math.min(index + BATCH_SIZE, allDomains.length)} / ${allDomains.length} domains...`)
    }
  }

  console.log(`Imported ${inserted} new phishing domains.`)
}

main()
  .catch(err => {
    console.error('Failed to import phishing domains:', err)
    process.exitCode = 1
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
