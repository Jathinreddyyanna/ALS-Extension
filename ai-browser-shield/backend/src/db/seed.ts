import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  console.log('🌱 Seeding database...')

  // Seed domain scores
  const domains = [
    { domain: 'evil-phish-login.tk', riskScore: 92, reportCount: 14, categories: ['phishing'] },
    { domain: 'free-crypto-wallet.xyz', riskScore: 88, reportCount: 9, categories: ['scam'] },
    { domain: 'amazon-secure-verify.com', riskScore: 85, reportCount: 7, categories: ['phishing'] },
    { domain: 'paypal-update-now.ml', riskScore: 91, reportCount: 11, categories: ['phishing'] },
    { domain: 'download-free-vpn.top', riskScore: 74, reportCount: 5, categories: ['malware'] },
  ]

  for (const d of domains) {
    await prisma.domainScore.upsert({
      where: { domain: d.domain },
      update: d,
      create: d,
    })
  }

  // Seed reports
  const reports = [
    { url: 'https://evil-phish-login.tk/signin', domain: 'evil-phish-login.tk', category: 'phishing' as const, description: 'Fake Google login page', ipHash: 'hash1' },
    { url: 'https://free-crypto-wallet.xyz/', domain: 'free-crypto-wallet.xyz', category: 'scam' as const, description: 'Asking for wallet seed phrases', ipHash: 'hash2' },
    { url: 'https://amazon-secure-verify.com/account', domain: 'amazon-secure-verify.com', category: 'phishing' as const, description: 'Fake Amazon account verification', ipHash: 'hash3' },
  ]

  for (const r of reports) {
    await prisma.threatReport.create({ data: r })
  }

  console.log('✅ Database seeded successfully!')
}

main().catch(console.error).finally(() => prisma.$disconnect())
