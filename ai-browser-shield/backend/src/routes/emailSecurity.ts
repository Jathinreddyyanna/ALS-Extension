import { Router, Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import { analyzeEmail } from '../ai/client'
import { prisma } from '../db/client'

const router = Router()

const EmailAnalysisSchema = z.object({
  sender: z.string(),
  subject: z.string().max(255),
  body: z.string().max(50000),
  headers: z.record(z.string()).optional(),
  timestamp: z.number().optional(),
})

type EmailAnalysisInput = z.infer<typeof EmailAnalysisSchema>

function extractDomainFromEmail(sender: string): string {
  const match = sender.match(/@([^\s>]+)/)
  return match ? match[1] : sender
}

function extractLinksFromBody(body: string): string[] {
  const urlRegex = /(https?:\/\/[^\s<>]+)/gi
  const matches = body.match(urlRegex) || []
  return [...new Set(matches)]
}

function authCheck(headers: Record<string, string> | undefined) {
  const spf = headers?.['spf'] || headers?.['SPF'] || 'unknown'
  const dkim = headers?.['dkim'] || headers?.['DKIM'] || 'unknown'
  const dmarc = headers?.['dmarc'] || headers?.['DMARC'] || 'unknown'

  const spfPassed = spf.toLowerCase().includes('pass')
  const dkimPassed = dkim.toLowerCase().includes('pass')
  const dmarcPassed = dmarc.toLowerCase().includes('pass')

  return {
    spfCheck: {
      passed: spfPassed,
      details: `SPF: ${spf}`,
    },
    dkimCheck: {
      passed: dkimPassed,
      details: `DKIM: ${dkim}`,
    },
    dmarcCheck: {
      passed: dmarcPassed,
      details: `DMARC: ${dmarc}`,
    },
    allPassed: spfPassed && dkimPassed && dmarcPassed,
  }
}

router.post(
  '/email/analyze',
  async (req: Request<{}, {}, EmailAnalysisInput>, res: Response, next: NextFunction) => {
    try {
      const parsed = EmailAnalysisSchema.safeParse(req.body)
      if (!parsed.success) {
        return res.status(422).json({
          error: 'Invalid payload',
          details: parsed.error.flatten(),
        })
      }

      const { sender, subject, body, headers, timestamp } = parsed.data
      const senderDomain = extractDomainFromEmail(sender)
      const links = extractLinksFromBody(body)
      const auth = authCheck(headers || {})

      const ai = await analyzeEmail({
        sender,
        subject,
        body,
        headers: headers || {},
        timestamp: timestamp ? new Date(timestamp).toISOString() : undefined,
      })

      // Map AI output to numeric risk and DB risk_level enum
      const phishingScore = typeof ai.phishingScore === 'number'
        ? Math.max(0, Math.min(100, ai.phishingScore))
        : (ai.riskLevel === 'CRITICAL'
            ? 90
            : ai.riskLevel === 'HIGH'
            ? 70
            : ai.riskLevel === 'MEDIUM'
            ? 50
            : 10)

      let dbRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
      if (ai.riskLevel === 'MEDIUM') dbRiskLevel = 'MEDIUM'
      if (ai.riskLevel === 'HIGH') dbRiskLevel = 'HIGH'
      if (ai.riskLevel === 'CRITICAL') dbRiskLevel = 'CRITICAL'

      let overallRiskLevel: 'SAFE' | 'CAUTION' | 'DANGEROUS' | 'CRITICAL' = 'SAFE'
      if (ai.riskLevel === 'MEDIUM') overallRiskLevel = 'CAUTION'
      if (ai.riskLevel === 'HIGH') overallRiskLevel = 'DANGEROUS'
      if (ai.riskLevel === 'CRITICAL') overallRiskLevel = 'CRITICAL'

      const trustScore = Math.max(0, Math.min(100, 100 - phishingScore))
      const suspiciousLinks = Array.isArray(ai.indicators?.suspiciousLinks)
        ? ai.indicators.suspiciousLinks.length
        : 0

      // Persist medium+ risk email events into central detection_events for reporting
      if (dbRiskLevel !== 'LOW') {
        try {
          // Ensure domain_scores row exists for FK requirements
          await prisma.domainScore.upsert({
            where: { domain: senderDomain },
            update: {},
            create: { domain: senderDomain },
          })

          await prisma.detectionEvent.create({
            data: {
              eventType: 'url_threat',
              domain: senderDomain,
              url: links[0] || `mailto:${sender}`,
              riskScore: phishingScore,
              riskLevel: dbRiskLevel,
              signals: {
                sender,
                subject,
                totalLinks: links.length,
                suspiciousLinks,
                spf: auth.spfCheck.details,
                dkim: auth.dkimCheck.details,
                dmarc: auth.dmarcCheck.details,
                aiIndicators: ai.indicators ?? {},
              } as any,
              aiExplanation: ai.judgment || ai.finalVerdict || undefined,
            },
          })
        } catch (e) {
          // Non-blocking: logging must not break user-facing email analysis
          console.error('[Email Security] Failed to persist detection event:', e)
        }
      }

      const responseBody = {
        sender,
        domain: senderDomain,
        subject,
        riskLevel: overallRiskLevel,
        trustScore,
        isAuthentic: auth.allPassed && !ai.isPhishing,
        isKnownPhisher: ai.isPhishing === true,
        suspiciousLinks,
        totalLinks: links.length,
        blockedLinks: 0,
        explanation: ai.judgment || ai.finalVerdict || 'Email analysis completed.',
        recommendations: ai.recommendations || [],
        linkDetails: [],
        timestamp: new Date().toISOString(),
        email: {
          sender,
          senderDomain,
          isAuthentic: auth.allPassed && !ai.isPhishing,
        },
        spfCheck: auth.spfCheck,
        dkimCheck: auth.dkimCheck,
        dmarcCheck: auth.dmarcCheck,
        senderReputation: {
          trustScore,
          knownPhisher: ai.isPhishing === true,
          previousReports: 0,
        },
        links: {
          total: links.length,
          suspicious: suspiciousLinks,
          blocked: 0,
          details: [],
        },
        overallRiskLevel,
      }

      res.json(responseBody)
    } catch (err) {
      next(err)
    }
  }
)

export default router
